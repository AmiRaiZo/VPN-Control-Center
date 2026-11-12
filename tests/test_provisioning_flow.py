import json
from decimal import Decimal

import httpx
import pytest
import respx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from vpn_manager.config import get_settings
from vpn_manager.models import Base, Customer, Order, Panel, ProductPlan, Subscription, VPNService
from vpn_manager.panels.errors import PanelOperationError
from vpn_manager.provisioning import fulfill_subscription_order
from vpn_manager.security.panel_credentials import decrypt_panel_password, encrypt_panel_password


@pytest.fixture
async def database(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("APP_SECRET_KEY", "t" * 48)
    monkeypatch.setenv("PANEL_CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    get_settings.cache_clear()
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'provisioning.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()
    get_settings.cache_clear()


async def _seed_order(session_factory):
    async with session_factory() as session:
        panel = Panel(
            name="Test panel",
            base_url="https://panel.example",
            base_path="vpn",
            username="admin",
            encrypted_password=encrypt_panel_password("panel-secret"),
            is_active=True,
            extra_data={},
        )
        session.add(panel)
        await session.flush()
        service = VPNService(
            panel_id=panel.id,
            external_id="5",
            name="VLESS inbound",
            protocol="vless",
            is_active=True,
        )
        customer = Customer(telegram_id=123456, username="buyer", full_name="Test Buyer")
        session.add_all([service, customer])
        await session.flush()
        plan = ProductPlan(
            service_id=service.id,
            name="30 day",
            duration_days=30,
            traffic_limit_bytes=10 * 1024**3,
            device_limit=2,
            price=Decimal(1500000),
            currency="IRR",
            is_active=True,
        )
        session.add(plan)
        await session.flush()
        order = Order(
            customer_id=customer.id,
            plan_id=plan.id,
            order_type="subscription",
            amount=plan.price,
            currency="IRR",
            status="paid",
            description="test purchase",
        )
        session.add(order)
        await session.commit()
        return order.id


def _mock_panel(add_client_route):
    respx.post("https://panel.example/vpn/login").mock(
        return_value=httpx.Response(
            200,
            headers={"set-cookie": "vpn-ui=session; Path=/vpn"},
            json={"success": True},
        )
    )
    respx.get("https://panel.example/vpn/panel/api/inbounds/get/5").mock(
        return_value=httpx.Response(
            200,
            json={"success": True, "obj": {"id": 5, "settings": {"clients": []}}},
        )
    )
    return respx.post("https://panel.example/vpn/panel/api/inbounds/addClient").mock(
        side_effect=add_client_route
    )


@pytest.mark.asyncio
@respx.mock
async def test_paid_order_provisions_enabled_client_and_encrypted_subscription(database):
    order_id = await _seed_order(database)
    add_route = _mock_panel(httpx.Response(200, json={"success": True, "obj": "client added"}))
    async with database() as session:
        order = await session.get(Order, order_id)
        subscription = await fulfill_subscription_order(session, order)
        assert subscription.status == "active"
        assert order.status == "fulfilled"
        payload_ciphertext = subscription.extra_data["client_payload_encrypted"]
        payload = json.loads(decrypt_panel_password(payload_ciphertext))
        assert payload["enable"] is True
        assert payload["totalGB"] == 10 * 1024**3
        assert payload["limitIp"] == 2
        assert payload["subId"]
        assert payload["id"]
    assert add_route.called
    assert "panel-secret" not in payload_ciphertext


@pytest.mark.asyncio
@respx.mock
async def test_failed_provisioning_retry_reuses_same_credentials_and_expiry(database):
    order_id = await _seed_order(database)
    add_route = _mock_panel(
        [
            httpx.Response(200, json={"success": False, "msg": "temporary failure"}),
            httpx.Response(200, json={"success": True, "obj": "client added"}),
        ]
    )
    async with database() as session:
        order = await session.get(Order, order_id)
        with pytest.raises(PanelOperationError, match="temporary failure"):
            await fulfill_subscription_order(session, order)
        assert order.status == "fulfillment_failed"
        subscription = await session.scalar(
            select(Subscription).where(Subscription.id == order.subscription_id)
        )
        original_payload = decrypt_panel_password(
            subscription.extra_data["client_payload_encrypted"]
        )
        original_expiry = subscription.expires_at
        original_identity = subscription.external_client_id
        await fulfill_subscription_order(session, order)
        assert order.status == "fulfilled"
        assert subscription.status == "active"
        assert subscription.expires_at == original_expiry
        assert subscription.external_client_id == original_identity
        assert (
            decrypt_panel_password(subscription.extra_data["client_payload_encrypted"])
            == original_payload
        )
    assert len(add_route.calls) == 2

