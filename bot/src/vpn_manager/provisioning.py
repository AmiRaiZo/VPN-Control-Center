"""Idempotent-ish VPN account provisioning across supported panel providers."""

from __future__ import annotations

import json
import secrets
import string
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from vpn_manager.models import Customer, Order, Panel, ProductPlan, Subscription, VPNService
from vpn_manager.panels import PanelConfig, VpnUiClient
from vpn_manager.panels.errors import PanelTwoFactorRequired
from vpn_manager.panels.protocols import IDENTITY_FIELDS
from vpn_manager.panels.vpn_panel import VpnPanelClient, VpnPanelConfig
from vpn_manager.security.panel_credentials import decrypt_panel_password, encrypt_panel_password
from vpn_manager.security.totp import totp_code


def _secret(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def build_client_payload(
    *,
    protocol: str,
    telegram_id: int,
    order_id: uuid.UUID,
    expires_at: datetime,
    traffic_limit_bytes: int,
    device_limit: int,
    email: str | None = None,
) -> dict[str, Any]:
    protocol = protocol.lower()
    if protocol not in IDENTITY_FIELDS:
        raise ValueError(f"پروتکل {protocol} برای فروش خودکار پشتیبانی نشده است.")
    email = email or f"u{telegram_id}-{order_id.hex[:10]}"
    payload: dict[str, Any] = {
        "email": email,
        "enable": True,
        "expiryTime": int(expires_at.timestamp() * 1000),
        "totalGB": int(traffic_limit_bytes),
        "limitIp": int(device_limit),
        "tgId": int(telegram_id),
        "subId": uuid.uuid5(order_id, "vpn-control-center").hex[:16],
        "comment": f"VPN Control Center order {order_id}",
        "reset": 0,
    }
    if protocol in {"l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2"}:
        payload.update({"id": f"u{telegram_id}_{order_id.hex[:8]}", "password": _secret()})
    elif protocol in {"trojan", "anytls"}:
        payload["password"] = _secret()
    elif protocol == "naive":
        payload.update({"username": email, "password": _secret()})
    elif protocol == "tuic":
        payload.update({"id": str(uuid.uuid4()), "password": _secret()})
    elif protocol in {"vmess", "vless"}:
        payload["id"] = str(uuid.uuid4())
        if protocol == "vmess":
            payload["security"] = "auto"
        else:
            payload["flow"] = ""
    elif protocol == "ssh":
        payload.update({"id": f"u{telegram_id}_{order_id.hex[:8]}", "password": _secret()})
    elif protocol == "shadowsocks":
        payload["password"] = _secret()
    elif protocol == "hysteria":
        payload["auth"] = _secret()
    elif protocol in {"wg-c", "awg", "gre", "mtproto"}:
        payload["id"] = email
        if protocol == "gre":
            payload["peers"] = [{"peerIp": "", "remark": ""}]
        if protocol == "mtproto":
            payload.update(
                {
                    "secret": secrets.token_hex(16),
                    "modeClassic": True,
                    "modeSecure": True,
                    "modeTls": True,
                    "tlsDomain": "www.google.com",
                    "adtagEnable": False,
                    "adtag": "",
                    "userLimit": 0,
                    "externalProxy": [],
                }
            )
    return payload


def _decode_client_settings(inbound: dict[str, Any]) -> list[dict[str, Any]]:
    settings = inbound.get("settings") or {}
    if isinstance(settings, str):
        try:
            settings = json.loads(settings)
        except ValueError:
            return []
    clients = settings.get("clients", []) if isinstance(settings, dict) else []
    return [item for item in clients if isinstance(item, dict)] if isinstance(clients, list) else []


async def _panel_client(panel: Panel) -> Any:
    config = PanelConfig(
        name=panel.name,
        base_url=panel.base_url,
        base_path=panel.base_path,
        username=panel.username,
        password=decrypt_panel_password(panel.encrypted_password),
    )
    if panel.provider_type == "vpn_panel":
        api = VpnPanelClient(
            VpnPanelConfig(
                name=config.name,
                base_url=config.base_url,
                base_path=config.base_path,
                username=config.username,
                password=config.password,
                verify_tls=config.verify_tls,
                timeout=config.timeout,
            )
        )
        try:
            await api.login()
        except Exception:
            await api.close()
            raise
        return api
    api = VpnUiClient(config)
    try:
        try:
            await api.login()
        except PanelTwoFactorRequired:
            encrypted_seed = (panel.extra_data or {}).get("totp_secret_encrypted")
            if not encrypted_seed:
                raise RuntimeError(
                    "پنل کد دومرحله‌ای می‌خواهد؛ Seed اپلیکیشن Authenticator در تنظیمات اتصال ثبت نشده است."
                )
            seed = decrypt_panel_password(encrypted_seed)
            await api.login(two_factor_code=totp_code(seed))
    except Exception:
        await api.close()
        raise
    return api


async def fulfill_subscription_order(session: AsyncSession, order: Order) -> Subscription:
    """Provision or retry a paid order. Credentials are encrypted before panel I/O."""
    if order.order_type != "subscription" or order.plan_id is None:
        raise ValueError("این سفارش از نوع اشتراک VPN نیست.")
    plan = await session.get(ProductPlan, order.plan_id)
    if plan is None or not plan.is_active:
        raise ValueError("پلن سفارش دیگر فعال نیست؛ برای بررسی دستی اقدام کنید.")
    service = await session.get(VPNService, plan.service_id)
    if service is None or not service.is_active:
        raise ValueError("سرویس انتخاب‌شده غیرفعال است.")
    panel = await session.get(Panel, service.panel_id)
    customer = await session.get(Customer, order.customer_id)
    if panel is None or not panel.is_active or customer is None:
        raise ValueError("پنل یا مشتری سفارش در دسترس نیست.")

    now = datetime.now(UTC)
    subscription: Subscription | None = None
    if order.subscription_id:
        subscription = await session.get(Subscription, order.subscription_id)
        if subscription is None or subscription.service_id != service.id:
            raise ValueError("اشتراک برای تمدید معتبر نیست یا به سرویس دیگری تعلق دارد.")
        encrypted_payload = subscription.extra_data.get("client_payload_encrypted")
        if not encrypted_payload:
            raise ValueError("اطلاعات امن کلاینت برای تمدید موجود نیست.")
        payload = json.loads(decrypt_panel_password(encrypted_payload))
        if order.extra_data.get("renewal") and not order.extra_data.get("renewal_applied"):
            previous_expiry = subscription.expires_at
            base = previous_expiry if previous_expiry and previous_expiry > now else now
            expires_at = base + timedelta(days=plan.duration_days)
            payload["expiryTime"] = int(expires_at.timestamp() * 1000)
            payload["totalGB"] = int(plan.traffic_limit_bytes)
            payload["limitIp"] = int(plan.device_limit)
            payload["enable"] = True
            order.extra_data = {**order.extra_data, "renewal_applied": True}
        else:
            expires_at = subscription.expires_at or now + timedelta(days=plan.duration_days)
    else:
        expires_at = now + timedelta(days=plan.duration_days)
        payload = build_client_payload(
            protocol=service.protocol,
            telegram_id=customer.telegram_id or 0,
            order_id=order.id,
            expires_at=expires_at,
            traffic_limit_bytes=plan.traffic_limit_bytes,
            device_limit=plan.device_limit,
        )
        identity_key = "email" if panel.provider_type == "vpn_panel" else IDENTITY_FIELDS[service.protocol]
        identity = str(payload[identity_key])
        subscription = Subscription(
            customer_id=customer.id,
            plan_id=plan.id,
            service_id=service.id,
            external_client_id=identity,
            status="provisioning",
            starts_at=now,
            expires_at=expires_at,
            traffic_limit_bytes=plan.traffic_limit_bytes,
            extra_data={
                "email": payload["email"],
                "client_payload_encrypted": encrypt_panel_password(
                    json.dumps(payload, separators=(",", ":"))
                ),
                "protocol": service.protocol,
                "plan_name": plan.name,
            },
        )
        session.add(subscription)
        await session.flush()
        order.subscription_id = subscription.id

    if order.subscription_id and subscription is not None:
        subscription.plan_id = plan.id
        subscription.expires_at = expires_at
        subscription.traffic_limit_bytes = plan.traffic_limit_bytes
        subscription.status = "provisioning"
        subscription.extra_data = {
            **subscription.extra_data,
            "client_payload_encrypted": encrypt_panel_password(
                json.dumps(payload, separators=(",", ":"))
            ),
            "plan_name": plan.name,
        }
    order.status = "processing"
    await session.commit()

    api: Any | None = None
    try:
        api = await _panel_client(panel)
        identity_key = "email" if panel.provider_type == "vpn_panel" else IDENTITY_FIELDS[service.protocol]
        identity = str(payload[identity_key])
        inbound_id = int(service.external_id)
        if panel.provider_type == "vpn_panel":
            # VPN Panel disables an expired account by clearing its protocol
            # flag. Search by unique username independently of that flag so a
            # renewal updates the existing user instead of creating a duplicate.
            exists = await api.find_user(identity) is not None
        else:
            inbound = await api.get_inbound(inbound_id)
            exists = any(
                str(item.get(identity_key, "")) == identity
                or str(item.get("email", "")).casefold() == str(payload["email"]).casefold()
                for item in _decode_client_settings(inbound)
            )
        if exists:
            await api.update_client(inbound_id, identity, payload)
        else:
            await api.add_client(inbound_id, payload)
    except Exception:
        subscription.status = "provisioning_failed"
        order.status = "fulfillment_failed"
        await session.commit()
        raise
    finally:
        if api is not None:
            await api.close()

    subscription.status = "active"
    subscription.expires_at = expires_at
    subscription.traffic_limit_bytes = plan.traffic_limit_bytes
    subscription.extra_data = {
        **subscription.extra_data,
        "client_payload_encrypted": encrypt_panel_password(
            json.dumps(payload, separators=(",", ":"))
        ),
        "email": payload["email"],
        "protocol": service.protocol,
        "plan_name": plan.name,
    }
    order.status = "fulfilled"
    await session.commit()
    return subscription
