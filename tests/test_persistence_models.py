from decimal import Decimal

from sqlalchemy import CheckConstraint, Numeric, UniqueConstraint

from vpn_manager.models import (
    AuditLog,
    Base,
    Customer,
    Order,
    Panel,
    Payment,
    Subscription,
    TrafficSnapshot,
    VPNService,
    WalletAccount,
    WalletLedger,
    utc_now,
)


def test_all_persistence_entities_are_registered():
    assert set(Base.metadata.tables) == {
        "admin_users",
        "panels",
        "customers",
        "vpn_services",
        "product_plans",
        "managed_clients",
        "subscriptions",
        "store_settings",
        "wallet_accounts",
        "wallet_ledger",
        "orders",
        "payments",
        "traffic_snapshots",
        "audit_logs",
    }


def test_money_columns_use_fixed_precision_decimal():
    for model, field in (
        (WalletAccount, "balance"),
        (WalletLedger, "amount"),
        (WalletLedger, "balance_after"),
        (Order, "amount"),
        (Payment, "amount"),
    ):
        column_type = model.__table__.c[field].type
        assert isinstance(column_type, Numeric)
        assert (column_type.precision, column_type.scale) == (20, 4)
    assert Decimal("0.10") + Decimal("0.20") == Decimal("0.30")


def test_uuid_primary_keys_and_timezone_aware_timestamp_columns():
    for table in Base.metadata.tables.values():
        if "id" in table.c:
            assert table.c.id.primary_key
            assert table.c.id.type.as_uuid
    for model in (
        Panel,
        Customer,
        VPNService,
        Subscription,
        WalletAccount,
        Order,
        Payment,
    ):
        assert model.__table__.c.created_at.type.timezone is True
        assert model.__table__.c.updated_at.type.timezone is True
    assert utc_now().utcoffset().total_seconds() == 0


def test_business_constraints_and_indexes_are_declared():
    assert any(isinstance(item, UniqueConstraint) for item in VPNService.__table__.constraints)
    assert any(
        isinstance(item, UniqueConstraint)
        and {column.name for column in item.columns} == {"service_id", "external_client_id"}
        for item in Subscription.__table__.constraints
    )
    assert any(isinstance(item, CheckConstraint) for item in WalletAccount.__table__.constraints)
    assert any(isinstance(item, CheckConstraint) for item in WalletLedger.__table__.constraints)
    assert any(isinstance(item, CheckConstraint) for item in Payment.__table__.constraints)
    assert "ix_audit_logs_created_at" in {index.name for index in AuditLog.__table__.indexes}
    assert "ix_traffic_snapshots_subscription_time" in {
        index.name for index in TrafficSnapshot.__table__.indexes
    }


def test_panel_connection_diagnostics_fields_exist():
    assert {"status", "last_checked_at", "last_error", "version"} <= set(Panel.__table__.c.keys())

