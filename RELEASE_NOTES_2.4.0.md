# VPN Panel + VPN Control Center 2.4.0

## Integrated multi-provider Telegram sales and management

- Embedded the independent VPN Control Center sales bot as a separate systemd service with its own Python virtual environment and persistent database.
- Added provider selection when registering a panel: existing `vpn-ui` panels remain `vpn_ui`; new connections can use either `vpn-ui` or the FastAPI-based VPN Panel.
- Added a VPN Panel JWT adapter with TLS verification, Base Path support, Super Admin and internal-license validation, protocol overview, user CRUD, protocol flags, quota/device/expiry updates, usage reset and subscription delivery.
- Mapped L2TP, PPTP, OpenVPN, SSTP, IKEv2, OpenConnect, VMess and VLESS into provider-specific service entries. vpn-ui-only Core, Xray Outbound and arbitrary inbound operations are hidden for VPN Panel.
- Preserved existing VPN Panel user passwords when editing, represented `used_bytes` as total account traffic, and used the API-provided `sub_link` and documented public subscription downloads.
- Replaced the legacy backend Telegram polling controller with the independent bot. Kept direct Telegram notifications, log queue and scheduled backups; removed dead callback controls and the old group-control UI/API registration.
- Added a separate bot systemd unit, fresh-install integration, noninteractive local update, data backup and code/unit rollback. Panel upgrades preserve the bot `.env`, data, backups, virtual environment and SQLite database.
- Updated Telegram settings UI to describe notification and backup delivery only.

## Database and compatibility

- Added Alembic revision `0004_panel_provider_type`. Existing panel records receive `provider_type='vpn_ui'` without changing stored credentials or relationships.
- Bot package version: `1.2.0` (Python `>=3.12,<3.15`).

## Validation

- VPN Control Center unit tests cover both providers and mocked paid-order fulfillment.
- VPN Panel backend tests cover legacy polling shutdown, scheduler retention, and notification behavior.
- Frontend production bundle rebuilt with Vite 8 using asset release number `24000`.
- No VPS or production server was deployed or modified during this release preparation.

## Operational limitations

- Live Telegram, live VPN Panel/vpn-ui mutations, real payment approval, Ubuntu/systemd install/update, and backup/restore drills still require environment-specific validation.
- VPN Panel exposes total `used_bytes`, not upload/download breakdown or per-protocol traffic.
- The bot remains manual-payment-review only; no online payment gateway is included.
