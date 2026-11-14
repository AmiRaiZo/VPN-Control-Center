# VPN Control Center 1.2.0

Telegram-based administration and sales control plane for both `vpn-ui` and the integrated FastAPI VPN Panel. It replaces the old interactive Telegram controller embedded in VPN Panel and runs as an independent service.

> **Operational status:** automated tests and mocked panel requests do not replace live Telegram/panel integration, production security review, recovery drills, or real payment verification. Payments currently use manual bank-transfer receipt review; no online gateway is implemented.

## Capabilities

- Preserve the independent storefront: plan catalog, orders, manual payment review, wallet, purchases, renewals, subscriptions, customer management, administrator management and audit events.
- Multi-provider panel registry. New panels can be added as `vpn-ui` or `VPN Panel`; migration `0004_panel_provider_type` keeps all existing records as `vpn_ui`.
- `vpn-ui`: encrypted credentials, Base Path, cookie session, TOTP login, inbound synchronization and management, Core setup and Xray Outbound operations.
- `VPN Panel`: TLS-verified Base Path-aware JWT login, mandatory `superadmin` role and valid internal license, protocol overview, and eight virtual services: L2TP, PPTP, OpenVPN, SSTP, IKEv2, OpenConnect, VMess and VLESS.
- VPN Panel user create/update/delete, protocol enable/disable, quota/device/expiry changes, usage reset and subscription delivery use only verified `/api/users`, `/api/dashboard/protocol-overview` and public `/api/sub/{token}` endpoints.
- VPN Panel `used_bytes` is total account traffic; the adapter does not fabricate separate upload/download values. Existing VPN Panel passwords are not returned by GET, so update requests omit password unless a real password exists in the encrypted local payload.
- Deleting a protocol from a multi-protocol VPN Panel account disables only that protocol flag; the whole user is deleted only when no other protocol remains enabled.
- Core setup, Xray Outbounds and arbitrary inbound CRUD are intentionally unavailable for the VPN Panel provider.

See [README_FA.md](README_FA.md) for the Persian operator guide and [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) for the acceptance ledger.

## Local development

```bash
cd bot
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
```

Configure `APP_SECRET_KEY`, `DATABASE_URL`, `BOT_TOKEN`, `ADMIN_TELEGRAM_IDS`, and `PANEL_CREDENTIAL_ENCRYPTION_KEY`. Run `alembic upgrade head`, then start the bot with `python -m vpn_manager.bot`.

## Installation

For a standalone bot-only host, run the nested installer from an interactive terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/AmiRaiZo/VPN-Control-Center/main/bot/install.sh | sudo bash
```

The installer downloads the latest stable Release, selects Python `>=3.12,<3.15`, creates a dedicated `.venv`, installs `vpn-manager-bot`, and runs Alembic migrations. The Telegram bot token and numeric owner ID are entered directly on the terminal; the token is verified with Telegram `getMe`, is not written to shell history or process arguments, and `.env` is saved with mode `0600`. The `vpn-help` maintenance menu is English-only.

For the integrated VPN Panel deployment, use `install/install.sh` for a fresh Main Panel installation or `install/update.sh` for an existing installation. The panel installer invokes `bot/install.sh` only after a successful fresh Main Panel install; panel updates call `bot/update-local.sh` only when the bot service is already installed. The bot keeps its own Python virtualenv and persistent `.env`, `var/`, `backups/` and SQLite database. If the host lacks a compatible Python runtime or an interactive TTY, panel installation continues and prints the exact manual bot-install command.

```bash
sudo systemctl status vpn-manager-bot
sudo journalctl -u vpn-manager-bot -f
sudo vpn-help
```

Panel updates preserve the bot's persistent data and virtualenv. Bot code/unit rollback is automatic when the local bot update fails; database schema downgrade is intentionally not attempted automatically. A pre-update data backup is retained for manual recovery.

## Provider API contracts

The `vpn-ui` adapter uses the panel session cookie, respects Base Path, sends `X-Requested-With`, and treats `success:false` as an API failure. Its `totalGB` field is bytes and `expiryTime` is Unix milliseconds.

The VPN Panel adapter uses `POST /api/auth/login` and Bearer JWT, requires `role=superadmin` and `internal_license_required=false`, and uses the verified user, protocol-overview and public subscription routes. No guessed `/xray-links` or `/openvpn-config` user routes are used. `sub_link` from the API is the delivery URL. OpenVPN, Xray subscription and SSTP certificate downloads use their documented public subscription endpoints.

## Validation boundary

Automated tests cover persistence/migrations, wallet ledger behavior, TOTP, installer configuration, mocked vpn-ui APIs, VPN Panel API adapter, paid-order fulfillment against both providers, and legacy polling shutdown. Live Telegram polling, live panel mutations, all protocol payloads, real payments, Ubuntu/systemd behavior, scheduled expiry/notifications and backup/restore drills remain unverified. Use one bot instance until distributed scheduler locking is added.
