# VPN Control Center 1.1.1

Telegram-based administration and sales control plane for one or more `vpn-ui` instances from [Sir-MmD/vpn-ui](https://github.com/Sir-MmD/vpn-ui).

> **Development status — not approved for live commercial use.** Automated tests and mocked panel requests do not replace live Telegram/panel integration, production security review, recovery drills, or real payment verification. The current checkout flow is manual bank transfer with human review; no online payment gateway is implemented.

## Current capabilities

- Multi-panel credentials encrypted at rest, Base Path support, connection test, 2FA/TOTP login and inbound synchronization.
- Basic inbound create, rename, port/status update and confirmed deletion.
- Managed inbound-client synchronization, status toggle, delete and basic traffic/expiry/IP-limit editing where the protocol identity is supported. Protocol-native config files are delivered for OpenVPN, WireGuard-C, AmneziaWG, GRE and SSH using the documented panel endpoints.
- Core status/install and Xray VPN Outbound management; outbound settings currently require administrator-supplied JSON.
- Customer search/status, plan catalog and editing, orders, manual receipt review, wallet and subscription purchase/renewal/retry.
- `owner`, `admin`, `finance`, and `support` roles, encrypted client payloads, append-style wallet ledger with idempotency keys, and audit events for selected administrative/financial operations.

See [README_FA.md](README_FA.md) for the Persian setup and operator guide and [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) for the acceptance ledger.

## Local setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
```

Configure `APP_SECRET_KEY`, `DATABASE_URL`, `BOT_TOKEN`, `ADMIN_TELEGRAM_IDS`, and `PANEL_CREDENTIAL_ENCRYPTION_KEY`. Run `alembic upgrade head`, then start the Telegram polling process with `python -m vpn_manager.bot`.

## One-line Ubuntu installer

On Ubuntu 24.04 LTS, from an interactive terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/AmiRaiZo/VPN-Control-Center/main/install.sh | sudo bash
```

The installer downloads the latest stable GitHub Release (pinned by its `vX.Y.Z` tag), installs system prerequisites including `jq` and `rsync`, prepares Python 3.12 and a virtual environment, creates the `vpnmanager` system user, installs the project, runs Alembic migrations, prompts for a hidden Telegram token, verifies it using Telegram `getMe`, requests the numeric owner Telegram ID, writes `.env` with mode `0600`, enables `vpn-manager-bot`, and installs the `vpn-help` maintenance command.

```bash
sudo systemctl status vpn-manager-bot
sudo journalctl -u vpn-manager-bot -f
sudo vpn-help
```

Keep `PANEL_CREDENTIAL_ENCRYPTION_KEY` safe and stable. Replacing it without a planned key-rotation migration makes previously encrypted panel credentials and client payloads unreadable. A real Ubuntu/systemd installation has not yet been exercised for this development state.

## Sales flow

An administrator adds a panel, synchronizes its inbounds, creates a plan and configures the manual payment instructions. A customer creates an order, sends a receipt photo with the full order UUID in its caption, and waits for an authorized administrator to approve or reject it. Provisioning runs only after approval. Wallet top-ups follow the same manual-review process. Wallet purchases, renewals and provisioning retries are available, but crash recovery/reconciliation across the database and remote panel still needs further work. The Super Admin can add subordinate admins from `vpn-help` and assign per-area permission overrides in Telegram. A five-minute lifecycle worker sends 24-hour reminders and attempts to disable expired clients; run only one bot instance until distributed scheduler locking is added.

## API and protocol caveats

The adapter uses the panel session cookie, respects Base Path, sends `X-Requested-With`, and treats `success:false` as an API failure. The client `totalGB` field is treated as bytes and `expiryTime` as Unix milliseconds, according to the reviewed API contract.

Recognizing a protocol does not guarantee complete automatic provisioning. In particular, `wg-c`, `awg`, `gre`, `mtproto`, and `hysteria` need protocol-specific schema validation against the exact target panel version. No live protocol-by-protocol provisioning test has been completed. Inbound creation currently covers basic fields rather than every stream/network/TLS/Reality option.

The per-client `limitIp` value caps simultaneous source IPs; it is not a guaranteed physical-device counter. For WireGuard-C, AmneziaWG and GRE, config slots are controlled by the inbound-level `userLimit`, not independently by each sales plan.

## Validation boundary

Automated tests cover persistence/migrations, wallet ledger behavior, TOTP, installer configuration, mocked panel APIs and mocked provisioning. Live Telegram polling, live vpn-ui mutations, all protocol payloads, real payments, Ubuntu/systemd behavior, multi-admin race testing, scheduled subscription expiry/notifications and backup/restore drills remain unverified. The current payment provider is manual review only.

