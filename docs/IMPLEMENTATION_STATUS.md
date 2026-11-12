# Implementation and acceptance status

This ledger distinguishes local implementation from live integration evidence. A feature is not production-complete merely because its handler or API method exists.

## Implemented locally; automated evidence exists

| Area | Current state | Evidence / boundary |
|---|---|---|
| Persistence | Implemented | SQLAlchemy models for panels, customers, services, plans, managed clients, subscriptions, wallets/ledger, orders, payments and audit logs. Alembic `0001`/`0002` upgrade, check and downgrade were exercised against temporary SQLite. |
| Telegram bootstrap | Implemented locally; live interaction pending | Installer reads the hidden token and visible owner-ID prompt directly from `/dev/tty`, pipes credentials to the setup module without exposing the token in argv/history, reports Bot API verification progress, and handles Ctrl+C. Token-format validation, Telegram `getMe` verification, numeric owner ID validation, atomic `.env` write and mode `0600`; Telegram call is mocked in tests. |
| RBAC | Implemented locally; live security review pending | Roles `owner`, `admin`, `finance`, `support`; Super Admin can create per-admin permission overrides in Telegram. Callback permissions and per-message administrative FSM re-check middleware; revocation clears admin FSM. |
| Panel credentials | Implemented | Fernet-encrypted password and TOTP seed; no key-rotation workflow. Key must remain stable across restarts/backups. |
| vpn-ui session adapter | Initial implementation | Session cookie, Base Path, HTTPS verification, AJAX header, form-encoded requests, JSON envelope and API error handling; HTTP mock tests only. |
| Inbound operations | Partial | List/get/create-basic/update name/port/status/delete and certificate endpoints implemented. Full stream/network/TLS/Reality settings wizard is not implemented. |
| Client operations | Partial | Inbound client sync, show, enable/disable, delete and traffic/expiry/IP-limit edits. Protocol-native config files are delivered for OpenVPN, wg-c, awg, GRE and SSH using documented GET endpoints. Manual client creation, full credential editor and generic QR generator are not complete. |
| Core and Xray outbound | Partial | Core status/catalog/install/provision status and VPN outbound list/kinds/status/save/delete. Outbound creation currently requires administrator-supplied JSON. |
| Customer administration | Partial | Search, details, block/restore attempts, wallet balance and manual wallet adjustment. Restore retries both `suspended` and `suspension_failed` subscriptions. Owner-only AuditLog browser displays the latest 20 events; event coverage is not exhaustive. |
| Plan catalog | Partial | Add, show, edit name/duration/traffic/devices/price, enable/disable. Description/currency editing, capacity controls, archive/delete and plan migration are not implemented. |
| Orders and manual payments | Partial | Create subscription/top-up orders, attach receipt photo, manager approve/reject, provisioning retry and customer notification. Approval claims order conditionally; rejection uses conditional order/payment updates. Paid/processing orders can be manually recovered by an authorized manager. No gateway verification. |
| Wallet | Partial | Ledger entries, idempotency keys, negative-balance prevention, top-up, purchase debit, manual adjustment and refund on handled provisioning failure. Manual recovery of an interrupted paid top-up is idempotent; automatic reconciliation worker is not implemented. |
| Subscription provisioning | Partial | Encrypted payload persistence, create/update client, retry identity reuse, expiry/traffic/device update and renewal path. Live panel/protocol validation is outstanding. |
| Installer / maintenance | Implemented locally; not live-verified | Ubuntu installer refreshes source from the latest pinned GitHub Release on every run while preserving `.env`, `var/`, `.venv/`, and backups; installs prerequisites and Ubuntu's default Python/venv/pip packages; validates Python `>=3.12,<3.15`; creates the service account/venv; runs migrations; reads Telegram credentials from `/dev/tty` with explicit prompts and interrupt handling; then installs `vpn-help`. English-only SSH menu updates the Super Admin ID and bot token independently, verifies tokens before persistence, preserves the other credential, checks systemd service existence/state, reports restart failures truthfully, updates from latest Release with backups, and performs confirmed full uninstall. No real Ubuntu installation has been run. |
| Subscription lifecycle | Implemented locally; single-instance assumption | Five-minute worker sends a 24-hour expiry reminder, disables due clients through vpn-ui, marks them expired, and retries `suspension_failed`. Multiple bot instances require a distributed scheduler lease before production. |
| Documentation | Updated locally | Persian and English operator guides now describe roles, manual sales, installation, backup cautions and known limitations. |

## Explicitly unverified / production blockers

1. No live Telegram bot token or polling session was used.
2. No live `vpn-ui` instance was connected; no real inbound/client/core/outbound mutation was performed. Protocol config endpoints are mock-tested only.
3. No protocol-by-protocol provisioning validation has been completed. `wg-c`, `awg`, `gre`, `mtproto`, `hysteria`, and other special protocols need exact schema fixtures from the target panel version.
4. `totalGB` as bytes and `expiryTime` as Unix milliseconds are assumptions taken from the reviewed API contract and still need live-version confirmation.
5. Periodic panel health checks and DB/panel reconciliation are not implemented. Lifecycle worker is single-process and has no distributed lease; do not run multiple bot instances.
6. Manual client creation, complete credential editing, QR generation and subscription-link verification with Base Path are incomplete. `limitIp` caps source IPs, not guaranteed physical devices; WireGuard/AmneziaWG/GRE config slots depend on inbound-level `userLimit`.
7. Manual bank-transfer receipt review is the only payment path. There is no online gateway or automated bank verification.
8. Wallet purchase and panel provisioning span multiple commits/network I/O. Paid/processing orders have a manual recovery action with idempotent ledger posting, but no automatic recovery/reconciliation worker exists.
9. Renewal retry semantics need dedicated tests for expired and unexpired subscriptions and interrupted panel updates.
10. Customer restore retries `suspension_failed` records, but there is no automatic retry queue or alerting for failed suspension operations.
11. AuditLog browser now shows the latest 20 events to users with the `audit` permission, but event coverage is not exhaustive and pagination/filtering are not implemented.
12. Backup/restore automation, database restore drill and Fernet key rotation are not implemented. Backups must include both database and secrets.
13. Installer/systemd hardening, service permissions and SQLite write access have not been validated on a real Ubuntu 24.04 host or a disposable Ubuntu VM.
14. Multi-admin concurrency, concurrent wallet debit, callback replay and process-crash scenarios need integration tests.
15. No security penetration test or production threat-model sign-off has been completed.

## Latest local validation

The installer, credential-update and SSH-menu changes are covered by **77 passing pytest tests**, Ruff check/format, compileall, `pip check`, `bash -n` and an ASCII-only scan of every root-level SSH shell script. Earlier migration validation (`upgrade head`, `alembic check`, `downgrade base`) passed against a disposable SQLite database; these changes do not alter the schema. Ubuntu `resolute` package metadata lists the distribution `python3` default as Python 3.14; no live Ubuntu installation has been run in this workspace.

## Release gate

Do not use for live sales until live Telegram/panel integration, protocol-specific payload validation, atomic financial transitions and recovery, scheduled subscription lifecycle, backup/restore, production secret handling, Ubuntu installation tests and a security review have passed. Do not claim a live payment or panel operation from a mock test.
