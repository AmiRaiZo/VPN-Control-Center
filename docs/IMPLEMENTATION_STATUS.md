# Implementation status

This file is the acceptance ledger. A feature is marked complete only after implementation and a test or a documented live integration check.

| Area | State | Evidence / remaining work |
|---|---|---|
| vpn-ui API contract research | Implemented | API reference reviewed; protocol ids, identity keys, session cookie, 2FA, response envelope and units recorded. |
| Panel HTTP adapter | Initial implementation | Cookie jar per client, Base Path, HTTPS verification, login/logout, 2FA challenge detection, AJAX header, form encoding, JSON envelope checks. Mock tests pass. |
| Inbound reads | Initial implementation | List and get endpoints implemented; no live panel was connected during development. |
| Client add/update/delete | Initial implementation | API methods implemented; add requires explicit `enable=true`. No live panel mutation was tested. |
| Initial persistence schema | Implemented | SQLAlchemy models and Alembic `0001_initial` cover panels, customers, services, subscriptions, wallets/ledger, orders, payments, traffic snapshots and audit logs. Migration upgrade/downgrade was exercised on SQLite. |
| Panel credential encryption | Initial implementation | Fernet helper and production key validation exist; key rotation and operational secret lifecycle remain pending. |
| Multi-panel administration | Initial implementation | In-process registry isolates cookie jars and health-check failures; durable panel CRUD, session renewal policy and admin authorization remain pending. |
| Customer identity and RBAC | Pending | Needs Telegram identity, roles, permissions and authorization tests. |
| Subscription lifecycle | Pending | Needs durable operation state, idempotency and compensation/reconciliation. |
| Wallet, payments, reseller ledger | Pending | No live payment provider or financial posting is implemented. |
| Traffic history and server monitoring | Pending | Needs snapshots, unit-safe aggregation and live panel polling. |
| Telegram bot bootstrap | Initial implementation | Interactive setup hides the token, verifies it with Telegram `getMe`, validates numeric admin IDs, atomically writes `.env` with mode 0600, and installs a dedicated polling systemd unit. Mock tests pass; no live Telegram token was used. |
| Telegram bot commands | Minimal initial implementation | `/start` and `/admin` respond only to configured admin IDs; customer, sales, wallet and subscription workflows remain pending. |
| Web admin dashboard | Pending | Not implemented. |
| Backup and restore | Basic scripts only | Current archive covers `.env` and `var`; no database dump or restore drill yet. |
| Ubuntu deployment | Initial bot unit | One-line installer downloads the public source, installs Python dependencies, interactively configures Telegram and enables `vpn-manager-bot`; no database/API deployment or live Ubuntu install has been exercised. |
| Security review | Pending | No production threat-model review, penetration test or live TLS/secret-rotation test yet. |

## Acceptance rule

Do not use this version for live sales until persistent storage, access control, financial ledger, payment verification, worker recovery, backup/restore drills and live integration tests have been completed.

