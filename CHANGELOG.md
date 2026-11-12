# Changelog

## 1.1.0

- Added the `sudo vpn-help` SSH maintenance menu for Super Admin ID changes, Telegram bot token rotation, latest-release updates and full uninstall.
- Installer now installs required system tools and downloads a pinned latest GitHub Release instead of an unpinned branch archive.
- Added per-subordinate-admin permission overrides managed by the Super Admin inside Telegram.
- Added the AuditLog viewer and a five-minute subscription lifecycle worker for 24-hour reminders, expiry suspension and retry of failed suspension.
- Clarified the storefront/admin separation and renamed the admin entry point to **پنل ادمین**.
- Added database migration `0003_admin_permissions`.
- Kept live Telegram, live vpn-ui, payment gateway and real Ubuntu installation verification as explicit deployment prerequisites.

