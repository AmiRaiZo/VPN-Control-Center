# Changelog

## 1.1.3

- Fix the installer Telegram setup prompt for `curl | sudo bash`: Bash now reads the hidden token and visible admin-ID prompt directly from `/dev/tty`, then passes both values over a private stdin pipe to the setup module.
- Show an explicit Telegram verification progress message, report setup errors without a traceback, and handle Ctrl+C/termination during installation.

## 1.1.2

- Fix the Ubuntu installer on newer releases such as Resolute by installing Ubuntu's default Python runtime and venv packages instead of hard-coding Python 3.12.
- Validate the runtime against the project's supported range (`>=3.12,<3.15`), recreate an incompatible existing virtual environment, and invoke pip through the selected venv interpreter.

## 1.1.1

- Keep `.env` owned by the service account with mode `0600` after Super Admin ID or bot-token changes from `vpn-help`.

## 1.1.0

- Added the `sudo vpn-help` SSH maintenance menu for Super Admin ID changes, Telegram bot token rotation, latest-release updates and full uninstall.
- Installer now installs required system tools and downloads a pinned latest GitHub Release instead of an unpinned branch archive.
- Added per-subordinate-admin permission overrides managed by the Super Admin inside Telegram.
- Added the AuditLog viewer and a five-minute subscription lifecycle worker for 24-hour reminders, expiry suspension and retry of failed suspension.
- Clarified the storefront/admin separation and renamed the admin entry point to **پنل ادمین**.
- Added database migration `0003_admin_permissions`.
- Kept live Telegram, live vpn-ui, payment gateway and real Ubuntu installation verification as explicit deployment prerequisites.
