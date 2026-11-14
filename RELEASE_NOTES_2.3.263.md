# VPN Panel 2.3.263

- PPTP installer now repairs stale listeners, orphaned daemons, obsolete PID units, invalid pools and incompatible logwtmp plugins before runtime verification.
- Full protocol provisioning automatically performs one recovery pass and retries a failed backend.
- Manual backups run as background jobs, avoiding reverse-proxy 120-second read timeouts.
- Temporary license-server/network outages no longer bounce the UI between the dashboard and license-lock page; genuine invalid or expired responses remain fail-closed.
