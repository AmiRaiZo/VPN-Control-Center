# Recovering a failed Ubuntu 24.04 installation

The previous failure occurred while dpkg was configuring strongSwan and
xl2tpd. The final package list in APT output identifies affected packages, but
not necessarily the first post-install error that triggered the cascade.

Version 2.3.3 performs these steps automatically before continuing:

1. waits for legitimate APT/dpkg owners to release their locks;
2. pauses automatic APT jobs without deleting lock files;
3. prevents VPN daemons from starting while package files are incomplete;
4. runs `dpkg --configure -a`;
5. runs `apt-get --fix-broken install` when required;
6. installs package groups independently;
7. restores normal service-start and APT timer behavior.

After publishing this ZIP on the license server, rerun:

```bash
curl -sSL https://license.tr.amiraizo.xyz:9999/install.sh | sudo bash
```

If recovery still fails, the last log section now contains `dpkg --audit`,
recent dpkg log entries, failed systemd units, and OOM diagnostics. Those lines
should be provided in full because they contain the original package error.
