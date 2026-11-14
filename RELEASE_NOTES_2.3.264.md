# VPN Panel 2.3.264

## Telegram user configuration delivery

- Added **ارسال کانفیگ** directly below the successful user-creation message and on each Telegram user-management card.
- Added **فایل‌های OpenVPN** only when OpenVPN is enabled for that user.
- Full delivery sends a readable message and a UTF-8 `CONNECTION-INFO.txt` file containing only protocols actually enabled for the user and available on the user's selected servers.
- L2TP/IPsec, PPTP, SSTP, IKEv2 and OpenConnect connection fields are rendered per selected server.
- VMess/VLESS URIs are included only when generated for that user/server.
- SSTP server certificates are sent for the selected SSTP servers when available.
- OpenVPN delivery uses the exact canonical subscription-generation path:
  - one per-server `.ovpn` file for every ready assigned server;
  - plus `ALL-USERNAME.ovpn` when two or more OpenVPN servers are assigned.
- Configuration messages/documents are no longer deleted by the Telegram control-message cleanup routine, so they can be forwarded to customers.
- The user-created caption now displays real server names instead of raw `node:<id>` tokens.
- Replaced the heavy decorative QR renderer with a compact 720×720 scanner-safe image with a guaranteed white quiet zone and no overlapping decorations.
