# VPN Panel 2.3.272

## Login and Telegram watchdog stability

- Replaced one-thread-per-Telegram-log delivery with a bounded queue and one worker.
- Database sessions are released before any Telegram network request or retry.
- Telegram log delivery uses short, bounded retries and can no longer exhaust the API database pool.
- OpenVPN extra-port repair alerts are deduplicated, persisted, and repeated at most every six hours while the exact same fault remains.
- A single recovery notification is sent when the listeners become healthy again.
- The listener watchdog runs no more frequently than every five minutes.
- Controller-only hosts, disabled OpenVPN installations, missing base configs, and legacy extra-port rows that duplicate primary listeners no longer create endless false alarms.
- Login requests now have a 15-second client timeout, so the login button cannot remain stuck forever if the API is unavailable.
