# VPN Panel 2.3.270

- The active frontend entry is now `index-v23270.js`; every active lazy chunk is wired back to this one entry, so an older entry cannot mount a second React root.
- `BrowserRouter` is the outermost runtime provider and the React root is created once and reused.
- Removed the unsafe global `Node.prototype` mutation override that could hide or create `removeChild` failures.
- Added per-Telegram-group access modes: all members except explicit blocks, or approved members only.
- Added explicit numeric Telegram user ID allow/deny rules. An explicit deny always has priority.
- Group members continue to operate only with the live permissions, node scope, protocol scope and quotas of the panel admin that owns the group.
- Added owner/superadmin management UI and backup/restore support for group member rules.
