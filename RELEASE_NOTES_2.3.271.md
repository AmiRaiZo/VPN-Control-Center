# VPN Panel 2.3.272

- Rebuilt the complete frontend asset namespace for this release; no shared JavaScript chunk from 2.3.261–2.3.270 is reused.
- Removed React Router context dependency from imperative login, logout, license and dashboard redirects.
- Added a context-independent full-page navigation fallback in the production bundle.
- Added release ownership for the React root so a previous bundle cannot reuse/mix its root with the new UI.
- Preserved per-group Telegram member allow/block controls introduced in 2.3.270.
