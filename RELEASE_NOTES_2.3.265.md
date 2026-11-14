# VPN Panel 2.3.265

- Fixed the login/recovery crash: `useNavigate() may be used only in the context of a <Router> component`.
- BrowserRouter is now the outer runtime provider around UIProvider and every route-aware component.
- Removed the nested router from App to guarantee exactly one router context.
- Renamed the active immutable frontend entry to `index-v23265.js` and rewired every lazy chunk to it.
- Updated the error-boundary and cache-busting identity to 2.3.265.
- Preserves all VPN Panel 2.3.264 Telegram configuration-delivery changes.
