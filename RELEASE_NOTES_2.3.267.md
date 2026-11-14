# VPN Panel 2.3.267

- Prevented React startup/route crashes caused by browser translators or extensions moving React-owned DOM nodes.
- Added guarded removeChild, insertBefore and replaceChild handling before the first React render.
- Marked the panel document and React root as notranslate to stop automatic translation from rewriting the application DOM.
- Published a new immutable frontend entry and cache identity for 2.3.267.
- Preserved all VPN, node-controller, Telegram configuration delivery and runtime recovery changes from 2.3.266.
