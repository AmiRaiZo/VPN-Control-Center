# VPN Panel 2.3.266

- Allow authenticated superadmins on node panels to read and change the controller migration settings endpoint.
- Prevent the node-role middleware from returning `node_managed_by_controller` for `/api/settings/node-controller`.
- Recover controller URL, token state, node name and public URL from all durable legacy/current configuration files.
- Preserve database-first precedence and never expose the stored controller token to the frontend.
