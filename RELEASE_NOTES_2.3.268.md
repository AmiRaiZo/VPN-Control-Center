# VPN Panel 2.3.268

## Telegram groups per admin

- Every panel admin can connect one or more Telegram groups to their own account.
- Group linking uses a one-time 8-character code valid for 10 minutes.
- The linking sender must be the Telegram user bound to that panel admin and must be an administrator of the target Telegram group.
- Bot commands in a linked group run with the live permissions of the owning panel admin.
- User visibility, node targets, protocol access, create/edit/delete permissions and limits are inherited dynamically from the panel account.
- Disabling or expiring the panel admin immediately blocks the linked groups.
- Superadmins can review, test, disable and disconnect all linked groups.
- Telegram bot tokens remain global; no extra BotFather bot is required per admin.
- Existing single control-chat configuration remains supported for backward compatibility.
- Confirmed group bindings are included in full backups and restored by admin username; temporary one-time link codes are never backed up.
