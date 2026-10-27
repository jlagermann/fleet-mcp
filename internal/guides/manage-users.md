# Manage Fleet Manager users

Fleet Manager users log in to its web interface and API. Each has a role (admin, monitor, editor, rules_editor, downloader, or a custom one), optional per-group permissions, and optional two-factor authentication (2FA, an authenticator app). `fm_users_list` shows them; `fm_user_manage` changes one user at a time.

## Look first

1. Run `fm_users_list` (all Fleet Managers, or the one the user names). Show the users, their roles and 2FA state, and the findings: admins without 2FA, everyone being admin, password changes still pending (often an account nobody uses), failed logins, test accounts, and whether only local accounts exist.
2. The account marked `fleet_mcp_account` is the one fleet-mcp logs in with. It must stay an admin and must not get 2FA: fleet-mcp logs in through the API and cannot answer a 2FA prompt. The tool refuses both.
3. Other accounts may belong to integrations (Corelight-update, a SIEM or threat-intel connector). Ask before deleting, demoting or turning on 2FA for one: an integration cannot answer a 2FA prompt either.

## Change a user

4. Call `fm_user_manage` without confirm_token for a preview, by **username**: fleet-mcp looks up the id the API needs (the API itself only accepts the id; a username there gives 404 "User not found"). Show the changes, steps and warnings, and name the Fleet Manager.
   - **create**: needs a role. The initial password never goes through the chat: the user runs `fleet-mcp secret set-setting fm-user:<username>` in their terminal (hidden prompt; the tool result gives the full command) and gives it to the new user outside the chat. The new user must change it at first login; the stored copy is deleted after the user is created. `require_2fa: true` makes them enroll an authenticator app at that login.
   - **update**: role, first and last name, `require_2fa`. For a role change (and a create) the preview has `permission_changes`: what the user gains, loses and keeps, by category. Show the user what they gain and lose, especially the sensitive ones the warnings name, and for a custom role go through its permissions. Everything else (permissions, 2FA enrollment, theme) is sent back as it was.
   - **reset_2fa**: for a user who lost their authenticator app. They enroll again at the next login, and Fleet Manager also asks them for a new password. A user with 2FA off has nothing to reset; one who never enrolled enrolls at the next login anyway.
   - **delete**: cannot be undone. The tool refuses the last admin and fleet-mcp's own account.
5. After the user approves, call again with the same arguments plus confirm_token. The result lists what was done and what the read-back confirmed; any `problems` need a look.

## Good practice to suggest

- Give people the least role that fits: monitor to look, editor to change sensors and policies, admin only to those who administer Fleet Manager.
- Require 2FA for every person's admin account.
- Remove test accounts and accounts whose password change has been pending for a long time.
- With many users, a central login (LDAP, SAML, RADIUS or TACACS+, set up in the Fleet Manager web interface) is easier to keep current than local accounts.
