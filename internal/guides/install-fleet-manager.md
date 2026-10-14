# Install Fleet Manager

1. Call `fm_install_checklist` (with the host if you know it) and show its markdown checklist to the user before anything else.
2. Work through the missing items with the user, one at a time:
   - The user supplies their own Corelight repository token and product identity certificate.
   - Tokens and passwords are typed by the user at a hidden terminal prompt (`fleet-mcp secret set repo-token`). Give every fleet-mcp command with the full path, as tool results do; fleet-mcp may not be on the user's PATH.
   - Files (identity certificate, Software Sensor license) are imported with `fm_secret_import_file`.
   - Never ask for tokens or passwords in the chat. `fm_secrets_status` shows what is stored, never the values.
3. `fm_host_check` checks the host read-only. When something blocks the install (for example too little free space), explain the fix and make it only after the user approves it.
4. Call `fm_host_install` without `confirm_token`. It changes nothing and returns the install plan. Show the plan, get the user's approval, then call again with the identical request and `confirm_token`.
5. Give the user the `admin_temporary_password` from the result; they must change it at first login, and fleet-mcp does not keep it. Then check the new Fleet Manager with `fm_fleets` (check: true) and `fm_info`.
