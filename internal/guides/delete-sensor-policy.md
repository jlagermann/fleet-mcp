# Delete a sensor policy

1. With `fm_policies_list`, list what the policy references: Suricata policy, YARA ruleset, input, intel, CA bundle and resource collections, and package bundle.
2. For each of those, find whether any other sensor policy references it.
3. Say which sensor groups use the policy.
4. Show all of this in the delete preview (`fm_api_write` DELETE without `confirm_token`). Ask whether to remove the objects only this policy uses as well. Keep anything another policy still uses.
5. After the user approves, delete with `confirm_token`, then delete the extra objects the user chose, each previewed in the same way.
