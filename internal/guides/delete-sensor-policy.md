# Delete a sensor policy

1. Call `fm_policy_delete` without `confirm_token`. The preview lists:
   - everything the policy references: Suricata policy, YARA ruleset, intel, input, resource and CA bundle collections, and package bundle;
   - which other sensor policies use each of them.
2. **Groups using the policy block the delete.** A sensor group that still uses the policy blocks it. With the user, give each such group another policy (`fm_group_manage` update with `policy`), or delete the group, and say what that means for its sensors. The global policy cannot be deleted.
3. **Objects only this policy uses.** Show the user which objects no other policy uses and ask whether to remove them too: `remove_unused` with `all`, or any of `suricata_policy`, `yara_ruleset`, `intel_collection`, `input_collection`, `resource_collection`, `ca_bundle_collection`, `bundle`. Preview again with their answer. Objects another policy uses are always kept. Deleting a collection or YARA ruleset keeps its sources.
4. After the user approves, call again with the same arguments and `confirm_token`. fleet-mcp checks that the policy and the removed objects are gone.
