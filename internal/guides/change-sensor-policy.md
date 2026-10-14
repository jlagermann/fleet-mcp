# Change an existing policy

1. Fleet Manager has sensor policies and Suricata policies. If the user said only "a policy", ask which kind first.
2. Read the current state first: `fm_policies_list` / `fm_policy_get` for sensor policies, `fm_suricata_policies_list` / `fm_suricata_policy_get` for Suricata policies. Say which groups (and so which sensors) use the policy: a change reaches all of them.
3. Find the endpoint with `fm_api_describe` (REST) or the GraphQL schema, and make the change with `fm_api_write` or `fm_graphql_mutate`. The first call returns a preview (for PUT/PATCH a field-by-field diff against the current object) and a `confirm_token`. Show it, get the user's approval, then repeat the identical request with `confirm_token`. Preview again if anything in the request changes.
4. Changing a sensor policy's input, intel or asset classification collection, or its packages: apply the same enrichment chain check as `fm_policy_create` (see the create-sensor-policy guide): connector, source, collection, policy link, and a package that reads each input file. Point out anything that would do nothing.
5. Secrets (exporter tokens, passwords) are never typed in the chat; the user enters them at a hidden prompt or in the Fleet Manager web interface.
