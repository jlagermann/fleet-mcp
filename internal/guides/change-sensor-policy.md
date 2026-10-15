# Change an existing policy, or which sensors use it

1. **Which policy.** Fleet Manager has sensor policies and Suricata policies. If the user said only "a policy", ask which kind first. Suricata rule tuning: see the tune-suricata guide. Suricata settings (address groups, eve options): `fm_api_write` on the Suricata policy.
2. **Read the current state:**
   - `fm_policies_list` and `fm_policy_get`;
   - which sensor groups (and so which sensors) use the policy, since a change reaches all of them;
   - for a setting's exact name, `fm_policy_get` with select `/configuration.metadata/properties`.

## Settings, packages and linked content: `fm_policy_update`

One call changes a sensor policy:

| What | Argument | Notes |
|---|---|---|
| Settings | `settings` | Key -> value. `null` resets a setting to its default. Lists can be a JSON array. |
| Secret settings | `secret_settings` | Proxy password, exporter tokens and the like. The user stores each at a hidden prompt with `fleet-mcp secret set-setting <key>` (give the full path, as tool results do). Never take them in the chat. They are removed from the store once the policy holds them. |
| Packages | `enable_packages`, `disable_packages` | Corelight packages by name (`corelight:<name>` or the display name), and custom bundle packages by key or short name. New bundle packages arrive disabled; this enables them. |
| Linked content | `suricata_policy`, `yara_ruleset`, `intel_collection`, `input_collection`, `resource_collection`, `ca_bundle_collection`, `bundle` | An id or name, or `none` to unlink. |
| Name and description | `name`, `description` | |

Call without `confirm_token` and show the user:
- **every change from -> to.** "default" means the setting is not set in the policy;
- **settings that are already so**;
- **licensed features turned on.** Sensors without that license keep the feature off;
- **Fleet Manager's validation.** fleet-mcp also checks IP and CIDR lists, which Fleet Manager does not;
- **the enrichment chain** of the linked intel, input and resource collections: sources that are disabled, empty, fed by a connector, and input files no package on the connected sensors reads. Explain anything that would do nothing (see the create-sensor-policy guide for the full connector, source, collection, policy and package chain);
- **which groups and sensors get the change.**

After the user approves, call again with `confirm_token`. fleet-mcp reads the policy back and checks that nothing else changed. Fleet Manager then sends the policy to its sensors; `fm_sensors_list` shows each sensor's config-apply state.

## Which sensors use a policy: `fm_group_manage`

A sensor is in one sensor group, and the group has one sensor policy.
- `create`, `update` or `delete` a group.
- Set its `policy`, or `none`.
- `add_sensors` moves sensors in from wherever they are. `remove_sensors` makes them unassigned.

The preview shows each sensor's group and policy before and after. It also lists licensed features the new policy turns on that a sensor has no active license for (they stay off on that sensor), and sensors that are not connected (they get the change when they reconnect). Point these out.

Moving sensors changes what they run. Name each sensor and the policy it gets, and get the user's approval.

Unassigned sensors, and sensors left by a deleted group, keep their current configuration until they join a group with a policy.
