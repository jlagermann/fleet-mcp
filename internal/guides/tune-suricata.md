# Tune Suricata rules

Rule tuning (disabling, enabling or changing rules) needs a Suricata policy with **Suricata automation** on. Fleet Manager then builds the ruleset from the policy's rule sources. It applies tuning in one of two modes; read the policy with `fm_suricata_policy_get` to see which (`useModifierFiles`):

- **Suricata rules manager** (`useModifierFiles: false`, Fleet Manager's recommended mode): one modifier per change. Use `fm_suricata_modify`.
- **Configuration files** (`useModifierFiles: true`): `disable.conf`, `enable.conf`, `modify.conf`. Push them with `fm_content_push` (kinds `suricata_disable`, `suricata_enable`, `suricata_modify`). Pushing a configuration file to a policy in rules-manager mode switches the mode, and the rules-manager changes stop applying.

Do not switch modes without the user's say-so.

## Change rules in the rules manager

1. Find the rules: the user's SIDs, or a match on another attribute (`match_key`: `re` with `/regex/`, `classtype`, `msg`, `metadata`, and so on).
2. Call `fm_suricata_modify` without `confirm_token`. Show the user:
   - each rule's current effective state (`rules_now`) and the expected result;
   - the modifiers that are added, updated (same rule and field) or removed (an enable replaces a disable and the other way round);
   - Fleet Manager's validation;
   - the notes.
3. Point out:
   - a SID that is not in the rule sources (the modifier waits for it);
   - when "Enable flowbit dependencies" is on, a disabled rule that sets a flowbit an enabled rule checks is turned back on;
   - which sensor policies get the change.
4. After the user approves, call again with `confirm_token`. fleet-mcp waits for the ruleset rebuild and checks every changed rule.
5. To undo a change, remove its modifier (`remove`: the modifier id, or `sid:<n>` for all modifiers on that rule). The rule goes back to its state in the rule sources.

Modify changes: `action`, `srcaddress`, `srcport`, `destaddress`, `destport`, `protocol`, or `ruleoptions` (the whole option text in parentheses, for example to add `flowbits:noalert;`).

## Test the ruleset

Fleet Manager only parses rules; it does not run Suricata. `fm_suricata_test` loads a ruleset with a real Suricata (`suricata -T`) on a host the user names, over SSH.

- **Version:** ask which host to use. Its Suricata should be the same version as the sensors' (the sensor logs it at startup: `fm_sensor_shell` check `service_logs`, service `sensor-core`, container `software-sensor`, pattern `Suricata version`).
- **What to test:**
  - before pushing a rules file: `file`;
  - after tuning or a push to a policy with automation: `suricata_policy`. This tests the ruleset Fleet Manager actually built and sends.
- **Variables:** the policy's address and port groups (its settings and `suricata.yaml` snippet) are passed to Suricata. Undefined variables show up as `undefined_vars`.
- **Configuration:** the host's stock `suricata.yaml` is used unless the user gives one (`config`). A rule for a protocol the sensors disable passes with the stock configuration and fails on the sensor, so a copy of the sensors' configuration gives the closest result.

Report the rules loaded and failed, the failure reasons and the failed SIDs.
