# Push content to Fleet Manager

`fm_content_push` pushes one local file as it is. It does not fetch feeds, merge files or rewrite rules; the user prepares the file.

1. **What and where.** Settle with the user:
   - the kind: `intel`, `input`, `yara`, `suricata_rules`, a Suricata configuration file (`suricata_yaml`, `suricata_threshold`, `suricata_classification`, `suricata_reference`) or `bundle`;
   - the Fleet Manager;
   - the target:
     - intel and input: the source alias (an existing alias is updated in place);
     - input: also the file name on the sensors, which must be the name the reading Zeek package looks for;
     - YARA: the source name;
     - Suricata: the Suricata policy, or a sensor policy to use its Suricata policy, and, with rules automation, the rule source name;
     - bundle: the sensor policy.
   - For intel, input and YARA, ask whether to link the source to a sensor policy (`policy`), so its sensors get it. Without a link that some policy uses, nothing reaches a sensor.
2. **Preview.** Call `fm_content_push` without `confirm_token` and show the user:
   - the steps;
   - the diff against what Fleet Manager has: SIDs added, removed, changed, newly enabled or disabled; indicators or records added and removed; YARA rules; bundle packages added, changed and removed;
   - Fleet Manager's validation of Suricata rules or YARA;
   - which sensor policies get the change (`used_by_sensor_policies`);
   - notes and warnings.

   Point out in particular:
   - Objects managed by Corelight-update or Fleet-client are updated anyway. The note says that tool overwrites the change if it still runs.
   - Rule errors and duplicate SIDs. Fleet Manager's validation checks the rules themselves. It can pass rules that still fail to load on the sensors, for example rules for a protocol the sensors' Suricata configuration disables.
   - For bundles: new packages arrive disabled, and enabled packages missing from the new bundle stop loading.
   - For input files: whether the connected sensors report a package that reads the file.
3. If the preview says nothing changed, tell the user and stop.
4. After the user approves, call again with the same arguments plus `confirm_token`. If the file, the arguments or Fleet Manager changed in between, the token no longer matches: preview again.
5. Report the result and its verification. Fleet Manager sends the change to the sensors of the policies that use it. Packages that arrive disabled in a new bundle stay off until they are enabled in the sensor policy.
