# Push content to Fleet Manager

`fm_content_push` pushes one local file as it is. It does not fetch feeds, merge files or rewrite rules; the user prepares the file. The one exception is converting Corelight-update syntax in a tuning file when the user asks for it (see the preview step). To put a source that already exists in Fleet Manager (for example one Corelight-update created) into a collection, without uploading it again, use `fm_collection_manage` instead (manage-collections guide).

1. **What and where.** Settle with the user:
   - the kind: `intel`, `input`, `yara`, `suricata_rules`, a Suricata configuration file (`suricata_yaml`, `suricata_threshold`, `suricata_classification`, `suricata_reference`), a Suricata tuning file (`suricata_disable`, `suricata_enable`, `suricata_modify`: the `disable.conf`, `enable.conf`, `modify.conf` of a policy with Suricata automation and "Use configuration files") or `bundle`;
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
   - Rule errors and duplicate SIDs. Fleet Manager only parses the rules; it does not run Suricata. Offer a real test with `fm_suricata_test` (see the tune-suricata guide): before pushing a rules file test the file, and after a push to a policy with Suricata automation test the policy's generated ruleset.
   - For tuning files: the syntax problems (Fleet Manager rejects the whole file for one bad line), a switch from the rules manager to configuration files (rule modifiers made in the rules manager stop applying), and whether "Enable flowbit dependencies" is on.
   - **Corelight-update syntax** (decision `cu_modifiers`): lines Fleet Manager rejects or silently ignores, such as `MetadataAppend`, `Msg`/`GID`/`Rev`/`Classtype` changes, regex rewrites (`"<from>" "<to>"`), `re:` without slashes, `Metadata:` matches, SID lists and `gid:sid`. Show `conversion.lines` (each line and the reason; what a line becomes is shown now only where it needs no rule text), then ask: convert, comment out, or stop. Preview again with `cu_modifiers: "convert"` or `"comment_out"`. Only convert reads the policy's rules (a few minutes for ET Pro); show that preview's `conversion.lines` results before asking for approval. The result goes to `<name>.fm.conf` next to the user's file, which is not changed. Point out:
     - `frozen_sids`: these rules get a `RuleOptions` line with their whole option text. When the source updates such a rule (a new rev), the old text stays until the file is converted again.
     - Regex rewrites that change one header field become one `re:` line per original value, so new rules that match still get the change. Otherwise they become one line per rule.
     - `need_rules_file`: lines touching rules the current modify.conf already changes and that come from a URL source (Fleet Manager only shows them changed). They are commented out unless `rules_file` gives the original rules.
     - `Other:` is never converted.
   - For bundles: new packages arrive disabled, and enabled packages missing from the new bundle stop loading.
   - For input files: whether the connected sensors report a package that reads the file.
3. If the preview says nothing changed, tell the user and stop.
4. After the user approves, call again with the same arguments plus `confirm_token`. If the file, the arguments or Fleet Manager changed in between, the token no longer matches: preview again.
5. Report the result and its verification. Fleet Manager sends the change to the sensors of the policies that use it. Packages that arrive disabled in a new bundle stay off until they are enabled in the sensor policy.
