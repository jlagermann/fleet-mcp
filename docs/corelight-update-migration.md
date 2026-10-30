# Moving Suricata tuning from Corelight-update to Fleet Manager

Fleet Manager can build a Suricata policy's ruleset itself. With **Suricata automation** on, it combines the policy's rule sources and applies tuning. Tuning comes in one of two forms:

- the **Suricata rules manager** (rule modifiers made in the web interface), or
- **configuration files** (`disable.conf`, `enable.conf`, `modify.conf`).

If you use Corelight-update today, the configuration files look like the place to move your tuning. They are close to Corelight-update's files, but not the same. This page lists the differences found by running the same rules and tuning files through both. Use it to plan a migration and to know what to check afterwards.

Tested with Fleet Manager 29.2.2 and Corelight-update's main branch (2.1.8 release notes merged; it includes the multi-pass bit-dependency fix), on 2026-10-15.

## How the test was run

- **Rules:** a small crafted ruleset with one case per flowbit situation, plus 135,602 rules from a commercial ruleset.
- **Tuning:** a production `disable.conf` (6 entries), `enable.conf` and `modify.conf` (362 lines) from Corelight-update.
- **Both sides:** the same input and the same tuning files went through Corelight-update's rule processor and through a Fleet Manager Suricata policy (automation on, configuration files on). The two outputs were compared rule by rule: enabled state, header and options.

## Summary

| | Corelight-update | Fleet Manager 29.2 |
|---|---|---|
| Ruleset test | Runs Suricata on the ruleset: the microsensor, or open-source Suricata | Parses the rules only; it does not run Suricata |
| Configuration files | Its own syntax | Similar syntax, fewer change keys, checked at upload; a single bad line rejects the whole file |
| Tuning result | | Identical, for every line Fleet Manager accepts, once `Metadata:` matches are rewritten (below) |
| Flowbit dependencies | Multi-pass; set and toggle; isset and isnotset; flowbits, xbits and hostbits; optional `noalert` | Single pass; set and isset only; flowbits only; no `noalert`; also enables setters that are not needed |

## Configuration file syntax

Fleet Manager checks every line when the file is uploaded and rejects the whole file at the first problem (for example `parsing modifier on line 96: validating: invalid change key "Msg"`). Some other lines are accepted but match nothing.

`fm_content_push` finds both kinds before uploading. It lists each line with what it would become and asks you to **convert** them, **comment them out** or stop (`cu_modifiers`). The result is written to `<name>.fm.conf` next to your file, with each converted line keeping the original as a comment. Your file is not changed. The "Conversion" column below shows what it does.

Fleet Manager applies the lines **in file order**, as Corelight-update does. A later `re:` sees the result of an earlier change, so a converted `MetadataAppend` still feeds a regex that matches on the added metadata.

### modify.conf

Fleet Manager accepts `<matchKey>:<value> <changeKey>:<value>`.
- **Change keys:** `Action`, `Protocol`, `SrcAddress`, `SrcPort`, `DestAddress`, `DestPort`, `Priority` (adds or replaces `priority:N;`) and `RuleOptions`.
- **Match keys:** `SID` (or a bare number), `re:/regex/`, `Action`, `ClassType`, `DestAddress`, `DestPort`, `Filename`, `GID`, `Group`, `Msg`, `Metadata`, `Priority`, `Protocol`, `Reference`, `Rev`, `SrcAddress`, `SrcPort` and `Target`.
- `re:/…/` is tried against the whole rule, header included (`^alert \S+ \$EXTERNAL_NET …`), with Go regex syntax. Escape a `/` inside it as `\/`.
- Several lines for one SID all apply.

| Corelight-update | Fleet Manager | Conversion |
|---|---|---|
| `MetadataAppend:`, `Metadata:`, `Msg:`, `GID:`, `Rev:`, `SID:`, `Classtype:`, `Target:`, `Threshold:`, `OtherAppend:`, `FlowbitsNoAlert:`, `NoAlert:` as change keys | Rejected | One `<sid> RuleOptions:(…)` per matched rule, with that one option edited the way Corelight-update does it. The rule's option text is then **frozen**: when the source updates the rule, the old text stays until you convert again. |
| `Other:` (replaces every detection option) | Rejected | Not converted: commented out or rewritten by hand. |
| `re:<regex> "<from>" "<to>"`, `<sid> "<from>" "<to>"` (regex rewrite of the raw rule) | Rejected | When it changes one header field, one `re:/^… <original value> .*<regex>/ <Field>:<new value>` per original value. These keep matching new rules, and fleet-mcp checks they select exactly the rules the rewrite changes. Otherwise, one line per changed rule (header fields, plus a frozen `RuleOptions` when the options change). |
| `re:<regex>` or `re:"<regex>"` without slashes | Rejected | `re:/<regex>/`. |
| `a,b,c` (SID list) | Rejected | One line per SID. |
| `1:<sid>` (gid:sid) | Accepted, but matches no rule | `<sid>`. |
| `Metadata:"<text>"` as a match | Accepted, but matches no rule | `re:/metadata:[^;]*<text>/`. |
| `*` | Rejected | `re:/./`. |
| `SrcAddress`, `DestAddress`, `SrcPort`, `DestPort`, `Protocol`, `Action`, `Priority`, `RuleOptions` | Accepted | Kept as they are. |

The conversion needs each rule's text **as it is before the file applies**. fleet-mcp reads it from the Suricata policy, but Fleet Manager only shows rules after its current configuration files. Rules the current modify.conf changes are therefore read again from their file source. Rules from a URL source (ET Open, ET Pro) have no downloadable file: lines that touch them are commented out unless you give `rules_file`, a local copy of those rules.

### disable.conf and enable.conf

Fleet Manager accepts:
- a bare SID (`2000328`) or `SID:2000328`;
- `re:/regex/`;
- `Field:value` with the match keys above.

| Corelight-update | Fleet Manager | Conversion |
|---|---|---|
| `Metadata:"deployment SSLDecrypt"` | Accepted, but matched no rules (with or without quotes). In the test, the quoted form left 4,136 rules enabled that Corelight-update disables. | `re:/metadata:[^;]*deployment SSLDecrypt/` |
| `1:<sid>` (gid:sid) | Accepted, but matches no rule | `<sid>` |
| `a,b,c`, `re:<regex>` without slashes | Rejected | One line per SID; `re:/<regex>/` |
| Bare SIDs, `SID:`, `re:/.../` | Accepted | Kept as they are. |

Fleet Manager stores each entry with a `-` (disable), `+` (enable) or `~` (modify) prefix. The file you download back shows them.

## Flowbit dependencies

Both tools can turn on rules that set a flowbit when an enabled rule checks it. In Fleet Manager this is **Enable flowbit dependencies** on the Suricata policy (`srmEnableFlowBits`). In Corelight-update it is `resolve_bit_dependencies`, with `modify_bit_dependencies` to add `noalert` to the rules it enables.

| Case | Corelight-update | Fleet Manager 29.2 |
|---|---|---|
| Disabled setter, enabled `isset` | Enables the setter | Enables the setter |
| Chain (C needs B, B needs A) | Enables B and A (repeats until nothing changes) | Enables B only (one pass) |
| Enabled `isnotset` | Enables the setter | Does nothing |
| `toggle` | Counts as a setter | Does not count |
| Name already set by an enabled rule | Enables nothing | Enables **every** other disabled setter of that name |
| `unset` only | Not a setter | Not a setter |
| Checking rule is disabled | Enables nothing | Enables nothing |
| `isset,a\|b` and `isset,a&b` | Not resolved | Not resolved |
| xbits, hostbits | Resolved like flowbits | Ignored |
| Setter that alerts | Adds `flowbits:noalert` (with `modify_bit_dependencies`) | Enables it as it is, so it alerts |
| Setter disabled in `disable.conf` | Enabled again: dependencies run after the configuration files | Enabled again |

On the 135,602-rule set, with the same tuning:
- **Fleet Manager enabled 441 rules that Corelight-update did not.** Every one sets a flowbit that another enabled rule already sets. 248 of them are rules the ruleset marks as `DELETED`.
- **Corelight-update enabled 2 rules that Fleet Manager did not:** one is needed by an `isnotset` check, one by an `xbits` check.
- **8 setters were enabled by both.** Corelight-update added `noalert` to them; in Fleet Manager they alert.

**What to expect:** with flowbit dependencies on, Fleet Manager runs more rules than Corelight-update, including obsolete ones, and some setters alert. A few `isnotset` and xbits dependencies are not resolved.

**What to do:**
- disable unwanted setters again in `disable.conf`;
- give setters that alert a `RuleOptions:` modify entry with `flowbits:noalert`;
- check the generated ruleset after each change.

Leaving flowbit dependencies off and listing needed setters in `enable.conf` gives the most predictable result.

## Testing the ruleset

Corelight-update tests the generated ruleset with Suricata, either the microsensor (retired in 2027) or open-source Suricata. Fleet Manager's validation (`POST /suricata/validate/rules`, shown in the `fm_content_push` preview) only parses the rules. It reports rule counts, parse errors and duplicate SIDs. It can pass rules that still fail to load on the sensors, for example rules for a protocol the sensors' Suricata configuration disables. To test a ruleset before it reaches the sensors, run Suricata yourself: `suricata -T -c <suricata.yaml> -S <rules>`, with a configuration that matches the sensors'.

## Checking the result

After a migration, compare Fleet Manager's generated ruleset with Corelight-update's for the same policy. `fm_suricata_policy_get` shows the generated file (`fileInfo` → `suricata-file-id`). Compare by SID, and look at:
- rules enabled in one and not the other;
- rules whose options differ.

Ignore spacing differences: Corelight-update rewrites rules with `flowbits:set,X`, while Fleet Manager keeps the source's spacing.
