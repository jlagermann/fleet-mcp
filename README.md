# fleet-mcp

An [MCP](https://modelcontextprotocol.io) server for installing, configuring and managing Corelight Fleet Manager.

> **Status:** early development. The server is **read-only unless writes are enabled**. Tested with Fleet Manager 29.2.2: installs on Ubuntu, policy copies between Fleet Managers, and sensor moves.

## Tools, skills and instructions

AI agents use several kinds of help. fleet-mcp provides tools, server instructions, and workflow guides that work like skills but ship with the server.

| | What it is | Who runs it | In fleet-mcp |
|---|---|---|---|
| **Tool** | A function the agent calls with typed arguments; code does the work (API calls, SSH) and returns a result. Tools give the agent abilities it would not have otherwise. | fleet-mcp's code | **50 tools** |
| **Server instructions** | Short guidance an MCP server sends when the agent connects. Clients truncate long instructions (Claude Code at 4,096 bytes), so fleet-mcp's hold only the rules for every call: approval after a preview, no secrets in the chat, naming the Fleet Manager, and which guide to load for which task. | the agent, by reading it | built in, about 2.4 KB |
| **Guides** (skill-like) | Step-by-step playbooks for multi-step tasks, such as the policy-creation interview or a policy migration. They add no abilities; they guide how the agent uses the tools. The agent loads one with `fm_guide` when a task matches, and you can start one yourself as an **MCP prompt** (in Claude Code: `/fleet-mcp:<guide>`, e.g. `/fleet-mcp:troubleshoot-sensor`). | the agent, by reading it | **14 guides**, each also a prompt |
| **Skill** | A packaged set of instructions (a `SKILL.md`) installed in the agent itself. | the agent, by reading it | none needed; you can write your own on top of these tools |

The guides: `install-fleet-manager`, `create-sensor-policy`, `change-sensor-policy`, `delete-sensor-policy`, `copy-sensor-policy`, `troubleshoot-sensor`, `push-content`, `manage-collections`, `tune-suricata`, `build-package-bundle`, `move-sensor`, `maintain-fleet-manager`, `upgrade-software-sensor`, `manage-users`. Each prompt takes an optional `request` argument, your task in your own words.

The 50 tools:

| Group | Count | Tools |
|---|---|---|
| Guides (always available) | 1 | `fm_guide` |
| Install, host health and secrets (always available) | 5 | `fm_install_checklist`, `fm_host_check`, `fm_host_diagnose`, `fm_secrets_status`, `fm_secret_import_file` |
| Fleet Manager reads | 20 | `fm_fleets`, `fm_fleet_health`, `fm_users_list`, `fm_policy_diff`, `fm_info`, `fm_sensors_list`, `fm_sensor_get`, `fm_sensor_diagnose`, `fm_groups_list`, `fm_policies_list`, `fm_policy_get`, `fm_suricata_policies_list`, `fm_suricata_policy_get`, `fm_sensor_updates_status`, `fm_notifications`, `fm_backups`, `fm_api_get`, `fm_graphql_query`, `fm_api_describe`, `fm_policy_profiles` |
| Policy packages (local files; Fleet Manager unchanged) | 2 | `fm_policy_export`, `fm_policy_packages` |
| Sensor diagnostics (read-only, over SSH as diag-shell) | 1 | `fm_sensor_shell` |
| Suricata ruleset test (read-only, over SSH on a host you name) | 1 | `fm_suricata_test` |
| Changes (only with writes enabled; preview, then confirm) | 20 | `fm_host_install`, `fm_host_configure`, `fm_host_upgrade`, `fm_api_write`, `fm_graphql_mutate`, `fm_policy_import`, `fm_policy_copy`, `fm_sensor_fleet`, `fm_sensor_ssh_key`, `fm_policy_create`, `fm_sensor_action`, `fm_sensor_support_access`, `fm_softsensor_upgrade`, `fm_content_push`, `fm_suricata_modify`, `fm_policy_update`, `fm_policy_delete`, `fm_group_manage`, `fm_collection_manage`, `fm_user_manage` |

Each tool is described in [Tools](#tools); the command-line companion is in [Command line](#command-line).

## Scope

- **Install and set up Fleet Manager** on an Ubuntu host over SSH, following Corelight's installation guide.
- **Fleet Manager API:** the REST API (`/fleet/v1/*`) and the GraphQL API (`/graph/query`): sensors, groups, tags, policies, Suricata, content resources, YARA, connectors, sensor updates, backups, users, roles and settings.
- **Content:** push intel, input, YARA, Suricata rules and configuration, and Zeek package bundles as they are (`fm_content_push`).
- **Fleet Manager host health and maintenance:** a read-only check of a running host (`fm_host_diagnose`); `corelight-fleetd.conf` settings, identity and web certificates, the Software Sensor license and the community string (`fm_host_configure`); upgrades with a backup first (`fm_host_upgrade`).
- **Fleet-wide views:** health of every Fleet Manager at once (`fm_fleet_health`) and policy drift between policies or Fleet Managers (`fm_policy_diff`).
- **Planned:** read-only diagnostics of Fleet Manager's databases.

Out of scope: the Corelight Sensor API, and scheduled content fetching.

## Requirements

- Fleet Manager 29.2 or later (to manage one), or an Ubuntu 22.04/24.04 x86_64 host (to install one).
- For the API tools, a **local** Fleet Manager user **without 2FA** for the server to log in as. An install creates one for you.
- For installs: SSH from the machine running fleet-mcp to the host with key authentication and passwordless sudo, plus your own Corelight package repository token and Fleet Manager product identity certificate.

## Build

With Go 1.25 or later:

```sh
make build            # bin/fleet-mcp
make build-windows    # bin/fleet-mcp.exe
```

## Register it with your agent

### Sample prompt

Paste a prompt like this into Claude Code (or another MCP client that can edit its own configuration), with your paths and names filled in:

```text
Register the fleet-mcp MCP server for me at user scope. The binary is at
/home/me/bin/fleet-mcp (run it as "fleet-mcp stdio"). Enable writes, use "ubuntu"
as the default SSH user for Fleet Manager hosts, and don't connect it to an
existing Fleet Manager yet. Add "ask" permission rules for every fleet-mcp tool that
changes something (the tools listed under "Changes need two calls" in the
README) so I approve every change.
```

To connect it to an existing Fleet Manager instead:

```text
Register the fleet-mcp MCP server at user scope from /home/me/bin/fleet-mcp, connected
to https://fleet.example.com as the local user "claude", with the password in
~/.local/share/fleet-mcp/fm-password.txt. Keep it read-only for now.
```

Restart your agent afterwards so it loads the server.

`stdio` means the agent starts fleet-mcp as a local process and talks to it over standard input and output: the server opens no network port and serves only that agent. (`serve` is an older name for the same thing; running the binary with no subcommand does the same.)

### By hand (Claude Code)

```sh
# Install mode: host and secret tools, no Fleet Manager yet
claude mcp add fleet-mcp --scope user \
  -e FLEET_MCP_ENABLE_WRITES=true \
  -e FLEET_MCP_SSH_USER=ubuntu \
  -- /path/to/fleet-mcp stdio

# Connected to an existing Fleet Manager
claude mcp add fleet-mcp --scope user \
  -e FLEET_MCP_URL=https://fleet.example.com \
  -e FLEET_MCP_USERNAME=claude \
  -- /path/to/fleet-mcp stdio
```

Permission rules for approving each change, in `~/.claude/settings.json`:

```json
{
  "permissions": {
    "ask": [
      "mcp__fleet-mcp__fm_host_install",
      "mcp__fleet-mcp__fm_host_configure",
      "mcp__fleet-mcp__fm_host_upgrade",
      "mcp__fleet-mcp__fm_api_write",
      "mcp__fleet-mcp__fm_graphql_mutate",
      "mcp__fleet-mcp__fm_policy_create",
      "mcp__fleet-mcp__fm_policy_update",
      "mcp__fleet-mcp__fm_policy_delete",
      "mcp__fleet-mcp__fm_policy_import",
      "mcp__fleet-mcp__fm_policy_copy",
      "mcp__fleet-mcp__fm_group_manage",
      "mcp__fleet-mcp__fm_collection_manage",
      "mcp__fleet-mcp__fm_content_push",
      "mcp__fleet-mcp__fm_suricata_modify",
      "mcp__fleet-mcp__fm_sensor_fleet",
      "mcp__fleet-mcp__fm_sensor_ssh_key",
      "mcp__fleet-mcp__fm_sensor_action",
      "mcp__fleet-mcp__fm_sensor_support_access",
      "mcp__fleet-mcp__fm_softsensor_upgrade",
      "mcp__fleet-mcp__fm_user_manage"
    ]
  }
}
```

These rules are optional. Every change already needs two calls: the first returns a preview, and the agent is told to get your approval before sending the second with its `confirm_token`. The rules add a second confirmation in Claude Code's own dialog. If you would rather approve once, after the preview, ask your agent to remove them (for example: "Remove the fleet-mcp ask rules so the approval after the preview is the only confirmation"), or delete them from `settings.json` yourself.

## Install and set up Fleet Manager

### Sample prompts

Start by asking what you need:

```text
I want to install Fleet Manager on fm01.example.com. What do I need to provide?
```

The agent shows the install checklist (`fm_install_checklist`), with each item's status: host access and resources, your Corelight repository token and product identity certificate, and your choices. Then work through it:

```text
Check whether fm01.example.com is ready for Fleet Manager. SSH as ubuntu.
```

```text
I've set my repo token. Import my Fleet Manager certificate from
~/Downloads/acme-fleet.pem.
```

```text
Install Fleet Manager on fm01.example.com, the latest version, with the agent
user named claude. Show me the plan first.
```

The agent shows the plan step by step, and runs it only after you approve. When it finishes, it gives you the **admin user's temporary password**; log in and Fleet Manager makes you choose your own.

Other useful prompts:

```text
Install Fleet Manager 29.2.2 on 10.0.0.15 and leave expose-swagger off.
```

```text
The install on fm01 stopped at the package step. Find out why and try again.
```

```text
Connect fleet-mcp to the Fleet Manager you just installed on fm01 and show me its status.
```

### What you provide

| Item | How |
|---|---|
| Corelight package repository token (Customer Portal → Downloads → Fleet Manager) | In a terminal: `fleet-mcp secret set repo-token` (hidden prompt). Never paste tokens into a chat. |
| Fleet Manager product identity certificate (`.pem` from Corelight, with its key; carries the license) | Ask the agent to import it from a file path (`fm_secret_import_file`), or `fleet-mcp secret import identity-cert.pem <path>` |
| Optional: your own sensor community string | `fleet-mcp secret set community-string -host <host>` before installing; otherwise one is generated |
| A host meeting the requirements | Any failure or resource shortfall stops the install; see the checklist |

Secrets are stored in `~/.local/share/fleet-mcp/secrets`, readable only by your user. Tools report whether each one is present, never its value.

### What the install does

Each step checks first and is skipped when already done, so an install that stopped can simply be run again. After applying a step, the installer checks it again and fails the step unless it is really done.

1. **readiness**: supported OS, CPUs, memory, disk (`/var`, `/tmp`), ports 443/1443, repository access. Failures and resource warnings stop the install.
2. **prerequisites**: `curl`, `gnupg`, `apt-transport-https`.
3. **repo_key / repo_source / repo_auth**: the Corelight repository key, source and your token. The token never appears on a command line.
4. **package**: `corelight-fleet`, the newest or a pinned version.
5. **identity_cert**: `/etc/corelight-fleetd.pem`, owned by `corelight-fleetd`, mode 0400.
6. **config**: `/etc/corelight-fleetd.conf` with the community string and `expose-swagger` (default on; without it Fleet Manager serves no REST API spec). The previous file is backed up.
7. **service**: enable, restart, and wait for the web API.
8. **agent_user**: the local admin user the agent logs in as (default `claude`). Its password is generated and kept only by fleet-mcp.
9. **admin**: your `admin` user, with a temporary password returned to you. Fleet Manager requires changing it at first login. An existing admin is never changed.

The install writes a profile for the new Fleet Manager (its URL, the agent user, the password file and the pinned certificate), and it becomes available to the API tools straight away under the host name you installed it on.

To read the community string later, for pairing sensors: `fleet-mcp secret show community-string -host <host>` (prints only in your terminal; `-copy` puts it on the clipboard).

## Maintain a Fleet Manager host

`fm_host_diagnose` checks a running host read-only. Two tools change it, each previewed first and refused for hosts of Fleet Managers marked `read_only`:

- **`fm_host_configure`** changes `corelight-fleetd.conf` settings by path (`{"log-level": "DEBUG"}`, `{"messaging/http-options/bind-address": ":1443"}`; null removes one), and installs files from the secret store: a renewed product identity certificate (`identity_cert`), a web interface certificate (`tls_cert`, from `tls-cert.pem` imported for that host), the Software Sensor license (`license`), or a new community string (`community_string`). Secrets in settings are refused. Settings that name a file are checked on the host first. Each replaced file is backed up root-only, `corelight-fleetd` is restarted and its API awaited. If it does not come up, the backups are restored, the service is restarted and Fleet Manager's own error is reported. A web certificate is installed as its own file, and sensor connections (port 1443) are pinned to the identity certificate. When the web certificate changes, the pinned certificate in the fleet-mcp profile is updated.
- **`fm_host_upgrade`** lists the installed and available versions, checks free space and the repository, makes a Fleet Manager backup first (Fleet Manager keeps one backup, so this replaces the previous image), installs the version keeping `corelight-fleetd.conf`, restarts, and checks the version. A downgrade needs `allow_downgrade`. Sensor software is not changed.

Sample prompts:

```text
Check the Fleet Manager host for fm-east and renew its identity certificate from C:\certs\fm-2027.pem.
Upgrade fm-west to the newest Fleet Manager version.
Turn on debug logging on the fm-east Fleet Manager for an hour.
```

## Several Fleet Managers

One fleet-mcp server can manage any number of Fleet Managers. Every API tool takes an optional `fleet` argument naming the one to use; `fm_fleets` lists them (with `check`, it logs in to each and shows its version). Fleet Managers come from:

1. **Installs by fleet-mcp**: picked up automatically, named after the host.
2. **`fleets.json`** (`~/.local/share/fleet-mcp/fleets.json`): for Fleet Managers fleet-mcp did not install.
3. **`FLEET_MCP_URL`** (named after its host) or **`FLEET_MCP_PROFILE`**, for single-FM setups.

```json
[
  {
    "name": "prod",
    "url": "https://fleet.example.com",
    "username": "claude",
    "password_file": "~/.local/share/fleet-mcp/prod-password.txt",
    "ca_file": "~/certs/corp-ca.pem",
    "read_only": true
  },
  {
    "name": "lab",
    "url": "https://fleet-lab.example.com",
    "username": "claude",
    "password_file": "~/.local/share/fleet-mcp/lab-password.txt",
    "cert_sha256": "3f2a9c11…",
    "default": true
  }
]
```

- `read_only: true` makes every write tool refuse that Fleet Manager; reads still work.
- The **default** Fleet Manager (used when a call names none) is the one marked `"default": true`, else `FLEET_MCP_DEFAULT_FLEET`, else the environment entry, else the only one. With several and no default, tools ask which one to use.
- Each Fleet Manager has its own login session and API schema cache. Confirm tokens include the Fleet Manager, so a change previewed on one can't be executed on another, and the audit log records the Fleet Manager of every change.

Sample prompts:

```text
Which Fleet Managers can you reach, and what version is each running?
```

```text
Compare the sensor policies on prod and lab.
```

## Create a sensor policy from scratch

`fm_policy_create` builds a new sensor policy from a deployment profile and your answers, instead of Fleet Manager's policy wizard. The agent interviews you one topic at a time, previews the whole policy, and creates it after your approval.

**Profiles.** `north-south` (border or egress) and `east-west` (internal) start from the sensor docs' deployment recommendations, which cover the packages that existed when they were written. For packages added since, fleet-mcp makes its own call (for example, malware C2 detectors are north-south because their traffic crosses the border; LDAP and SSDP analyzers are east-west). `fm_policy_profiles` lists every package with both recommendations, the reason and its source. ICS/OT protocol analyzers and environment-specific packages (shunting, Geneve, Netskope, log filters) are never enabled by a profile, only on request. The interview asks whether the sensors see ICS/OT traffic and offers all ICS/OT analyzers in bulk (`ics_ot`) or a selection. You can add or remove any package, now or at any time later.

**What the interview covers:**

- Name and description; the profile; packages to add or remove; a custom package bundle and which of its packages to enable.
- Remote access: SSH and HTTPS are **on by default** and shown in the preview; allowed networks optional.
- Machine learning and anomaly detection: **on by default** and shown in the preview. They need at least 32 GB RAM and 8 CPUs on virtual and software sensors; a sensor below that gets an automatic exception. Anomaly detection trains for 31 days before it alerts.
- Network: keep or replace the local network blocks, traffic exclusion filter, NTP servers, diagnostic syslog, and a proxy if the sensors need one.
- The traffic exclusion filter is the sensor's limited BPF, not standard BPF. It names only what to exclude (the sensor applies `not (filter)`), so a capture filter that says what to keep has to be inverted. One-direction filters (`src host …`, `dst port …`) are refused, because dropping one side of a connection breaks Zeek's analysis of it; the preview suggests the same filter without `src`/`dst`, which excludes both directions. VLAN, ATM/MTP2/MTP3, arithmetic and packet-data expressions (`tcp[13]`, `len`) are refused too. `bro.site.restrictive_bpf` set to false lifts the one-direction rule per packet; it is set only on request, and Corelight recommends contacting Support first.
- Exports: batch export of Zeek log archives (SFTP or S3) and streaming exporters (any type the Fleet Manager offers; unset fields take their defaults, as in the web interface).
- Detection and enrichment: Suricata policy, YARA ruleset, input, intel and asset classification collections on the target.
- Connector-fed enrichments only work when the whole chain is there: a connector (authentication), a source per file that uses it, a collection of sources, the collection linked to the policy, and, for input files, a Zeek package in the same policy that reads the file. Without that package the file reaches the sensors and nothing uses it. The preview's `enrichments` section follows each linked collection to its sources (connector, fetch status) and the package that reads each input file. The reader comes, in order, from what you name in `input_readers`; from the target's connected sensors, whose `bro.inputs` lists every input file a loaded package is looking for and which package (`corelight:datared`, `customer:dns-bypass`), custom packages included; and only then from fleet-mcp's own matches, which are suggestions only (the docs' packages, `*-wl.txt` allowlists named after their package, host and CVE data for endpoint enrichment, the icann files for icannTLD): customers write their own packages, and a newer package version can stop using a file. So for any input file without an enabled reader the preview asks (`questions_for_user`) which package reads it, and the answer goes in `input_readers`, which accepts any package, custom ones included. It warns about a disabled or failing source, a named reader that is not enabled, a package fleet-mcp knows that lacks its files (icannTLD needs all four `*_level_public_icann.dat`; `trusted_domains.dat` is optional; endpoint enrichment needs host or CVE data), and more intel indicators than the sensor's limit. Intel files are read by the Zeek intel framework itself (ExtendIntel adds their metadata to the logs); asset classification also turns on `asset_classification.enable` (Early Access). Connectors are set up in the Fleet Manager web interface, with their credentials entered there, never in the chat.
- Performance monitoring ("Enable reporting through Zeek log streams", syslog or Graphite; separately the Network Performance Monitoring package, which detects network performance anomalies).
- Software updates. "Install software updates" is on by default: each sensor downloads its own updates from Corelight Cloud Services and applies them. Offline updates are loaded into Fleet Manager and delivered from there. Fully disabling automatic updates turns off Install software updates and all four update types (no impact, service restart, visible change, reboot); you can also apply only selected types.

Anything not asked about stays at the sensor default, and the preview lists those defaults. Other advanced settings are set only when you ask for them.

**Secrets** (proxy password, S3 secret key, exporter tokens) are never typed in the chat: you store each at a hidden prompt, for example `fleet-mcp secret set-setting "exporter:Splunk:hec_token"`. The preview says which are needed, with each command spelled out by the full path of the fleet-mcp binary (it is often not on your PATH; on Windows the command starts with `& "C:\...\fleet-mcp.exe"` for PowerShell); they are deleted from the store once the policy holds them.

The preview is validated by the target Fleet Manager itself before anything is created. If linking the Suricata policy, YARA ruleset, collections or bundle fails, the new policy is deleted again.

```text
Create a new north-south sensor policy called "Edge" on lab.
```

## Change, assign or delete a sensor policy

- **`fm_policy_update`** changes an existing sensor policy in one step:
  - settings (`null` resets a setting to its default) and secret settings from fleet-mcp's store;
  - Corelight packages and custom bundle packages, enabled or disabled by name;
  - the linked Suricata policy, YARA ruleset, collections and package bundle, or `none` to unlink.

  The preview shows every change from → to, the licensed features it turns on, Fleet Manager's validation (fleet-mcp also checks IP and CIDR lists, which Fleet Manager accepts unchecked), the enrichment chain of the linked collections, and the sensor groups that get the change. After applying, fleet-mcp reads the policy back and checks that nothing else changed.
- **`fm_group_manage`** creates, changes or deletes a sensor group and moves sensors in or out. The preview shows each sensor's group and policy before and after, and warns when the new policy turns on a feature a sensor has no active license for.
- **`fm_collection_manage`** creates, changes or deletes a collection of any kind (intel, input, asset classification, CA bundle) or a YARA ruleset, adds and removes existing sources without uploading them again (so a source Corelight-update created can be put in a collection), and links it to or unlinks it from sensor policies. A policy has one collection of each kind, so the preview warns when a link replaces one; a collection still in use is deleted only when the same call unlinks it, and its sources are kept.
- **`fm_policy_delete`** deletes a policy once no sensor group uses it. It lists everything the policy references and which other policies use each one, and on request also deletes the objects only this policy uses.

```text
On the lab Fleet Manager, add 198.51.100.0/24 to the Edge policy's local networks and enable the JA4 package.

Move Lab-Sensor3 into the border group.
```

## Copy a sensor policy to another Fleet Manager

Fleet Manager has no export feature, so fleet-mcp provides one. `fm_policy_copy` copies a sensor policy and everything it uses from one Fleet Manager to another; `fm_policy_export` and `fm_policy_import` do the two halves separately, through a package directory in `~/.local/share/fleet-mcp/packages`.

**Copied:** the policy settings and enabled Zeek packages, the package bundle, the linked Suricata policy (rule sources, settings, HOME_NET, custom suricata.yaml, threshold, classification and reference files, modifier files, and the per-rule modifiers made in the UI), the YARA ruleset and its rule files, and the input, intel, resource and CA bundle collections with their uploaded files. Every new object is created alongside what the target already has; nothing existing is changed. A file source that already exists on the target with identical content is reused.

**Exporter tokens** (and other write-only settings) are never returned by Fleet Manager's API, so the preview asks how to supply them:

- **database**: fleet-mcp reads them from the source Fleet Manager's database over SSH, read-only (`sqlite3` on `/var/lib/corelight-fleetd/sensor-catalog`, which keeps policy settings unencrypted). Needs SSH with passwordless sudo to the source host.
- **prompt**: you run `fleet-mcp policy tokens <package>` in a terminal and type each token at a hidden prompt.

Either way the values go into `secrets.json` in the package directory (readable only by you, not part of the manifest), are sent to the target with the new policy's settings, and are never shown in tool output or the audit log. The file is deleted once the import has used every secret; it is kept while exporters wait for a completion.

**Not copied:** licensed rule-feed URLs (ET Pro) and connector credentials. Sources fed by a connector (CrowdStrike, Corelight, SentinelOne, ...) are listed too, or with `snapshot_connector_sources` copied as a static file. Sensor groups are not copied, and generated files (the compiled Suricata rule set and YARA ruleset) are rebuilt by the target. The preview lists everything you need to finish by hand.

**Content maintained by Corelight-update** (a Suricata source named `Corelight-update`, input and intel sources described "Created by Corelight Update", YARA sources whose name starts with `Corelight-update`, bundles "managed by Corelight-update") is copied as it is now and flagged in the preview: on the target it stays static unless Corelight-update is also configured to push to the new policy.

**Checks before anything is created:**

- Fleet Manager versions must match on major.minor (29.2.x to 29.2.y is fine).
- The target must know every setting (checked with its own validation endpoint). Suricata settings it does not know are listed and left out.
- Exporters need a sensor attached to the target: Fleet Manager offers no exporter types before that. The preview then asks whether to continue with everything else. If you continue, the import is recorded in the package, and once a sensor is attached, importing the same package again with `complete: true` adds the exporters to the policy that was created. `fm_policy_packages` shows imports still waiting for that.
- Sensors play no part in an import: a policy can be imported, and assigned to a group, before any sensor exists. For information, the preview shows how many target sensors hold the licenses for the features the policy enables (Suricata, YARA, SmartPCAP, asset classification).
- Objects that already exist on the target under the same name are compared with the package (file checksums, Suricata settings, sources, modifier files and rule modifiers, collection and YARA sources, policy settings). An identical one is reused. A different one is shown with its differences and the preview asks what to do: keep and link the existing one (`use_existing`), or create the migrated one under a new name (`rename`, `rename:<name>`). For the sensor policy itself the choices are `rename` or `update_existing` (merge the migrated settings and links into the existing policy). Answers go in `resolve`, keyed by the question's ID.

If a step fails, everything created so far is deleted again. Uploaded files stay behind unreferenced.

Sample prompts:

```text
Copy the defaultPolicy sensor policy from prod to lab.
```

```text
lab has a sensor now. Finish the defaultPolicy migration from prod by adding the exporters.
```

```text
Export the defaultPolicy from prod, including snapshots of the connector-fed
intel, then show me what importing it into lab would do, without the exporters.
```

## Push content to Fleet Manager

`fm_content_push` pushes one local file to Fleet Manager **as it is**. It does not fetch feeds, merge files or rewrite rules: prepare the file with your own tooling. The one exception, on request, is converting Corelight-update syntax in Suricata tuning files (below). Rule tuning belongs in the Suricata policy's modifiers.

| Kind | What it changes |
|---|---|
| `intel` | An intel file source (by alias, default `fleet-mcp`), updated in place or created. Sensors get it as `bro_intel.dat`. |
| `input` | An input file source (by alias, default the file name). `name` is the file name on the sensors, which the Zeek package reading it looks for. |
| `yara` | A YARA source (by name, default `fleet-mcp`), checked by Fleet Manager's YARA validation first. |
| `suricata_rules` | With rules automation: a file rule source of the Suricata policy (by name, default `fleet-mcp`; the other sources are kept). Without: the policy's whole rule set. Fleet Manager parses the file first (it does not run Suricata). |
| `suricata_yaml`, `suricata_threshold`, `suricata_classification`, `suricata_reference` | That configuration file of the Suricata policy. A `suricata.yaml` snippet must start with `%YAML 1.1` and `---`. |
| `suricata_disable`, `suricata_enable`, `suricata_modify` | The `disable.conf`, `enable.conf` or `modify.conf` of a Suricata policy with Suricata automation, set to "Use configuration files" (the push switches it if needed). fleet-mcp checks the syntax first, because Fleet Manager rejects the whole file at upload for one bad line. Lines in Corelight-update syntax that Fleet Manager rejects or ignores (`MetadataAppend`, `Msg`/`GID`/`Rev`/`Classtype` changes, regex rewrites, `re:` without slashes, `Metadata:` matches, SID lists, `gid:sid`) are listed with what each would become, and you choose: convert them, comment them out, or stop (`cu_modifiers`). The result is written to `<name>.fm.conf` next to your file and pushed. Option changes become a per-rule `RuleOptions` line (frozen until converted again). A rewrite of one header field becomes `re:` lines that still catch new rules. The rule text comes from the policy; give `rules_file` for URL-source rules the current modify.conf already changes. After the push, fleet-mcp waits for Fleet Manager to rebuild the ruleset and reports errors. |
| `bundle` | A Zeek package bundle (from `zkg bundle`) as the sensor policy's bundle. The policy keeps its enabled packages. |

The preview shows:
- **A diff against what Fleet Manager has:** SIDs added, removed, changed, newly enabled or disabled; intel indicators or input records added and removed; YARA rules added and removed; bundle packages added, removed, or changed in version or git revision.
- **Fleet Manager's validation** (Suricata rule counts, parse errors and duplicate SIDs; YARA syntax). Fleet Manager only parses Suricata rules, it does not run Suricata, so test a ruleset with Suricata yourself before it reaches the sensors.
- **Who gets the change:** the sensor policies that use it.
- **Notes and warnings**, for example:
  - the target is managed by Corelight-update or Fleet-client, which overwrite it if they still run;
  - new bundle packages arrive disabled;
  - an enabled package is missing from the new bundle;
  - no connected sensor reads an input file.

A file Fleet Manager already has is reported as unchanged. For intel, input and YARA, `policy` also adds the source to that sensor policy's collection or YARA ruleset, creating and linking one named after the policy if it has none. After the push, fleet-mcp reads everything back. If a step fails, objects the push created are deleted again.

Moving Suricata tuning from Corelight-update? Fleet Manager's configuration files and flowbit dependencies differ from Corelight-update's in several ways: see [Moving Suricata tuning from Corelight-update to Fleet Manager](docs/corelight-update-migration.md).

Sample prompts:

```text
Push C:\feeds\intel.dat to the lab Fleet Manager as intel and link it to the Edge policy.

Push the Suricata rules in C:\rules\suricata.rules to the Lab Suricata policy as source "local-rules".

Replace the Edge policy's package bundle with C:\build\corelight.bundle.
```

## Tune and test Suricata rules

A Suricata policy with Suricata automation tunes its rules in one of two modes:
- the **Suricata rules manager** (Fleet Manager's recommended mode): use `fm_suricata_modify`;
- **configuration files**: push `disable.conf`, `enable.conf` and `modify.conf` with `fm_content_push`.

`fm_suricata_modify` previews:
- each rule's current effective state;
- the modifiers it adds, updates or removes (an enable replaces a disable on the same rule; a new value for the same field updates the existing modifier);
- Fleet Manager's validation.

After you approve, it waits for Fleet Manager to rebuild the ruleset and checks every changed rule.

Fleet Manager only parses rules; it does not run Suricata. `fm_suricata_test` loads a ruleset with a real Suricata on a host you name, over SSH, as the login user and in a temporary directory it removes. Use the sensors' Suricata version on that host.
- **What it tests:** a local file before a push, or the ruleset Fleet Manager generated for a policy after tuning.
- **Variables:** the policy's address and port groups, including those in its `suricata.yaml` snippet (for example `$SCANNERS`), are passed to Suricata.
- **Report:** rules loaded and failed, failed SIDs, failure reasons and undefined variables.

```text
Disable SIDs 2013028 and 2013504 in the Lab Suricata policy on the lab Fleet Manager, then test the policy's ruleset on my Suricata host.
```

## Build a Zeek package bundle

The `build-package-bundle` guide walks through building a bundle with `zkg bundle` (for example in the `zeek/zeek` Docker image matching the sensors' Zeek). It then pushes the bundle with `fm_content_push` and enables new packages in the sensor policy.

## Upgrade a Software Sensor

A Software Sensor cannot update itself: Fleet Manager's update settings and update trigger do not change it. `fm_softsensor_upgrade` upgrades one on its Ubuntu host over SSH (a user with passwordless sudo, as for Fleet Manager hosts; the host key must already be in your `known_hosts`). It follows the Corelight installation guide: `apt-get install corelightctl=<v> corelight-sensor=<v>` from the sensor-stable repository (the image packages follow), `corelightctl sensor prepare`, then `corelightctl sensor deploy -v`.

The preview reads the installed, running and available versions and picks the newest version that is **not newer than the sensor's Fleet Manager** (a Fleet Manager must be the same version as its sensors or newer). It checks free space against the download plus corelightctl's own deploy requirement (about 22 GB in 29.x), the repository, a retired `corelight_corelightctl.list`, the OS, firewalld and the permissions of `corelightctl.yaml`, which holds the community string and pairing token. If the packages are already installed but the sensor still runs the old version (for example after a reboot was needed), it offers the deploy only.

It also times synchronous writes on `/var/lib` and warns when they average 10 ms or more: etcd, the sensor's Kubernetes datastore, then falls behind and the deploy can miss corelightctl's fixed waits (exit 3, no rollback); on a VM, the warning also says to delete old snapshots, which slow writes further. If Kubernetes keeps running after such a failure, running the tool again once the host is idle deploys only, and usually passes. The upgrade runs on the host as the systemd unit `fleet-mcp-softsensor-upgrade`, so a dropped connection does not stop it; its output goes to `/var/log/fleet-mcp-softsensor-upgrade.log`. The confirmed call waits `wait_minutes` (default 20) and `status: true` follows it after that. Results name the failed stage and what corelightctl's deploy exit code means (6: the deploy rolled back to the previous one). Take a VM snapshot first and delete it afterwards.

## Manage Fleet Manager users

`fm_users_list` reads the users of every Fleet Manager in one call: role, admin, 2FA state (off, required but not enrolled, enrolled), pending password change, failed logins and per-group permissions, plus the roles, the login providers (LDAP, SAML, RADIUS, TACACS+) and findings such as admins without 2FA, everyone being admin, or test accounts. It marks the account fleet-mcp itself logs in with.

`fm_user_manage` changes one user, by **username**: the Fleet Manager API addresses users only by their id (a username in `/fleet/v1/users/{id}` gives 404 "User not found"), so the tool looks it up.

- **create** with a role, names and `require_2fa`. The initial password is stored at a hidden prompt (`fleet-mcp secret set-setting fm-user:<username>`), never typed in the chat, and deleted once the user exists; the new user must change it at first login.
- **update** the role, names or `require_2fa`. A role change (and a create) previews the permissions gained, lost and kept, by category with Fleet Manager's display names, from the roles' own permission lists, so custom roles are covered; sensitive ones (managing users, login providers, backups, secrets, sensors, policies) are called out. Fleet Manager's `PUT` may reset what it is not sent, and the user's settings hold the 2FA enrollment, so the tool sends back everything it read with only the change applied.
- **reset_2fa** for a user who lost their authenticator app: they enroll again at the next login, and Fleet Manager also asks for a new password.
- **delete**.

It refuses to delete or demote the last admin or fleet-mcp's own account, and to turn on 2FA for fleet-mcp's own account (an API login cannot answer a 2FA prompt). Each change is read back. The `manage-users` guide covers the workflow.

```text
Show me the users on all Fleet Managers and anything that needs attention.
```

## Detach, attach or move a sensor

Fleet Manager cannot point a sensor at another Fleet Manager (its sensor proxy does not offer `fleet.server`), and deleting a sensor from Fleet Manager does not stop it from connecting again. So `fm_sensor_fleet` works on the sensor itself: it logs in over SSH as `diag-shell` and runs `corelight-client configuration update`.

- **`detach`** runs `--fleet.enable=false`. The Fleet Manager keeps the sensor's record, group and policy and shows it offline; the sensor keeps running with its current configuration. Use it to borrow a sensor for a test without losing its place.
- **`attach`** connects the sensor to `target_fleet` (default: the Fleet Manager that lists it) in three steps, about 30 seconds apart:
  1. `--fleet.enable=false`: disconnect, so a connected Fleet Manager cannot put its `fleet.server_sslname` back.
  2. `--fleet.community_string=<target's> --fleet.server=<target host>:1443 --fleet.server_sslname=''`: `server_sslname` comes from each Fleet Manager's license, which may differ, so it is cleared; the Fleet Manager sets its own when the sensor connects.
  3. `--fleet.enable=true`: connect.

  Attaching to the same Fleet Manager reattaches a detached sensor to its group and policy, or gives it a new community string. Attaching to another Fleet Manager moves it: there it appears in UNASSIGNED and changes only when you put it in a sensor group with a policy, and its entry on the old Fleet Manager goes offline.

- The sensor address comes from the Fleet Manager that lists it; the target's community string from the secret store (stored by fleet-mcp's install, or `fleet-mcp secret set community-string -host <fleet>`).
- Login as `diag-shell`: with fleet-mcp's own SSH key when it is installed on the sensor (`fm_sensor_ssh_key` sets it as the sensor's individual setting `security.user.admin.ssh_public_key` through its Fleet Manager; the sensor holds one admin key, so an existing different key is only replaced on request), otherwise with the `admin` password, stored once with `fleet-mcp secret set sensor-admin-password`. A detached sensor cannot be asked through Fleet Manager whether it has the key, so the key is tried first and the password after it.
- On first contact the preview shows the sensor's SSH host key fingerprint; it is pinned when you confirm, and a changed key is refused.

```text
Detach Lab-Sensor6 from prod; I need it for a test.
Attach Lab-Sensor6 to prod again.
Move Lab-Sensor6 from prod to lab.
```

## Diagnose an unhealthy sensor

Two read-only tools, used in this order, and one that acts on the sensor:

1. **`fm_sensor_diagnose`** answers from Fleet Manager in one call (two API requests for the whole fleet). Without a sensor it covers every sensor that is not healthy or not connected. For each: the services that are not running and their messages, the version the sensor reports versus the NGS (container platform) version it actually runs, the last software update, config apply errors and failed fields, exceptions, ended licenses and failed metrics, and whether the same service fails on the other sensors of the policy. It ends with findings and next steps: a deploy that failed on a timeout points to slow storage (with the checks that confirm it and how to retry), a sensor newer than its Fleet Manager is flagged (Corelight recommends upgrading Fleet Manager first), a failed Base Services gets the reboot-then-custom-packages steps, and exceptions get a reminder that they may be left over from adding the sensor to a group with a policy.
2. **`fm_sensor_shell`** looks at the sensor itself, for what Fleet Manager cannot show. fleet-mcp logs in over SSH as `diag-shell` (its own key if installed, otherwise the `sensor-admin-password` secret) and runs one of a fixed set of checks with validated, quoted arguments; it never runs free-form commands and never changes the sensor. The first connection to a sensor shows its SSH host key fingerprint for you to approve; it is then pinned.

| Check | What it shows |
|---|---|
| `status` | `corelightctl sensor status`: OS and NGS versions, license, every service and exporter, errors |
| `version` | `corelightctl version`: the NGS version installed for the next deploy |
| `deploy` | The latest NGS deploy run (rerun at every boot and daily): when it started, whether it succeeded, failed or is still running, and its last steps; use it to follow a deploy after a reboot |
| `upgrade` | Every NGS deploy attempt from `/system-logs/corelightctl.log`: pre-flight checks, bootstrap, success or failure (repeated wait messages removed; `file` reads a rotated copy) |
| `service_logs`, `exporter_logs`, `pod_logs` | `corelightctl sensor logs` for a service (and container) or exporter; `kubectl logs` for a pod in `corelight-sensor` or, with `namespace: kube-system`, the Kubernetes system pods (rke2-canal, coredns, kube-controller-manager, kube-scheduler) |
| `system_logs`, `system_log` | The host logs in `/system-logs` (k3s, containerd, ansible, sensor API and others), and the end of one of them |
| `disk` | `df -h` |
| `datastore` | Kubernetes datastore latency (k3s "Slow SQL" warnings): tens of seconds means slow storage, which makes upgrade jobs time out |
| `node` | Whether the sensor host is starved, from `kubelet.log`: exec probe timeouts (10 s each) and the slowest and latest pod start-ups. Probe timeouts and start-ups of minutes mean slow storage (or CPU). `pattern` narrows it to a time, e.g. `Oct 12 14:5` |

`pattern` keeps only lines containing a text and `lines` sets how many (default 200, 60 for `deploy`, at most 2000).


3. **`fm_sensor_action`** (only with writes enabled) changes the sensor, one fixed action at a time, through `corelight-client` as `diag-shell`:

| Action | What it does |
|---|---|
| `reboot` | Reboots the sensor. At boot it reruns its NGS deploy, the first thing to try when an NGS upgrade failed on a job timeout (pre-flight or bootstrap) |
| `apply_updates` | Applies pending software updates now, whatever the policy's update settings say. Refused when none are pending |
| `revert_update` | Returns the sensor to its state before the last software update, then reboots it. Only when you ask for a revert |

The preview shows the sensor's update state (`updates updating`, `updates list`) and, for `reboot` and `revert_update`, a `--dry-run` of the command (`corelight-client` words a dry run like a real one; nothing happens). It refuses while an update is in progress. After one confirmation the action runs and is written to the audit log; follow the deploy with `fm_sensor_shell` check `deploy`. Factory reset, shutdown, flush-data and `corelightctl sensor stop` are never offered. Fleet Manager's own update trigger only pushes policy; it never upgrades software.
What `diag-shell` is: an unprivileged bash inside a firejail sandbox. It can read `/system-logs`, and through `sudo` run `corelightctl sensor status`, `version`, `sensor logs`, `images`, `datastore` and `certificates`, and `kubectl logs`. It cannot list pods or processes, or run `ps`, `top`, `free` or `awk`, and it has no root; root on a sensor needs a Corelight Support escalation. `sudo` also allows `corelightctl sensor stop`; no check uses it.


### Give Corelight Support remote access

`fm_sensor_support_access` turns the sensor's "Enable Corelight remote interface" (`remote.management`) on or off. Support also needs the sensor's **Device UID**, which the preview shows. The remote interface needs Corelight Cloud Services (`remote.enable`) on. Turn it on only when Support asks, and off when they are done.

Two routes:

- **fleet** sets a per-sensor exception through Fleet Manager (`PUT /fleet/v1/sensor/instance/{uid}/api/configuration`; turning it off removes the exception). Refused on read-only Fleet Managers.
- **sensor** runs `corelight-client configuration update --remote.management true|false` on the sensor as `diag-shell`. Use it when a change through Fleet Manager would not get through: a large policy change or several changes are queued for the sensor, the last configuration apply did not succeed, or the sensor is not connected. Fleet Manager may then show the setting as a difference, and a later policy apply can set it back.

`auto` (the default) picks **fleet** when nothing stands in its way and **sensor** otherwise, and the preview says why. In the worst cases neither works and the sensor has to be removed from Fleet Manager before the remote interface can be turned on; fleet-mcp leaves that to you.
## Configuration

Settings come from environment variables.

| Variable | Default | Description |
|---|---|---|
| `FLEET_MCP_URL` | | Fleet Manager URL or host name, e.g. `https://fleet.example.com`. HTTPS only. Optional: one more Fleet Manager, named after its host. |
| `FLEET_MCP_USERNAME` | | Local Fleet Manager user without 2FA (required with `FLEET_MCP_URL`). |
| `FLEET_MCP_PASSWORD_FILE` | `~/.local/share/fleet-mcp/fm-password.txt` | File containing only the password. Restrict it to your user. |
| `FLEET_MCP_PROFILE` | | Host name of a Fleet Manager installed by fleet-mcp to use as the default. Use instead of `FLEET_MCP_URL`. |
| `FLEET_MCP_FLEETS_FILE` | `~/.local/share/fleet-mcp/fleets.json` | Fleet Managers fleet-mcp did not install (see Several Fleet Managers). |
| `FLEET_MCP_DEFAULT_FLEET` | | Name of the default Fleet Manager. |
| `FLEET_MCP_CERT_SHA256` | | Pin the Fleet Manager certificate by its SHA-256 fingerprint instead of verifying a chain. |
| `FLEET_MCP_CA_FILE` | | PEM file of extra CA certificates, for a Fleet Manager with a private CA. |
| `FLEET_MCP_INSECURE_SKIP_VERIFY` | `false` | Skip TLS verification. Not recommended. |
| `FLEET_MCP_ENABLE_WRITES` | `false` | Register the tools that change Fleet Manager or install it. |
| `FLEET_MCP_AUDIT_LOG` | `~/.local/share/fleet-mcp/audit.jsonl` | JSON Lines record of every executed change (secrets redacted). |
| `FLEET_MCP_PACKAGES_DIR` | `~/.local/share/fleet-mcp/packages` | Exported policy packages. |
| `FLEET_MCP_DEMO_METRICS` | `false` | For demos: append to every tool result its time, a timeline of where the time went (SSH steps, waits for a sensor, uploads, Fleet Manager API calls) and the result's size in AI-context tokens. |
| `FLEET_MCP_SECRETS_DIR` | `~/.local/share/fleet-mcp/secrets` | Secret store. |
| `FLEET_MCP_SSH_USER` | | Default SSH user for host tools. |
| `FLEET_MCP_SSH` | `ssh` | SSH client to run. |
| `FLEET_MCP_SPEC_DIR` | `~/.local/share/fleet-mcp/spec` | Where API schemas are read from and cached. |
| `FLEET_MCP_MAX_RESPONSE_BYTES` | `60000` | Default cap on a tool result. |
| `FLEET_MCP_TIMEOUT` | `60s` | Per-request timeout. |
| `FLEET_MCP_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. Logs go to stderr. |

## Tools

Always available:

| Tool | Description |
|---|---|
| `fm_guide` | A step-by-step guide for a multi-step task (without `topic`, lists the guides); the same guides are MCP prompts |
| `fm_install_checklist` | Everything you provide or decide before an install, with status |
| `fm_host_check` | Read-only readiness check of a host |
| `fm_host_diagnose` | Read-only health check of a running Fleet Manager host: service, version and available upgrade, load, memory, disk and data path, journal errors (24 h), certificate expiry, ports 443/1443, NTP sync, world-readable files holding secrets, newest backup |
| `fm_secrets_status` | Which secrets are stored (never values) and how to add missing ones |
| `fm_secret_import_file` | Import the identity certificate, a Software Sensor license, or a host's web certificate (`tls-cert.pem`, with `host`) from a file |
| `fm_host_install` | Install and set up Fleet Manager (writes enabled; preview, then confirm) |
| `fm_host_configure` | Change an installed host: `corelight-fleetd.conf` settings, community string, identity or web certificate, license; backup, restart, automatic rollback (writes enabled; preview, then confirm) |
| `fm_host_upgrade` | Upgrade or downgrade Fleet Manager from the Corelight repository, with a backup first (writes enabled; preview, then confirm) |

Fleet Manager API tools (each takes an optional `fleet` argument):

| Tool | Description |
|---|---|
| `fm_fleets` | The Fleet Managers this server can manage; with `check`, reachability and versions |
| `fm_fleet_health` | One overview of every Fleet Manager: reachability, version, sensors by health, disconnected and unhealthy sensors, failed config applies and services, license warnings, software versions, open notifications, automatic backups, with what needs attention |
| `fm_policy_diff` | Compare two sensor policies on the same or different Fleet Managers: settings, bundle packages, linked objects by name, Suricata policies, YARA and collection sources by file hash |
| `fm_info` | Fleet Manager version and features, the logged-in user, schema availability |
| `fm_sensors_list` | One summary row per sensor: health, connection, version, group, policy, config-apply state |
| `fm_sensor_get` | Full detail for one sensor (by uid or name) |
| `fm_sensor_diagnose` | Why sensors are unhealthy, from Fleet Manager in one call: failed services and messages, reported vs deployed version, last update, config errors, exceptions, compared with the other sensors on the policy, with findings and next steps |
| `fm_sensor_shell` | Read-only checks on the sensor itself as diag-shell: status, version, latest deploy run, upgrade history, service, exporter and pod logs, host logs, disk, datastore latency, node starvation |
| `fm_groups_list` | Sensor groups, their policy and members |
| `fm_policies_list` / `fm_policy_get` | Sensor policies and their linked content |
| `fm_suricata_policies_list` / `fm_suricata_policy_get` | Suricata policies, sources, modifier files and settings |
| `fm_sensor_updates_status` | Sensor software update state |
| `fm_notifications` | Fleet Manager notifications |
| `fm_backups` | Backup image, status and schedule |
| `fm_api_get` | GET any REST endpoint |
| `fm_graphql_query` | Run a GraphQL query (mutations are rejected) |
| `fm_api_describe` | Search the REST spec and GraphQL schema |
| `fm_api_write` | POST, PUT, PATCH or DELETE a REST endpoint (writes enabled) |
| `fm_graphql_mutate` | Run a GraphQL mutation (writes enabled) |
| `fm_policy_export` | Export a sensor policy and everything it uses to a local package |
| `fm_policy_packages` | List exported packages |
| `fm_policy_profiles` | The north-south and east-west package recommendations `fm_policy_create` starts from |
| `fm_policy_create` | Create a sensor policy from scratch (writes enabled; preview, then confirm) |
| `fm_policy_update` | Change a sensor policy: settings (null resets), secret settings from the store, Corelight and bundle packages, linked Suricata policy, YARA ruleset, collections and bundle; diff, validation (plus IP and CIDR lists), licensed features, enrichment chain, read-back (writes enabled; preview, then confirm) |
| `fm_policy_delete` | Delete a sensor policy and, if you choose, the objects only it uses; blocked while a sensor group uses it (writes enabled; preview, then confirm) |
| `fm_group_manage` | Create, change or delete a sensor group: name, policy and member sensors, with each sensor's group and policy before and after and license warnings (writes enabled; preview, then confirm) |
| `fm_collection_manage` | Create, change or delete an intel, input, resource or CA bundle collection or a YARA ruleset: add or remove existing sources (also ones Corelight-update created), rename, link to or unlink from sensor policies; replaced links, duplicate file names, affected groups, input readers, read-back (writes enabled; preview, then confirm) |
| `fm_policy_import` | Import a package as a new sensor policy (writes enabled; preview, then confirm) |
| `fm_policy_copy` | Export from one Fleet Manager and import into another (writes enabled; preview, then confirm) |
| `fm_sensor_fleet` | Detach a sensor from Fleet Manager, attach it again, or move it to another one, over SSH as diag-shell (writes enabled; preview, then confirm) |
| `fm_sensor_action` | Reboot a sensor, apply its pending updates, or revert its last update, over SSH as diag-shell (writes enabled; preview, then confirm) |
| `fm_suricata_modify` | Tune single Suricata rules in Fleet Manager's rules manager: disable, enable or modify by SID or another match, remove modifiers; shows each rule before and after, waits for the rebuild and checks the rules (writes enabled; preview, then confirm) |
| `fm_suricata_test` | Load a ruleset with a real Suricata (`suricata -T`) over SSH on a host you name: a local file, or the ruleset Fleet Manager generated for a policy, with the policy's address and port groups |
| `fm_content_push` | Push an intel, input, YARA, Suricata rules or configuration file, or a package bundle, as it is: diff, Fleet Manager validation, optional policy linking, read-back (writes enabled; preview, then confirm) |
| `fm_softsensor_upgrade` | Upgrade a Software Sensor on its Ubuntu host: corelightctl and corelight-sensor packages, prepare, deploy, with version, Fleet Manager and free-space checks; `status: true` follows a running upgrade (writes enabled; preview, then confirm) |
| `fm_users_list` | Users of every Fleet Manager (or the ones named): roles, admin, 2FA state, pending password change, failed logins, fleet-mcp's own account; roles, login providers, and findings such as admins without 2FA |
| `fm_user_manage` | Create, update (role, name, require 2FA), reset the 2FA of, or delete a user, by username; keeps everything not changed, refuses to remove the last admin or fleet-mcp's own account (writes enabled; preview, then confirm) |
| `fm_sensor_support_access` | Turn "Enable Corelight remote interface" (`remote.management`) on or off for Corelight Support, through Fleet Manager or directly on the sensor; shows the Device UID (writes enabled; preview, then confirm) |
| `fm_sensor_ssh_key` | Install fleet-mcp's SSH key on a sensor (its individual setting `security.user.admin.ssh_public_key`) so moves need no password (writes enabled; preview, then confirm) |

### Changes need two calls

A tool that changes something (`fm_host_install`, `fm_host_configure`, `fm_host_upgrade`, `fm_api_write`, `fm_graphql_mutate`, `fm_policy_create`, `fm_policy_import`, `fm_policy_copy`, `fm_sensor_fleet`, `fm_sensor_ssh_key`, `fm_sensor_action`, `fm_sensor_support_access`, `fm_softsensor_upgrade`, `fm_content_push`, `fm_suricata_modify`, `fm_policy_update`, `fm_policy_delete`, `fm_group_manage`, `fm_collection_manage`, `fm_user_manage`) changes nothing when called without `confirm_token`. It returns a **preview**: the install plan, the import plan, or the request, the matching spec operation, impact warnings and, for PUT/PATCH, a field-by-field diff against the current object. The preview includes a `confirm_token`, a hash of that exact request; calling again with the identical request and the token executes it, and any other request is refused. A token works once, only within 30 minutes of its preview, and not after the server restarts, so every change follows a fresh preview; the hash also covers what the preview read where the tool reads state (a policy, a host, a sensor), so a change made in between makes the token stale. The agent is expected to show you the preview and get your approval in between.

Requests to the server's own session and credential endpoints (login, logout, OAuth2 tokens, `/fleet/v1/current/*`) are refused.

Results can be narrowed with `select` (a JSON Pointer; Fleet Manager keys often contain dots, as in `/information/health.status`), `fields`, `offset`/`limit` and `max_bytes`.

### Secrets in results

Values under keys that look like secrets (passwords, tokens, keys, credentials) and license codes embedded in feed URLs are replaced with `[REDACTED]` before results reach the agent. The one exception is the `admin` user's temporary password after an install, which Fleet Manager requires you to change at first login.

## API specifications

The Fleet Manager API specifications are not included in this repository. `fm_api_describe` uses them when available:

1. A saved file in `FLEET_MCP_SPEC_DIR` named `rest-<version>.json` / `graphql-<version>.json`.
2. Otherwise, a live download from Fleet Manager, which is then cached.

Fleet Manager serves the REST spec only when `"expose-swagger": true` is set in `/etc/corelight-fleetd.conf`; installs by fleet-mcp set it. The GraphQL schema is available either way. Every other tool works without the specs.

## Command line

```sh
fleet-mcp stdio                             # run the MCP server for a local agent (the default)
fleet-mcp host checklist <host>             # what to provide before an install, with status
fleet-mcp host check <host>                 # readiness check
fleet-mcp host install <host> [-execute]    # preview an install; -execute runs it
fleet-mcp secret list [host]                # stored secrets (never values)
fleet-mcp secret set-setting <name>         # hidden prompt: proxy password, S3 secret key or "exporter:<name>:<field>" for fm_policy_create
fleet-mcp secret set repo-token             # hidden prompt
fleet-mcp secret import identity-cert.pem <path>
fleet-mcp secret import tls-cert.pem <path> -host <host>
fleet-mcp secret show community-string -host <host> [-copy]
fleet-mcp policy tokens <package>           # enter the exporter tokens a policy package needs (hidden prompt)
fleet-mcp fleets [-check]                   # the Fleet Managers this server can manage
fleet-mcp get [-fleet n] /fleet/v1/info     # GET a REST path, print redacted JSON
fleet-mcp gql [-fleet n] '{ yaraRulesets { count } }'  # read-only GraphQL query
fleet-mcp spec [-fleet n] -out spec         # download the API specs
fleet-mcp version
```

## Demo metrics

To show what each tool costs in time and AI tokens:

- Set `FLEET_MCP_DEMO_METRICS=true` in the server's registration. Every tool result then ends with a footer: total time, a timeline (for example the 30-second pauses while a sensor applies a change during `fm_sensor_fleet` attach), Fleet Manager API calls and time, and the result's size in tokens of AI context.
- The model's own token use is known only to the client. `fleet-mcp report [-since <time>] [-timeline] <session.jsonl>` reads a Claude Code session transcript (`~/.claude/projects/<project>/<session>.jsonl`) and lists every fleet-mcp call with its wall time, the model's output and input tokens for the turn that made it, and the result size; `-timeline` adds the server's footers.

## Development

```sh
make test   # unit tests against a fake Fleet Manager and fake hosts
make lint   # go vet + staticcheck
make vuln   # govulncheck
```

## License

fleet-mcp is released under the [BSD 3-Clause License](LICENSE). It is a personal project, not a Corelight product, and Corelight Support does not support it.
