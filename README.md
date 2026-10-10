# fleet-mcp

An [MCP](https://modelcontextprotocol.io) server for installing, configuring and managing Corelight Fleet Manager.

> **Status:** early development. The server is **read-only unless writes are enabled**. Installation is tested on Ubuntu 22.04 with Fleet Manager 29.2.2; the API write tools are tested only against a fake Fleet Manager so far.

## Scope

- **Install and set up Fleet Manager** on an Ubuntu host over SSH, following Corelight's installation guide.
- **Fleet Manager API:** the REST API (`/fleet/v1/*`) and the GraphQL API (`/graph/query`): sensors, groups, tags, policies, Suricata, content resources, YARA, connectors, sensor updates, backups, users, roles and settings.
- **Planned:** upgrades, `corelight-fleetd.conf` changes, licenses and TLS certificates on an existing host; read-only diagnostics of Fleet Manager's databases.

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
existing Fleet Manager yet. Add "ask" permission rules for fm_host_install,
fm_api_write, fm_graphql_mutate, fm_policy_import and fm_policy_copy so I
approve every change.
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
      "mcp__fleet-mcp__fm_api_write",
      "mcp__fleet-mcp__fm_graphql_mutate",
      "mcp__fleet-mcp__fm_policy_import",
      "mcp__fleet-mcp__fm_policy_copy"
    ]
  }
}
```

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

## Copy a sensor policy to another Fleet Manager

Fleet Manager has no export feature, so fleet-mcp provides one. `fm_policy_copy` copies a sensor policy and everything it uses from one Fleet Manager to another; `fm_policy_export` and `fm_policy_import` do the two halves separately, through a package directory in `~/.local/share/fleet-mcp/packages`.

**Copied:** the policy settings and enabled Zeek packages, the package bundle, the linked Suricata policy (rule sources, settings, HOME_NET, custom suricata.yaml, threshold, classification and reference files, modifier files, and the per-rule modifiers made in the UI), the YARA ruleset and its rule files, and the input, intel, resource and CA bundle collections with their uploaded files. Every new object is created alongside what the target already has; nothing existing is changed. A file source that already exists on the target with identical content is reused.

**Exporter tokens** (and other write-only settings) are never returned by Fleet Manager's API, so the preview asks how to supply them:

- **database**: fleet-mcp reads them from the source Fleet Manager's database over SSH, read-only (`sqlite3` on `/var/lib/corelight-fleetd/sensor-catalog`, which keeps policy settings unencrypted). Needs SSH with passwordless sudo to the source host.
- **prompt**: you run `fleet-mcp policy tokens <package>` in a terminal and type each token at a hidden prompt.

Either way the values go into `secrets.json` in the package directory (readable only by you, not part of the manifest), are sent to the target with the new policy's settings, and are never shown in tool output or the audit log. The file is deleted once the import has used every secret; it is kept while exporters wait for a completion.

**Not copied:** licensed rule-feed URLs (ET Pro) and connector credentials. Sources fed by a connector (CrowdStrike, Corelight, SentinelOne, ...) are listed too, or with `snapshot_connector_sources` copied as a static file. Sensor groups are not copied, and generated files (the compiled Suricata rule set and YARA ruleset) are rebuilt by the target. The preview lists everything you need to finish by hand.

**Checks before anything is created:**

- Fleet Manager versions must match on major.minor (29.2.x to 29.2.y is fine).
- The target must know every setting (checked with its own validation endpoint). Suricata settings it does not know are listed and left out.
- Exporters need a sensor attached to the target: Fleet Manager offers no exporter types before that. The preview then asks whether to continue with everything else. If you continue, the import is recorded in the package, and once a sensor is attached, importing the same package again with `complete: true` adds the exporters to the policy that was created. `fm_policy_packages` shows imports still waiting for that.
- Sensors play no part in an import: a policy can be imported, and assigned to a group, before any sensor exists. For information, the preview shows how many target sensors hold the licenses for the features the policy enables (Suricata, YARA, SmartPCAP, asset classification).
- No created object may clash with an existing name (use `name_suffix`).

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

## Move a sensor to another Fleet Manager

Fleet Manager cannot point a sensor at another Fleet Manager (its sensor proxy does not offer `fleet.server`), so `fm_sensor_move` logs in to the sensor over SSH as `diag-shell` and runs `corelight-client configuration update` in three steps, about 30 seconds apart:

1. `--fleet.enable=false`: disconnect from the current Fleet Manager, so it cannot put its `fleet.server_sslname` back.
2. `--fleet.community_string=<target's> --fleet.server=<target host>:1443 --fleet.server_sslname=''`: `server_sslname` comes from each Fleet Manager's license, which may differ, so it is cleared; the new Fleet Manager sets its own when the sensor connects.
3. `--fleet.enable=true`: connect to the new Fleet Manager.

- The sensor address comes from the source Fleet Manager; the target's community string from the secret store (stored by fleet-mcp's install, or `fleet-mcp secret set community-string -host <fleet>`).
- Login as `diag-shell`: with fleet-mcp's own SSH key when it is installed on the sensor (`fm_sensor_ssh_key` sets it as the sensor's individual setting `security.user.admin.ssh_public_key` through its Fleet Manager; the sensor holds one admin key, so an existing different key is only replaced on request), otherwise with the `admin` password, stored once with `fleet-mcp secret set sensor-admin-password`.
- On first contact the preview shows the sensor's SSH host key fingerprint; it is pinned when you confirm, and a changed key is refused.
- The sensor keeps its configuration: it appears on the target in UNASSIGNED and changes only when you put it in a sensor group with a policy. Its entry on the source goes offline.

```text
Move Lab-Sensor6 from prod to lab.
```

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
| `FLEET_MCP_SECRETS_DIR` | `~/.local/share/fleet-mcp/secrets` | Secret store. |
| `FLEET_MCP_SSH_USER` | | Default SSH user for host tools. |
| `FLEET_MCP_SSH` | `ssh` | SSH client to run. |
| `FLEET_MCP_SPEC_DIR` | `~/.local/share/fleet-mcp/spec` | Where API schemas are read from and cached. |
| `FLEET_MCP_MAX_RESPONSE_BYTES` | `60000` | Default cap on a tool result. |
| `FLEET_MCP_TIMEOUT` | `60s` | Per-request timeout. |
| `FLEET_MCP_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. Logs go to stderr. |

## Tools

Host and secret tools (always available):

| Tool | Description |
|---|---|
| `fm_install_checklist` | Everything you provide or decide before an install, with status |
| `fm_host_check` | Read-only readiness check of a host |
| `fm_secrets_status` | Which secrets are stored (never values) and how to add missing ones |
| `fm_secret_import_file` | Import the identity certificate or a Software Sensor license from a file |
| `fm_host_install` | Install and set up Fleet Manager (writes enabled; preview, then confirm) |

Fleet Manager API tools (each takes an optional `fleet` argument):

| Tool | Description |
|---|---|
| `fm_fleets` | The Fleet Managers this server can manage; with `check`, reachability and versions |
| `fm_info` | Fleet Manager version and features, the logged-in user, schema availability |
| `fm_sensors_list` | One summary row per sensor: health, connection, version, group, policy, config-apply state |
| `fm_sensor_get` | Full detail for one sensor (by uid or name) |
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
| `fm_policy_import` | Import a package as a new sensor policy (writes enabled; preview, then confirm) |
| `fm_policy_copy` | Export from one Fleet Manager and import into another (writes enabled; preview, then confirm) |
| `fm_sensor_move` | Move a sensor to another Fleet Manager over SSH as diag-shell (writes enabled; preview, then confirm) |
| `fm_sensor_ssh_key` | Install fleet-mcp's SSH key on a sensor (its individual setting `security.user.admin.ssh_public_key`) so moves need no password (writes enabled; preview, then confirm) |

### Changes need two calls

A tool that changes something (`fm_host_install`, `fm_api_write`, `fm_graphql_mutate`, `fm_policy_import`, `fm_policy_copy`) changes nothing when called without `confirm_token`. It returns a **preview**: the install plan, the import plan, or the request, the matching spec operation, impact warnings and, for PUT/PATCH, a field-by-field diff against the current object. The preview includes a `confirm_token`, a hash of that exact request; calling again with the identical request and the token executes it, and any other request is refused. The agent is expected to show you the preview and get your approval in between.

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
fleet-mcp secret set repo-token             # hidden prompt
fleet-mcp secret import identity-cert.pem <path>
fleet-mcp secret show community-string -host <host> [-copy]
fleet-mcp policy tokens <package>           # enter the exporter tokens a policy package needs (hidden prompt)
fleet-mcp fleets [-check]                   # the Fleet Managers this server can manage
fleet-mcp get [-fleet n] /fleet/v1/info     # GET a REST path, print redacted JSON
fleet-mcp gql [-fleet n] '{ yaraRulesets { count } }'  # read-only GraphQL query
fleet-mcp spec [-fleet n] -out spec         # download the API specs
fleet-mcp version
```

## Development

```sh
make test   # unit tests against a fake Fleet Manager and fake hosts
make lint   # go vet + staticcheck
make vuln   # govulncheck
```
