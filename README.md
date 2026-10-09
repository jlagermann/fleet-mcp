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
/home/me/bin/fleet-mcp (run it as "fleet-mcp serve"). Enable writes, use "ubuntu"
as the default SSH user for Fleet Manager hosts, and don't connect it to an
existing Fleet Manager yet. Add "ask" permission rules for fm_host_install,
fm_api_write and fm_graphql_mutate so I approve every change.
```

To connect it to an existing Fleet Manager instead:

```text
Register the fleet-mcp MCP server at user scope from /home/me/bin/fleet-mcp, connected
to https://fleet.example.com as the local user "claude", with the password in
~/.local/share/fleet-mcp/fm-password.txt. Keep it read-only for now.
```

Restart your agent afterwards so it loads the server.

### By hand (Claude Code)

```sh
# Install mode: host and secret tools, no Fleet Manager yet
claude mcp add fleet-mcp --scope user \
  -e FLEET_MCP_ENABLE_WRITES=true \
  -e FLEET_MCP_SSH_USER=ubuntu \
  -- /path/to/fleet-mcp serve

# Connected to an existing Fleet Manager
claude mcp add fleet-mcp --scope user \
  -e FLEET_MCP_URL=https://fleet.example.com \
  -e FLEET_MCP_USERNAME=claude \
  -- /path/to/fleet-mcp serve
```

Permission rules for approving each change, in `~/.claude/settings.json`:

```json
{
  "permissions": {
    "ask": [
      "mcp__fleet-mcp__fm_host_install",
      "mcp__fleet-mcp__fm_api_write",
      "mcp__fleet-mcp__fm_graphql_mutate"
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

The install writes a profile for the new Fleet Manager. Start a server with `FLEET_MCP_PROFILE=<host>` to manage it: the profile holds its URL, the agent user, the password file and the pinned certificate.

To read the community string later, for pairing sensors: `fleet-mcp secret show community-string -host <host>` (prints only in your terminal; `-copy` puts it on the clipboard).

## Configuration

Settings come from environment variables.

| Variable | Default | Description |
|---|---|---|
| `FLEET_MCP_URL` | | Fleet Manager URL or host name, e.g. `https://fleet.example.com`. HTTPS only. Without it (or a profile), only the host and secret tools are available. |
| `FLEET_MCP_USERNAME` | | Local Fleet Manager user without 2FA (required with `FLEET_MCP_URL`). |
| `FLEET_MCP_PASSWORD_FILE` | `~/.local/share/fleet-mcp/fm-password.txt` | File containing only the password. Restrict it to your user. |
| `FLEET_MCP_PROFILE` | | Host name of a Fleet Manager installed by fleet-mcp; supplies URL, user, password file and pinned certificate. Use instead of `FLEET_MCP_URL`. |
| `FLEET_MCP_CERT_SHA256` | | Pin the Fleet Manager certificate by its SHA-256 fingerprint instead of verifying a chain. |
| `FLEET_MCP_CA_FILE` | | PEM file of extra CA certificates, for a Fleet Manager with a private CA. |
| `FLEET_MCP_INSECURE_SKIP_VERIFY` | `false` | Skip TLS verification. Not recommended. |
| `FLEET_MCP_ENABLE_WRITES` | `false` | Register the tools that change Fleet Manager or install it. |
| `FLEET_MCP_AUDIT_LOG` | `~/.local/share/fleet-mcp/audit.jsonl` | JSON Lines record of every executed change (secrets redacted). |
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

Fleet Manager API tools (with `FLEET_MCP_URL` or `FLEET_MCP_PROFILE`):

| Tool | Description |
|---|---|
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

### Changes need two calls

A tool that changes something (`fm_host_install`, `fm_api_write`, `fm_graphql_mutate`) changes nothing when called without `confirm_token`. It returns a **preview**: the install plan, or the request, the matching spec operation, impact warnings and, for PUT/PATCH, a field-by-field diff against the current object. The preview includes a `confirm_token`, a hash of that exact request; calling again with the identical request and the token executes it, and any other request is refused. The agent is expected to show you the preview and get your approval in between.

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
fleet-mcp host checklist <host>             # what to provide before an install, with status
fleet-mcp host check <host>                 # readiness check
fleet-mcp host install <host> [-execute]    # preview an install; -execute runs it
fleet-mcp secret list [host]                # stored secrets (never values)
fleet-mcp secret set repo-token             # hidden prompt
fleet-mcp secret import identity-cert.pem <path>
fleet-mcp secret show community-string -host <host> [-copy]
fleet-mcp get /fleet/v1/info                # GET a REST path, print redacted JSON
fleet-mcp gql '{ yaraRulesets { count } }'  # run a read-only GraphQL query
fleet-mcp spec -out spec                    # download the API specs
fleet-mcp version
```

## Development

```sh
make test   # unit tests against a fake Fleet Manager and fake hosts
make lint   # go vet + staticcheck
make vuln   # govulncheck
```
