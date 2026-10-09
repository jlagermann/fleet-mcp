# fleet-mcp

An [MCP](https://modelcontextprotocol.io) server for installing, configuring and managing Corelight Fleet Manager.

> **Status:** early development. This build is **read-only**: it can inspect Fleet Manager but not change it.

## Scope

- **Fleet Manager API:** the REST API (`/fleet/v1/*`) and the GraphQL API (`/graph/query`): sensors, groups, tags, policies, Suricata, content resources, YARA, connectors, sensor updates, backups, users, roles and settings.
- **Fleet Manager host** (planned): install, upgrade, `corelight-fleetd.conf`, licenses, TLS certificates, service state and logs, over SSH.
- **Diagnostics** (planned): read-only access to Fleet Manager's SQLite databases.

Out of scope: the Corelight Sensor API, and scheduled content fetching.

## Requirements

- Fleet Manager 29.2 or later.
- A **local** Fleet Manager user **without 2FA** for the server to log in as. Give it the role it needs; read-only tools need only list/read permissions.

## Install

Build from source with Go 1.25 or later:

```sh
make build            # bin/fleet-mcp
make build-windows    # bin/fleet-mcp.exe
```

## Configuration

Settings come from environment variables.

| Variable | Default | Description |
|---|---|---|
| `FLEET_MCP_URL` | *(required)* | Fleet Manager URL or host name, e.g. `https://fleet.example.com`. HTTPS only. |
| `FLEET_MCP_USERNAME` | *(required)* | Local Fleet Manager user without 2FA. |
| `FLEET_MCP_PASSWORD_FILE` | `~/.local/share/fleet-mcp/fm-password.txt` | File containing only the password. Restrict it to your user. The password is read at each login and never logged. |
| `FLEET_MCP_CA_FILE` | | PEM file of extra CA certificates, for a Fleet Manager with a private CA. |
| `FLEET_MCP_INSECURE_SKIP_VERIFY` | `false` | Skip TLS verification. Not recommended. |
| `FLEET_MCP_SPEC_DIR` | `~/.local/share/fleet-mcp/spec` | Where API schemas are read from and cached. |
| `FLEET_MCP_MAX_RESPONSE_BYTES` | `60000` | Default cap on a tool result. |
| `FLEET_MCP_TIMEOUT` | `60s` | Per-request timeout. |
| `FLEET_MCP_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. Logs go to stderr. |

### Claude Code

```sh
claude mcp add fleet-mcp --scope user \
  -e FLEET_MCP_URL=https://fleet.example.com \
  -e FLEET_MCP_USERNAME=mcp-user \
  -- /path/to/fleet-mcp serve
```

## Tools

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

Results can be narrowed with `select` (a JSON Pointer; Fleet Manager keys often contain dots, as in `/information/health.status`), `fields`, `offset`/`limit` and `max_bytes`.

### Secrets

Values under keys that look like secrets (passwords, tokens, keys, credentials) and license codes embedded in feed URLs are replaced with `[REDACTED]` before results reach the MCP client.

## API specifications

The Fleet Manager API specifications are not included in this repository. `fm_api_describe` uses them when available:

1. A saved file in `FLEET_MCP_SPEC_DIR` named `rest-<version>.json` / `graphql-<version>.json`.
2. Otherwise, a live download from Fleet Manager, which is then cached.

The REST spec is served only when `"expose-swagger": true` is set in `/etc/corelight-fleetd.conf`, which is not the default. Every other tool works without the specs.

To save the specs from a Fleet Manager you have access to:

```sh
make spec      # or: fleet-mcp spec -out <dir>
```

## Command line

Besides `serve`, the binary has helpers for development:

```sh
fleet-mcp get /fleet/v1/info                # GET a REST path, print redacted JSON
fleet-mcp gql '{ yaraRulesets { count } }'  # run a read-only GraphQL query
fleet-mcp spec -out spec                    # download the API specs
fleet-mcp version
```

## Development

```sh
make test   # unit tests against a fake Fleet Manager
make lint   # go vet + staticcheck
make vuln   # govulncheck
```
