# fleet-mcp

An [MCP](https://modelcontextprotocol.io) server for installing, configuring and managing Corelight Fleet Manager.

> **Status:** early development. Not ready for use.

## Scope

- **Fleet Manager API:** the REST API (`/fleet/v1/*`) and the GraphQL API (`/graph/query`): sensors, groups, tags, policies, Suricata, content resources, YARA, connectors, sensor updates, backups, users, roles and settings.
- **Fleet Manager host:** install, upgrade, `corelight-fleetd.conf`, licenses, TLS certificates, service state and logs, over SSH.
- **Diagnostics:** read-only access to Fleet Manager's SQLite databases.

Out of scope: the Corelight Sensor API, and scheduled content fetching.

## Requirements

- Fleet Manager 29.2 or later.
- A local Fleet Manager user without 2FA for the server to log in as.

## API specifications

The Fleet Manager API specifications are not included in this repository. Run `make spec` to download them from a Fleet Manager you have access to. The REST spec requires `"expose-swagger": true` in `/etc/corelight-fleetd.conf`, which is not set in a default production install.
