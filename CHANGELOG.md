# Changelog

All notable changes to fleet-mcp. Versions follow [Semantic Versioning](https://semver.org); until 1.0, a minor version may change tool arguments or results.

## 0.1.1 — 2026-11-04

Tested with Fleet Manager 29.2.6, whose REST and GraphQL APIs are identical to 29.2.2's.

- **Suricata tuning files:** after a converted modify.conf is pushed, fleet-mcp reads back every rule the file should change and reports any that Fleet Manager did not change as expected.
- **Suricata tuning files:** the preview warns about control characters in a line (for example a backspace left by a script that wrote `\b` through `printf`); they are invisible in most editors but change what a regex matches.
- **fm_sensor_fleet** refuses Software Sensors with an explanation; it moves appliance sensors only.
- **fm_host_diagnose** no longer reports a synchronized ntpsec clock as unsynchronized. It now uses the leap indicator and stratum, since ntpsec can report `sync_unspec` while in sync.
- **Policy updates** report changed links (Suricata policy, collections, YARA ruleset, bundle) in their summary.
- The `enable_packages` example names a package Fleet Manager 29.2 has.

## 0.1.0 — 2026-11-04

First public release (beta). Tested with Fleet Manager 29.2.2.

- **50 tools and 14 guides**, also offered as MCP prompts. The server is read-only unless writes are enabled. Every change previews first and runs only with a confirm token, which is single-use and valid for 30 minutes. Executed changes are written to an audit log.
- **Install and maintain Fleet Manager** on Ubuntu over SSH: readiness checks, install, configuration and certificates, upgrades with a backup first, and host diagnostics.
- **Several Fleet Managers** from one server, with read-only ones protected.
- **Sensor policies:** create from a profile, change, assign to groups, delete, compare, and copy between Fleet Managers (exporters, tokens, Suricata policies, collections, YARA and bundles included).
- **Content:** push intel, input, YARA, Suricata rules and configuration, tuning files and Zeek package bundles. Includes Suricata rule modifiers and a real `suricata -T` test. Corelight-update syntax in tuning files can be converted.
- **Collections and YARA rulesets:** create, change, link and unlink.
- **Sensors:** health and diagnostics, read-only checks over SSH, reboot and update actions, Corelight Support remote access, and moving a sensor between Fleet Managers.
- **Software Sensor upgrades** on Ubuntu.
- **Fleet Manager users:** list, create, change roles and 2FA, and delete.
- **Fleet-wide health** and policy drift views.
- Release binaries for Linux, Windows and macOS with SHA-256 checksums and build provenance attestations.
