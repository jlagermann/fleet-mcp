# Maintain a Fleet Manager host

1. Start with `fm_host_diagnose` (host, or fleet). It shows the version and the newest available one, certificate expiry, the newest backup, NTP, disk and secret files every local user can read. Fix what it finds with the user before other changes.
2. Hosts of Fleet Managers marked read_only are refused by `fm_host_configure` and `fm_host_upgrade`. Ask the user before changing any production Fleet Manager, and prefer a quiet time: every change restarts corelight-fleetd, so the web interface is down for up to two minutes and sensors reconnect on their own.

## Settings (`fm_host_configure` settings)

3. Give settings by their path in corelight-fleetd.conf, for example `{"log-level": "DEBUG"}` or `{"messaging/http-options/bind-address": ":1443"}`; null removes one. Secrets (the community string, TACACS+ shared secret) are refused here.
4. Changing `messaging/http-options/bind-address` changes the port sensors connect to: every sensor must be given the new address.

## Certificates and licenses

5. **Product identity certificate** (carries the Fleet Manager license; expires yearly). The user downloads the renewed .pem from Corelight and you import it with `fm_secret_import_file` (name identity-cert.pem). Then `fm_host_configure` with `identity_cert: true`. The preview warns if the new certificate's name differs from the installed one: sensors check that name.
6. **Web interface certificate**: the user puts the certificate, its chain and its unencrypted key in one .pem; import it with `fm_secret_import_file` (name tls-cert.pem, with host). Then `fm_host_configure` with `tls_cert: true`. It is installed as its own file and ssl-certificate-path and ssl-key-path point at it; sensors keep using the identity certificate on port 1443. For a Fleet Manager fleet-mcp installed, the pinned certificate is updated; for one in fleets.json, tell the user to update cert_sha256 or ca_file there.
7. **Software Sensor license**: import it with `fm_secret_import_file` (name sensor-license.txt), then `fm_host_configure` with `license: true`.
8. **Community string**: changing it disconnects every sensor until each is given the new one, so do it only when the user asks. The user stores the new value at a hidden prompt (`fleet-mcp secret set community-string -host <host>`, full path as tool results give it), then `fm_host_configure` with `community_string: true`, then `fm_sensor_fleet` with `action: attach` for each sensor on this same Fleet Manager.

If corelight-fleetd does not come up after a change, the backups are restored and it is restarted; report the error the result gives.

## Backups and upgrades

9. `fm_backups` shows the backup image and schedule. Recommend automatic backups when they are off.
10. `fm_host_upgrade` without a version previews the newest version in the repository; give a version (29.2.1) for another one. The preview checks free space and the repository token. By default it makes a Fleet Manager backup first: keep it, a failed upgrade cannot be undone without one.
11. Check the release notes for sensor compatibility before upgrading. Sensors keep their software version; Fleet Manager only pushes policy.
12. A downgrade needs `allow_downgrade`; Fleet Manager's database may not work with an older version, so restore the backup if it does not.
13. Afterwards run `fm_host_diagnose` and `fm_fleet_health`.
