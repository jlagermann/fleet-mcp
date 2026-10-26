# Detach, attach or move a sensor

`fm_sensor_fleet` changes which Fleet Manager a sensor uses, on the sensor itself:

- **detach**: turn Fleet Manager off on the sensor, e.g. to use it for a test. The Fleet Manager keeps its record, group and policy and shows it offline. Do not delete the sensor from Fleet Manager for this.
- **attach**: connect the sensor to `target_fleet` (default: the Fleet Manager that lists it). Attaching to that same Fleet Manager reattaches a detached sensor, or gives a sensor a new community string. Attaching to another Fleet Manager moves the sensor.

1. Check the Fleet Managers involved with `fm_fleets` (check: true). Name each one in the preview.
2. fleet-mcp logs in to the sensor over SSH as diag-shell, with its own key if installed (`fm_sensor_ssh_key`), otherwise the `sensor-admin-password` secret, which the user stores at a hidden prompt, never in the chat. The first connection shows the sensor's SSH host key fingerprint for the user to approve.
3. Call `fm_sensor_fleet` with `fleet` (the Fleet Manager that lists the sensor), `sensor` and `action`, without `confirm_token`, and show the preview. After the user approves, call again with `confirm_token`.
   - detach sets `fleet.enable=false` and waits for the Fleet Manager to lose the sensor.
   - attach disables Fleet Manager on the sensor, sets the target's address and community string, re-enables it, and waits for the sensor to connect to the target.
4. After a move, the sensor arrives on the new Fleet Manager in UNASSIGNED (or its old group, if that Fleet Manager listed it before) and keeps its configuration until it is put in a group with a policy. The old Fleet Manager still lists it, offline, until it is removed there; remove it only if the user asks.
5. After a detach, tell the user how to reattach: `fm_sensor_fleet` with `action: attach` on the same Fleet Manager.
