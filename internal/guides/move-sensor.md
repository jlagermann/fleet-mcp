# Move a sensor to another Fleet Manager

1. Check both Fleet Managers with `fm_fleets` (check: true). Name both in the preview.
2. fleet-mcp logs in to the sensor over SSH as diag-shell, with its own key if installed (`fm_sensor_ssh_key`), otherwise the `sensor-admin-password` secret, which the user stores at a hidden prompt, never in the chat. The first connection shows the sensor's SSH host key fingerprint for the user to approve.
3. Call `fm_sensor_move` without `confirm_token` and show the preview. After the user approves, call again with `confirm_token`. The tool disables Fleet Manager on the sensor, sets the target's address and community string, re-enables it, and waits for the sensor to appear on the target.
4. On the target, the sensor arrives unassigned and keeps its configuration until it is put in a group with a policy. The source Fleet Manager still lists it, offline, until it is removed there.
