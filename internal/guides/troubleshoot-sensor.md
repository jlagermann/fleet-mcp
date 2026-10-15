# Troubleshoot a sensor

For an overview of every Fleet Manager and which sensors need attention, use `fm_fleet_health`; for a Fleet Manager host itself, `fm_host_diagnose`.

1. Start with `fm_sensor_diagnose`. It answers from Fleet Manager in one call: failed services and their messages, reported versus deployed (NGS) version, the last software update, config apply errors, exceptions and ended licenses, each compared with the other sensors on the same policy, plus findings and next steps.
2. Then use `fm_sensor_shell` for what Fleet Manager cannot show. It runs fixed read-only checks over SSH as diag-shell, which has no root. Useful checks:
   - `status`, `version`
   - `deploy`: the latest NGS deploy run
   - `upgrade`: every deploy attempt
   - `service_logs`, `exporter_logs`, `pod_logs`, `system_logs`, `system_log`
   - `disk`
   - `datastore`: k3s "Slow SQL" latency
   - `node`: kubelet probe timeouts and slow pod start-ups
3. Compare with healthy sensors on the same policy before you conclude a cause.
4. Exceptions may be left over from adding the sensor to a group with a policy.
5. **Slow storage** makes NGS deploy jobs time out. Signs are pre-flight or bootstrap timeouts, datastore latency of tens of seconds, and pod start-ups that take minutes. On a virtual sensor, ask the user to check the hypervisor for snapshot chains or slow datastores. Exit code 137 in sandbox logs is normal job teardown, not evidence.
6. When writes are enabled, `fm_sensor_action` does one fixed action, previewed first:
   - `reboot`: at boot the sensor reruns its NGS deploy, the first thing to try when an NGS upgrade failed on a job timeout.
   - `apply_updates`: applies pending software updates.
   - `revert_update`: only when the user asks for a revert by name.

   Follow a deploy with `fm_sensor_shell` check `deploy`. Fleet Manager's update trigger only pushes policy; it never upgrades software.
7. **Corelight Support remote access:** `fm_sensor_support_access` turns "Enable Corelight remote interface" on or off and shows the Device UID Support needs. Turn it on only when Support asks, and off when they are done.
