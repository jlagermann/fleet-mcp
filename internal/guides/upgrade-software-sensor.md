# Upgrade a Software Sensor

A Software Sensor cannot update itself, and Fleet Manager's update settings and update trigger do not change it. It is upgraded on its Linux host: install the new corelightctl and corelight-sensor packages from the Corelight sensor-stable repository, then `corelightctl sensor prepare` and `corelightctl sensor deploy`. `fm_softsensor_upgrade` does all of this. Ubuntu hosts only for now.

## Before

1. Find the sensor with `fm_sensors_list` and check it with `fm_sensor_diagnose`. Fix existing problems first; an upgrade does not fix a broken deploy.
2. The tool needs SSH to the sensor host as a user with passwordless sudo (`ssh_user`, or FLEET_MCP_SSH_USER). The host key must already be in the user's known_hosts: if the first connection fails on the host key, ask the user to confirm the fingerprint, never accept it yourself.
3. **Version:** a Fleet Manager must be the same version as its sensors or newer. Without a version, the tool picks the newest in the repository that the Fleet Manager allows. If the user wants a newer one, upgrade Fleet Manager first (follow fm_guide topic maintain-fleet-manager).
4. **Snapshot:** suggest a VM snapshot (or a host backup) first. Delete it once the sensor is healthy: on slow storage, a growing snapshot delta slows the next deploy.

## Preview and upgrade

5. Call `fm_softsensor_upgrade` without confirm_token. Show the user the installed, running and target versions, the steps, warnings and blockers. Common blockers:
   - **Free space:** the download stays on disk while the image archives in /opt/corelight are replaced, and `corelightctl sensor deploy` has its own free-space check (about 22 GB in 29.x). Growing the filesystem is the user's call (for an LVM root, `lvextend -r`).
   - **Retired repository file** `corelight_corelightctl.list`: set up the sensor-stable repository as in the installation guide first.
   - **apt-get update failed:** the repository token in /etc/apt/auth.conf.d may have expired; the user gets a new one at my.corelight.cloud (Downloads | Software Sensor). Never ask for it in the chat.
   - **Slow storage** (warning; `sync_write_ms` 10 or more): the deploy loads several GB of images and restarts Kubernetes, whose etcd datastore needs fast synchronous writes. On slow disks it can miss corelightctl's fixed 5- and 15-minute waits and fail with exit 3. Tell the user before they approve; moving the VM to faster storage first avoids it, and otherwise step 12 applies. Stopping the sensor first does not help: the deploy starts the existing Kubernetes again before it loads images.
6. After the user approves, call again with confirm_token. Capture and export stop during the deploy. The upgrade runs on the host as systemd unit fleet-mcp-softsensor-upgrade, so a dropped connection does not stop it. The call waits `wait_minutes` (default 20, at most 25); if it is still running, check with `status: true` every few minutes. A deploy on slow storage can take 40 minutes or more.

## After

7. When the result is `done`, run `fm_sensor_diagnose`: the version Fleet Manager reports should be the target, and the sensor healthy. Fleet Manager may need a few minutes.
8. `reboot-required`: corelightctl needs a host reboot before it can deploy. Ask the user to reboot the host, then run `fm_softsensor_upgrade` again: the preview offers the deploy only.
9. Remind the user to delete the snapshot when the sensor has been healthy for a while.

## If it fails

10. The result names the stage and, for the deploy, what corelightctl's exit code means. Exit 6 means the deploy rolled back: the sensor runs its previous deployment, with the new packages installed.
11. The full output is in /var/log/fleet-mcp-softsensor-upgrade.log and /var/log/corelightctl.log on the host. `corelightctl sensor status` on the host shows the services.
12. **Exit 3 (bootstrap failed) does not roll back.** On slow storage it is usually one of corelightctl's fixed waits timing out ("did not finish removing the nginx HelmChart within 5m0s", "daemonset rke2-traefik is not ready after 900 seconds"). What to do depends on Kubernetes (RKE2) afterwards; ask the user to check `systemctl status rke2-server` on the host, or check it if you have shell access:
    - **rke2-server is running** (not restarting over and over): retry. Wait until the host is idle (load back to normal, typically 10–20 minutes), then run `fm_softsensor_upgrade` again: the packages are installed, so the preview offers the deploy only. With no apt download and nothing else loading images, the retry usually passes. Retry once; if it fails the same way again, revert the snapshot or move the VM to faster storage.
    - **rke2-server keeps restarting** with "failed to reconcile with local datastore": the etcd datastore did not survive. A retry will not help: revert the VM snapshot.
13. Preflight timeouts (zeek-bundle, "failed to create sensor-core tmp dir") are usually slow storage: see fm_guide topic troubleshoot-sensor. Running the tool again retries the deploy.
14. To go back, revert the VM snapshot, or run the tool with the previous version and `allow_downgrade` (a downgrade is not documented by Corelight; prefer the snapshot).
