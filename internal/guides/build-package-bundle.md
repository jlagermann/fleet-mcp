# Build and push a Zeek package bundle

A sensor policy's custom packages come from one bundle: a gzipped tar made by `zkg bundle`. It holds a `manifest.txt` and one directory per package (a git checkout). fleet-mcp pushes a bundle as it is (`fm_content_push` kind `bundle`). This guide covers building one and getting the packages running.

1. **The manifest.** Settle with the user which packages and versions to bundle. The manifest is in zkg's INI form:
   ```ini
   [bundle]
   https://github.com/corelight/ExtendIntel = v4.1
   /path/to/local/package = main
   ```
   Each line is an index name, a git URL or a local git repository path, `=` a tag or branch.
   - A branch floats: every build takes its latest commit. A tag pins the version.
   - A local repository ships only what is committed.
2. **Build with the sensors' Zeek version.** The sensors run Corelight's Zeek; `fm_sensor_get` and the sensor docs give the version. Build where `zkg` and `git` are available, for example the `zeek/zeek:<major.minor>` Docker image:
   ```bash
   docker run --rm --user $(id -u):$(id -g) -e HOME=/tmp -v "$PWD":/work -v /path/to/local/packages:/path/to/local/packages:ro -w /work zeek/zeek:8.0 \
     sh -c 'git config --global --add safe.directory "*" && zkg --user autoconfig --force >/dev/null && zkg --user bundle --force --manifest /work/bundle.manifest -- /work/corelight.bundle'
   ```
   Mount local package repositories at the same paths the manifest uses. `--user` keeps zkg's state in the container's home.
3. **Test before pushing** if the user can. Sensors test every enabled package together when a bundle arrives, and one failure can stop the deployment. Load the packages with the same Zeek: `zeek -a <package>/scripts ...`.
4. **Push.** Call `fm_content_push` with kind `bundle`, the file and the sensor policy. In the preview, show:
   - the packages added, removed and changed (version or git revision) against the policy's current bundle;
   - that new packages arrive **disabled**;
   - which enabled packages are missing from the new bundle (sensors stop loading them);
   - a note when the current bundle is managed by Corelight-update.

   After the user approves, push with `confirm_token`. Fleet Manager deploys the bundle to the policy's sensors. Updates to packages that are already enabled need nothing more.
5. **Enable new packages** in the sensor policy, either in the Fleet Manager web interface or with `fm_api_write`: PUT `/fleet/v1/sensor/policy/<id>` with the policy's full `packages.enabled` map plus the new package key, for example `"https:github.com:corelight:ExtendIntel": true`. The key is the source with `://` and `/` turned into `:`; the preview's diff shows it. Then the sensors load the package.
6. **Input files** a package reads: push them with `fm_content_push` kind `input` and the same `policy`, so the source lands in the policy's input collection.
