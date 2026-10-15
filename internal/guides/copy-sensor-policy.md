# Copy a sensor policy to another Fleet Manager

1. `fm_policy_copy` exports the policy and everything it uses from the source Fleet Manager (`source_fleet`, which may be read-only) and previews the import into the target (`fleet`). `fm_policy_export` and `fm_policy_import` do the two halves separately; `fm_policy_packages` lists exported packages.
2. Versions must match on major.minor (the patch level is ignored). Sensors don't matter: a policy can be imported into a Fleet Manager with no sensors.
3. Go through the preview with the user:
   - **plan.decisions** are questions for the user. Ask them and never decide for them. Pass the answers back as the tool describes.
   - **Exporters** can be migrated only once the target has a sensor attached (Fleet Manager lists no exporter types before that). The preview then asks whether to continue without them. A user who continues can add them later, after attaching a sensor, with `fm_policy_import`, the same package and `complete: true`; `fm_policy_packages` shows imports still waiting for that.
   - **Conflicts:** an object already on the target that is identical is reused; one that differs becomes a decision (use the existing one, rename, or update the existing sensor policy).
   - **Warnings**, for example content pushed by Corelight-update, which stays static on the target unless Corelight-update also pushes to the new policy. Pass them on; take no action.
4. Secrets (exporter tokens, password settings, licensed feed URLs, connector credentials) are never copied with the policy. Show the follow_up list so the user can enter them on the target, never in the chat.
5. Sensor groups are not copied.
6. Get the user's approval of the preview, then call again with the same arguments plus `package` and `confirm_token`.
7. Afterwards, `fm_policy_diff` (policy, fleet, compare_fleet) shows what still differs between the two Fleet Managers, for example the secrets that were not copied.
