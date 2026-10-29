# Manage collections and YARA rulesets

Content reaches sensors through a chain: **source** (a file, or a connector that fetches one) → **collection** → **sensor policy** → the sensors of the groups using that policy → (for input files) a loaded Zeek package that reads the file. A sensor policy links at most one collection of each kind:

| Kind | What it holds | Policy field |
|---|---|---|
| `intel` | Zeek Intel framework files | intel collection |
| `input` | Input framework files that packages read (allowlists, lookup tables) | input collection |
| `resource` | Asset classification files | asset classification collection |
| `ca_bundle` | CA bundles | CA bundle collection |
| `yara` | YARA sources (a YARA ruleset) | YARA ruleset |

`fm_collection_manage` creates, changes or deletes one collection or ruleset, and in the same call adds or removes existing sources and links it to or unlinks it from sensor policies. To upload a file, use `fm_content_push` (see the push-content guide); it can also add the new source to a policy's collection.

## Look first

1. Name the Fleet Manager. Read the current state with `fm_policies_list` (each policy's collection ids) and `fm_graphql_query`, e.g. `{ fileCollection(id: "1") { name type sources { id alias name createdBy enabled } } }`, or `yaraRulesets { rulesets { id name sources { id } } }`.
2. Sources created by another tool are fine to use. Corelight-update puts each `local-input/` file in Fleet Manager as an input source named `<policy>_<file>` ("Created by Corelight Update"), but does not add it to a collection: that step is this tool's job. Corelight-update keeps updating the source's content; adding it to a collection only changes who gets it.

## Change a collection

3. Call `fm_collection_manage` without confirm_token for a preview:
   - **create**: `kind` and the new name in `collection`; optionally `description`, `add_sources`, `link_policies`.
   - **update**: `collection` by id or name (add `kind` when the same name exists for several kinds); any of `new_name`, `description`, `add_sources`, `remove_sources`, `link_policies`, `unlink_policies`.
   - **delete**: only `unlink_policies`. A collection that a policy still uses cannot be deleted unless the same call unlinks it. Its sources are kept.
   Sources are named by id, alias or file name; when a file name matches several sources the preview asks for the id.
4. Show the user:
   - every change, and the sources and policies after it;
   - **links that replace** a policy's current collection: its sensors stop getting sources that are only in the old one. Unlinking leaves the policy with none of that kind;
   - disabled sources, and sources that share a file name (they feed one file of that name on the sensors);
   - sources another tool manages (note only);
   - the sensor groups affected, or that no group uses the policy yet;
   - for input collections, which loaded package on the connected sensors reads each file. A file no package reads does nothing until a package that reads it is enabled (fm_policy_update `enable_packages`).
5. After the user approves, call again with the same arguments plus confirm_token. The result lists what was done; the read-back checks the collection's sources and each changed policy link. Fleet Manager then sends the changed policies to their sensors (`fm_sensors_list` shows the apply state).
