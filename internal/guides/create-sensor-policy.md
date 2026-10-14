# Create a sensor policy from scratch

Fleet Manager has sensor policies and Suricata policies. If the user said only "a policy", ask which kind first. This guide is for sensor policies (`fm_policy_create`).

Interview the user first, **one topic at a time**, and only then preview. Topics, in order:

1. **Name and description.**
2. **Where the sensors sit:** north-south (border or egress), east-west (internal), or neither. Show that profile's packages from `fm_policy_profiles` and ask what to add or remove.
3. **ICS/OT:** do the sensors see ICS/OT traffic? If so, all ICS/OT protocol analyzers in bulk (`ics_ot`) or only some. Mention that packages can be added or removed at any time later. Advanced packages only on request.
4. **Custom package bundle**, and which of its packages to enable.
5. **Remote access:** SSH and HTTPS are on by default; ask about allowed networks.
6. **Local network blocks:** keep the defaults or replace them.
7. **Traffic exclusion filter.** It is not standard BPF:
   - Write only what to exclude; the sensor applies `not (filter)`. A user who gives a standard capture filter (what to keep) must have it inverted.
   - One-direction filters (`src host`, `dst port`, ...) are not supported: dropping one side of a connection breaks Zeek's analysis. Rewrite them without src/dst to exclude both directions, and say so.
   - No VLAN, ATM/MTP, arithmetic or packet-data expressions.
   - `bro.site.restrictive_bpf=false` allows one-direction filters per packet, but only on explicit request, with Corelight's advice to contact Support first.
8. **NTP servers, diagnostic syslog, and a proxy** if the sensors need one.
9. **Exports:** batch export (SFTP or S3) and streaming exporters.
10. **Content:** Suricata policy, YARA ruleset, input, intel and asset classification collections.
    - Connector-fed enrichments work only with the whole chain: a connector for authentication, a source per file using it, a collection of sources, the collection linked to the policy, and for input files a Zeek package in the same policy that reads the file. Otherwise nothing happens.
    - The preview takes each input file's reader from the target's connected sensors (`bro.inputs` lists the files loaded packages look for, with the package) before fleet-mcp's own matches, which are only suggestions: customers write their own packages and packages change. Ask the user which package reads each file the preview asks about, and pass the answers in `input_readers`.
    - Check each link with `fm_graphql_query` (fileCollections, fileSources) and the preview's enrichments section. Explain any missing piece and how to set it up from the Fleet Manager Connectors docs. Connector credentials are entered by the user in the Fleet Manager web interface, never in the chat.
    - Intel files are read by the Zeek intel framework; ExtendIntel adds their metadata to logs.
    - Asset classification also turns on `asset_classification.enable` (Early Access).
11. **Machine learning and anomaly detection:** on by default; sensors under 32 GB RAM and 8 CPUs get automatic exceptions.
12. **Performance monitoring**, in the sensor's own wording: "Enable reporting through Zeek log streams" (corelight_metrics_* and corelight_service_status logs), "Enable reporting through syslog", "Enable reporting to a Graphite server". Separately, the Network Performance Monitoring package (a Zeek package that detects and aggregates network performance anomalies).
13. **Software updates:** "Install software updates" is on by default, and the sensor downloads its own updates from Corelight Cloud Services. Offline updates are loaded into Fleet Manager and delivered from there instead. To fully disable automatic updates, turn off Install software updates and all four update types (no impact, service restart, visible change, reboot). Or apply only selected types.

Set other advanced settings only when asked.

Secrets (proxy password, S3 secret key, exporter tokens) are typed by the user at a hidden prompt (`fleet-mcp secret set-setting <name>`, given with the full path), never in the chat.

Then call `fm_policy_create` without `confirm_token`, show the preview (including what stays at the sensor default), get the user's approval, and call again with the identical request and `confirm_token`.
