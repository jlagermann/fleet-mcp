package newpolicy

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
)

// Spec is everything the user decides about a new sensor policy.
type Spec struct {
	Name        string `json:"name" jsonschema:"name of the new sensor policy"`
	Description string `json:"description,omitempty" jsonschema:"description of the policy"`
	// Profile is north-south, east-west or none.
	Profile        string   `json:"profile" jsonschema:"starting set of Zeek packages: north-south (border or egress), east-west (internal) or none; see fm_policy_profiles"`
	AddPackages    []string `json:"add_packages,omitempty" jsonschema:"packages to enable in addition to the profile (key, short name or display name)"`
	RemovePackages []string `json:"remove_packages,omitempty" jsonschema:"profile packages to leave off"`

	// Access: SSH and HTTPS are on unless set to false.
	SSH           *bool  `json:"ssh,omitempty" jsonschema:"remote access over SSH (default true)"`
	SSHNetworks   string `json:"ssh_networks,omitempty" jsonschema:"networks allowed to SSH, comma-separated CIDRs (default: any)"`
	HTTPS         *bool  `json:"https,omitempty" jsonschema:"remote access to the sensor web interface over HTTPS (default true)"`
	HTTPSNetworks string `json:"https_networks,omitempty" jsonschema:"networks allowed to use HTTPS, comma-separated CIDRs (default: any)"`

	// Machine learning and anomaly detection are on unless set to false.
	MachineLearning  *bool `json:"machine_learning,omitempty" jsonschema:"on-sensor machine learning detections (default true; needs 32 GB RAM and 8 CPUs on virtual and software sensors)"`
	AnomalyDetection *bool `json:"anomaly_detection,omitempty" jsonschema:"anomaly detection (default true; same requirements; 31-day training)"`

	// Network. Empty keeps the sensor default.
	LocalNets     string `json:"local_nets,omitempty" jsonschema:"replace the local network blocks Zeek considers local, comma-separated CIDRs (empty keeps the defaults)"`
	TrafficFilter string `json:"traffic_filter,omitempty" jsonschema:"traffic exclusion filter (BPF) for traffic the sensor should ignore"`
	NTPServers    string `json:"ntp_servers,omitempty" jsonschema:"NTP servers, comma-separated"`
	SyslogServer  string `json:"syslog_server,omitempty" jsonschema:"syslog server for sensor diagnostics, host:port"`
	ProxyServer   string `json:"proxy_server,omitempty" jsonschema:"proxy URL for Corelight cloud services, if the sensors need one"`
	ProxyUsername string `json:"proxy_username,omitempty" jsonschema:"proxy username; the password is stored with fleet-mcp secret set-setting network.management.proxy.password"`

	BatchExport *BatchExport `json:"batch_export,omitempty" jsonschema:"batch export of Zeek log archives to SFTP or S3"`
	Exporters   []Exporter   `json:"exporters,omitempty" jsonschema:"streaming (dynamic) exporters; secret fields are stored with fleet-mcp secret set-setting exporter:<name>:<field>"`

	// Bundle is a custom package bundle on the target (name or ID) and
	// BundlePackages the packages of it to enable.
	Bundle         string   `json:"bundle,omitempty" jsonschema:"custom Zeek package bundle on the target, by name or ID"`
	BundlePackages []string `json:"bundle_packages,omitempty" jsonschema:"packages of that bundle to enable"`

	// Detection and enrichment: names or IDs on the target.
	Suricata        string `json:"suricata_policy,omitempty" jsonschema:"Suricata policy on the target, by name or ID (enables Suricata)"`
	Yara            string `json:"yara_ruleset,omitempty" jsonschema:"YARA ruleset on the target, by name or ID (enables YARA)"`
	InputCollection string `json:"input_collection,omitempty" jsonschema:"input collection on the target, by name or ID"`
	IntelCollection string `json:"intel_collection,omitempty" jsonschema:"intel collection on the target, by name or ID"`

	Performance *Performance `json:"performance,omitempty" jsonschema:"performance monitoring and reporting"`
	Updates     *Updates     `json:"updates,omitempty" jsonschema:"automatic software updates"`

	// Settings are advanced settings set only because the user asked.
	Settings map[string]any `json:"settings,omitempty" jsonschema:"advanced settings to set, only those the user asked for: setting key to value"`
}

// BatchExport sends Zeek log archives to an SFTP server or S3.
type BatchExport struct {
	Type      string `json:"type"` // sftp or s3
	Server    string `json:"server,omitempty"`
	User      string `json:"user,omitempty"`
	Path      string `json:"path,omitempty"`
	ServerKey string `json:"server_key,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	Region    string `json:"region,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
	UseIAM    bool   `json:"use_iam,omitempty"`
	Include   string `json:"include,omitempty"`
	Exclude   string `json:"exclude,omitempty"`
	Interval  string `json:"interval,omitempty"` // seconds, e.g. "300"
}

// Exporter is a dynamic (streaming) exporter.
type Exporter struct {
	Type     string         `json:"type" jsonschema:"exporter type offered by the target (hec, syslog, kafka, ...)"`
	Name     string         `json:"name" jsonschema:"name of this exporter"`
	Settings map[string]any `json:"settings,omitempty" jsonschema:"exporter fields and values, without secrets"`
}

// Performance is device performance reporting.
type Performance struct {
	ZeekLogs       bool   `json:"zeek_logs,omitempty"` // metrics through Zeek log streams
	Syslog         bool   `json:"syslog,omitempty"`
	Graphite       string `json:"graphite_server,omitempty"`
	Interval       string `json:"interval,omitempty"` // seconds
	NetworkMonitor bool   `json:"network_performance_package,omitempty"`
}

// Updates is automatic software updates.
type Updates struct {
	ViaFleet bool `json:"via_fleet_manager,omitempty"`
	// Apply is none, no_impact, service_restart, reboot or all.
	Apply string `json:"apply,omitempty"`
}

// Item is one line of the preview.
type Item struct {
	Section string `json:"section"`
	Setting string `json:"setting"`
	Value   any    `json:"value"`
	Why     string `json:"why,omitempty"`
}

// Built is the policy a Spec produces.
type Built struct {
	Configuration map[string]any `json:"-"`
	// Secrets lists settings whose values come from the secret store.
	Secrets []string `json:"secrets_needed,omitempty"`
	Items   []Item   `json:"items"`
	// Packages enabled, with where the recommendation came from.
	Packages []Package `json:"packages"`
	// Unavailable are recommended packages the target does not have.
	Unavailable []string `json:"unavailable_packages,omitempty"`
	// Defaults lists topics left at the sensor default.
	Defaults []string `json:"left_at_default,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Errors   []string `json:"errors,omitempty"`

	secretTargets []secretTarget
}

// secretTarget is a setting filled from the secret store.
type secretTarget struct{ store, setting string }

// SecretSettings maps each secret-store name the policy needs to the
// setting it fills.
func (b *Built) SecretSettings() map[string]string {
	out := map[string]string{}
	for _, t := range b.secretTargets {
		out[t.store] = t.setting
	}
	return out
}

// ExporterSecretKey names an exporter field in the secret store.
func ExporterSecretKey(name, field string) string { return "exporter:" + name + ":" + field }

func on(b *bool) bool { return b == nil || *b }

// Build turns a Spec into a configuration, checked against the target's
// settings schema (props) and exporter types (exporters).
func Build(s Spec, props, exporters map[string]any) *Built {
	b := &Built{Configuration: map[string]any{}}
	set := func(section, key string, v any, why string) {
		if len(props) > 0 && props[key] == nil && !strings.HasPrefix(key, "bro.exporters.") {
			b.Errors = append(b.Errors, fmt.Sprintf("the target does not know setting %s", key))
			return
		}
		b.Configuration[key] = v
		b.Items = append(b.Items, Item{Section: section, Setting: key, Value: v, Why: why})
	}
	secret := func(section, key, why string) {
		b.secretTargets = append(b.secretTargets, secretTarget{store: key, setting: key})
		b.Secrets = append(b.Secrets, key)
		b.Items = append(b.Items, Item{Section: section, Setting: key, Value: "(secret, from the secret store)", Why: why})
	}

	if strings.TrimSpace(s.Name) == "" {
		b.Errors = append(b.Errors, "a policy name is required")
	}

	// Access.
	set("access", "security.ssh.enable", on(s.SSH), "on by default")
	if s.SSHNetworks != "" {
		set("access", "security.ssh.networks", s.SSHNetworks, "")
	}
	set("access", "security.http.enable", on(s.HTTPS), "on by default")
	if s.HTTPSNetworks != "" {
		set("access", "security.http.networks", s.HTTPSNetworks, "")
	}

	// Machine learning and anomaly detection.
	ml, ad := on(s.MachineLearning), on(s.AnomalyDetection)
	set("detection", "corelight.ml.enable", ml, "on by default")
	set("detection", "bro.pkgs.corelight.ml_package.loaded", ml, "loads the machine learning package")
	set("detection", "corelight.anomaly_detection.enable", ad, "on by default")
	if ml || ad {
		b.Warnings = append(b.Warnings, "machine learning and anomaly detection need at least 32 GB RAM and 8 CPUs on virtual and software sensors (all physical sensors qualify); a sensor below that gets an automatic exception. Anomaly detection trains for 31 days before it alerts.")
	}

	// Network.
	if s.LocalNets != "" {
		set("network", "bro.site.local_nets", s.LocalNets, "replaces the default local network blocks")
	} else {
		b.Defaults = append(b.Defaults, "local network blocks (bro.site.local_nets): Zeek's default private and reserved ranges")
	}
	if s.TrafficFilter != "" {
		set("network", "bro.site.ignore_bpf", s.TrafficFilter, "traffic exclusion filter")
	}
	if s.NTPServers != "" {
		set("network", "network.management.ntp.server", s.NTPServers, "")
	} else {
		b.Defaults = append(b.Defaults, "NTP servers (network.management.ntp.server)")
	}
	if s.SyslogServer != "" {
		set("network", "network.management.syslog.server", s.SyslogServer, "diagnostic syslog")
	} else {
		b.Defaults = append(b.Defaults, "diagnostic syslog server (network.management.syslog.server)")
	}
	if s.ProxyServer != "" {
		set("network", "network.management.proxy.server", s.ProxyServer, "proxy for Corelight cloud services")
		if s.ProxyUsername != "" {
			set("network", "network.management.proxy.username", s.ProxyUsername, "")
			secret("network", "network.management.proxy.password", "proxy password")
		}
	} else {
		b.Defaults = append(b.Defaults, "proxy (none)")
	}

	// Exports.
	b.batchExport(s.BatchExport, set, secret)
	b.exporters(s.Exporters, exporters, set, secret)

	// Packages.
	b.packages(s, props, set)
	if s.Bundle == "" {
		b.Defaults = append(b.Defaults, "custom package bundle (none)")
	}

	// Detection and enrichment links are resolved by the caller; their
	// enable switches are settings.
	if s.Suricata != "" {
		set("detection", "suricata.enable", true, "Suricata policy "+s.Suricata)
	}
	if s.Yara != "" {
		set("detection", "corelight.yara.enable", true, "YARA ruleset "+s.Yara)
	}

	// Performance monitoring.
	if p := s.Performance; p != nil {
		if p.ZeekLogs {
			set("performance", "metrics.bro.enable", true, "device metrics and service status in Zeek logs")
		}
		if p.Syslog {
			set("performance", "metrics.syslog.enable", true, "device metrics over syslog")
		}
		if p.Graphite != "" {
			set("performance", "metrics.graphite.enable", true, "")
			set("performance", "metrics.graphite.server", p.Graphite, "")
		}
		if p.Interval != "" {
			if p.ZeekLogs {
				set("performance", "metrics.bro.interval", p.Interval, "")
			}
			if p.Syslog {
				set("performance", "metrics.syslog.interval", p.Interval, "")
			}
			if p.Graphite != "" {
				set("performance", "metrics.graphite.interval", p.Interval, "")
			}
		}
		if p.NetworkMonitor {
			set("performance", "bro.pkgs.corelight.net_perf.loaded", true, "Network Performance Monitoring package")
		}
	} else {
		b.Defaults = append(b.Defaults, "performance monitoring (off)")
	}

	// Updates.
	if u := s.Updates; u != nil {
		set("updates", "fleet.updates.enable", u.ViaFleet, "use Fleet Manager as the update server")
		levels := []string{"no_impact", "service_restart", "visible_change", "reboot"}
		apply := u.Apply
		if apply == "" {
			apply = "none"
		}
		switch apply {
		case "none":
			for _, l := range levels {
				set("updates", "updates."+l, false, "automatic updates off")
			}
		case "all":
			set("updates", "updates.all", true, "apply every update automatically")
		case "no_impact", "service_restart", "reboot":
			// Each level includes the less disruptive ones.
			for _, l := range []string{"no_impact", "service_restart", "reboot"} {
				set("updates", "updates."+l, true, "automatic up to "+apply)
				if l == apply {
					break
				}
			}
		default:
			b.Errors = append(b.Errors, fmt.Sprintf("updates.apply must be none, no_impact, service_restart, reboot or all, not %q", apply))
		}
	} else {
		b.Defaults = append(b.Defaults, "automatic updates (sensor default)")
	}

	// Advanced settings the user asked for.
	for _, k := range sortedKeys(s.Settings) {
		set("advanced", k, s.Settings[k], "asked for")
	}
	sort.Strings(b.Secrets)
	return b
}

func (b *Built) batchExport(e *BatchExport, set func(string, string, any, string), secret func(string, string, string)) {
	if e == nil {
		b.Defaults = append(b.Defaults, "batch export (off)")
		return
	}
	switch e.Type {
	case "sftp":
		set("export", "bro.export.logs.enable", true, "batch export of Zeek logs to SFTP")
		for k, v := range map[string]string{"bro.export.sftp.log.server": e.Server, "bro.export.sftp.log.user": e.User,
			"bro.export.sftp.log.path": e.Path, "bro.export.sftp.log.server_key": e.ServerKey} {
			if v != "" {
				set("export", k, v, "")
			}
		}
		if e.Server == "" || e.User == "" {
			b.Errors = append(b.Errors, "SFTP batch export needs server and user")
		}
		b.Warnings = append(b.Warnings, "SFTP batch export logs in with the sensor's key: add each sensor's export public key to the SFTP user's authorized_keys")
		b.logSelection("bro.export.logs", e, set)
		if e.Interval != "" {
			set("export", "bro.export.logs.interval", e.Interval, "")
		}
	case "s3":
		set("export", "bro.export.s3.log.enable", true, "batch export of Zeek logs to S3")
		for k, v := range map[string]string{"bro.export.s3.log.bucket": e.Bucket, "bro.export.s3.log.prefix": e.Prefix,
			"bro.export.s3.region": e.Region, "bro.export.s3.endpoint": e.Endpoint} {
			if v != "" {
				set("export", k, v, "")
			}
		}
		if e.Bucket == "" {
			b.Errors = append(b.Errors, "S3 batch export needs a bucket")
		}
		if e.UseIAM {
			set("export", "bro.export.s3.use_iam", true, "IAM role instead of keys")
		} else {
			if e.AccessKey == "" {
				b.Errors = append(b.Errors, "S3 batch export needs access_key, or use_iam")
			} else {
				set("export", "bro.export.s3.access_key", e.AccessKey, "")
				secret("export", "bro.export.s3.secret_access_key", "S3 secret access key")
			}
		}
		b.logSelection("bro.export.s3.log", e, set)
	default:
		b.Errors = append(b.Errors, fmt.Sprintf("batch_export.type must be sftp or s3, not %q", e.Type))
	}
}

func (b *Built) logSelection(prefix string, e *BatchExport, set func(string, string, any, string)) {
	if e.Include != "" {
		set("export", prefix+".include_enabled", true, "")
		set("export", prefix+".include", e.Include, "")
	}
	if e.Exclude != "" {
		set("export", prefix+".exclude", e.Exclude, "")
	}
}

// exporters adds dynamic exporters, checked against the target's exporter
// types: required fields must be given, secret (noLog) fields come from the
// secret store.
func (b *Built) exporters(list []Exporter, types map[string]any, set func(string, string, any, string), secret func(string, string, string)) {
	if len(list) == 0 {
		b.Defaults = append(b.Defaults, "streaming exporters (none)")
		return
	}
	var instances []string
	for _, e := range list {
		def, ok := types[e.Type]
		if !ok {
			b.Errors = append(b.Errors, fmt.Sprintf("the target offers no %s exporter type (exporter types appear once a sensor has connected)", e.Type))
			continue
		}
		fields := exporterFields(def)
		inst := instanceID()
		instances = append(instances, inst)
		prefix := "bro.exporters." + inst + "."
		set("export", prefix+"type", e.Type, "exporter "+e.Name)
		set("export", prefix+"name", e.Name, "")
		for _, k := range sortedKeys(e.Settings) {
			f, known := fields[k]
			switch {
			case !known:
				b.Errors = append(b.Errors, fmt.Sprintf("exporter %s (%s) has no field %s", e.Name, e.Type, k))
			case f.secret:
				b.Errors = append(b.Errors, fmt.Sprintf("exporter %s field %s is a secret: store it with fleet-mcp secret set-setting %s instead", e.Name, k, ExporterSecretKey(e.Name, k)))
			default:
				set("export", prefix+k, e.Settings[k], "")
			}
		}
		for _, name := range sortedKeys(fields) {
			f := fields[name]
			if f.secret {
				b.Secrets = append(b.Secrets, ExporterSecretKey(e.Name, name))
				b.Items = append(b.Items, Item{Section: "export", Setting: prefix + name, Value: "(secret, from the secret store)", Why: "exporter " + e.Name})
				b.secretTargets = append(b.secretTargets, secretTarget{store: ExporterSecretKey(e.Name, name), setting: prefix + name})
				continue
			}
			if _, given := e.Settings[name]; given {
				continue
			}
			switch {
			case f.hasDefault:
				// As the web interface does: unset fields take their default.
				b.Configuration[prefix+name] = f.defaultValue
			case f.required:
				b.Errors = append(b.Errors, fmt.Sprintf("exporter %s (%s) needs field %s", e.Name, e.Type, name))
			}
		}
	}
	if len(instances) > 0 {
		set("export", "bro.exporters.instances", strings.Join(instances, ", "), "")
	}
}

type field struct {
	secret, required, hasDefault bool
	defaultValue                 any
}

// exporterFields reads an exporter type's fields from exporter.metadata.
func exporterFields(def any) map[string]field {
	out := map[string]field{}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if name, _ := t["fieldName"].(string); name != "" {
				f := field{secret: t["noLog"] == true}
				if dv, ok := t["defaultValue"]; ok {
					f.hasDefault, f.defaultValue = true, dv
				}
				if vs, ok := t["validators"].([]any); ok {
					for _, x := range vs {
						if m, ok := x.(map[string]any); ok && m["type"] == "required" {
							f.required = true
						}
					}
				}
				out[name] = f
			}
			for _, c := range t {
				walk(c)
			}
		case []any:
			for _, c := range t {
				walk(c)
			}
		}
	}
	walk(def)
	return out
}

// instanceID makes an exporter instance ID like Fleet Manager's (10
// characters of [0-9a-z]).
func instanceID() string {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

func (b *Built) packages(s Spec, props map[string]any, set func(string, string, any, string)) {
	var chosen map[string]Package
	switch s.Profile {
	case NorthSouth, EastWest:
		chosen = Recommended(s.Profile)
	case NoProfile, "":
		chosen = map[string]Package{}
	default:
		b.Errors = append(b.Errors, fmt.Sprintf("profile must be north-south, east-west or none, not %q", s.Profile))
		chosen = map[string]Package{}
	}
	for _, ref := range s.AddPackages {
		p, ok := Lookup(ref)
		if !ok {
			b.Errors = append(b.Errors, fmt.Sprintf("unknown package %q (see fm_policy_profiles)", ref))
			continue
		}
		p.Source = "asked for"
		chosen[p.Key] = p
	}
	for _, ref := range s.RemovePackages {
		p, ok := Lookup(ref)
		if !ok {
			b.Errors = append(b.Errors, fmt.Sprintf("unknown package %q (see fm_policy_profiles)", ref))
			continue
		}
		delete(chosen, p.Key)
	}
	keys := make([]string, 0, len(chosen))
	for k := range chosen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := chosen[k]
		if len(props) > 0 && props[k] == nil {
			b.Unavailable = append(b.Unavailable, p.Name)
			continue
		}
		b.Configuration[k] = true
		b.Packages = append(b.Packages, p)
	}
	_ = set
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
