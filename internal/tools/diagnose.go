package tools

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/jsonview"
	"github.com/jlagermann/fleet-mcp/internal/spec"
)

// fm_sensor_diagnose condenses what Fleet Manager knows about an unhealthy
// sensor into one answer: the services that are not running and why,
// version and upgrade state, config apply errors, exceptions, licenses and
// metrics, compared with the healthy sensors on the same policy. It uses
// two requests for the whole fleet (the sensor catalog and the update
// status), so it is cheap enough to run on every sensor.

var deployedVersion = regexp.MustCompile(`does not match deployed version '([^']+)'`)

// jobTimeout matches deploy failures caused by waiting too long: a job,
// pod or daemonset that did not become ready in time.
var jobTimeout = regexp.MustCompile(`(?i)timed out|not ready after|deadline exceeded`)

// okStatus are service states that are not a problem.
var okStatus = map[string]bool{"running": true, "ok": true, "": true}

type serviceProblem struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Status  string   `json:"status"`
	Message string   `json:"message,omitempty"`
	Peers   string   `json:"peers,omitempty"` // how the same service is on the other sensors of the policy
	peerBad []string // peers where it is also not running
}

type sensorDiagnosis struct {
	Name      string            `json:"name"`
	UID       string            `json:"uid"`
	MgmtIPv4  any               `json:"mgmt_ipv4,omitempty"`
	Health    any               `json:"health"`
	Connected any               `json:"connected"`
	LastPing  string            `json:"last_ping,omitempty"`
	Group     any               `json:"group,omitempty"`
	Policy    any               `json:"policy,omitempty"`
	Model     any               `json:"model,omitempty"`
	Version   string            `json:"version,omitempty"`
	Deployed  string            `json:"deployed_ngs_version,omitempty"`
	Bundle    any               `json:"bundle_id,omitempty"`
	Problems  []serviceProblem  `json:"service_problems,omitempty"`
	Config    map[string]any    `json:"config_apply,omitempty"`
	Except    map[string]string `json:"exceptions,omitempty"`
	Licenses  map[string]any    `json:"licenses,omitempty"`
	Metrics   map[string]any    `json:"metrics,omitempty"`
	Update    map[string]any    `json:"last_update,omitempty"`
	Findings  []string          `json:"findings"`
	NextSteps []string          `json:"next_steps,omitempty"`
}

func registerDiagnose(s *mcp.Server, d *Deps) {
	type diagArgs struct {
		target
		Sensor string `json:"sensor,omitempty" jsonschema:"sensor uid or exact name; omit for every sensor that is not healthy or not connected"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_sensor_diagnose",
		Description: "Diagnose sensors from what Fleet Manager knows, in one call: for each sensor that is not healthy (or the one named), the services that are not running with their messages, the reported versus deployed (NGS) version, the last software update, config apply errors and failed fields, exceptions, ended licenses, failed metrics and connection age, each compared with the other sensors on the same policy (does the same service fail there too?), plus findings and next steps. " +
			"Start here for any unhealthy sensor before fm_sensor_get. Fleet Manager has no sensor logs; for those use fm_sensor_shell.",
		Annotations: readOnly("Diagnose sensors"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a diagArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.conn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		cat, err := d.catalog(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		updates := map[string]map[string]any{}
		if v, err := d.getDecoded(ctx, c, pathUpdateStatus, nil); err == nil {
			for _, el := range asList(v) {
				if m, ok := el.(map[string]any); ok {
					updates[fmt.Sprint(m["uid"])] = m
				}
			}
		}
		var want []map[string]any
		if a.Sensor != "" {
			uid, err := d.resolveSensor(ctx, c, a.Sensor)
			if err != nil {
				return nil, nil, err
			}
			for _, s := range cat {
				if fmt.Sprint(s["uid"]) == uid {
					want = append(want, s)
				}
			}
			if len(want) == 0 {
				return nil, nil, fmt.Errorf("sensor %s is not in %s's catalog", a.Sensor, c.Name)
			}
		} else {
			for _, s := range cat {
				if !strings.EqualFold(fmt.Sprint(s["health.status"]), "healthy") || s["fleet.connected"] != true {
					want = append(want, s)
				}
			}
		}
		// The FM version, to flag sensors newer than their Fleet Manager;
		// empty when it cannot be read.
		fmVersion, _ := spec.Version(ctx, c.Client)
		now := time.Now()
		var out []sensorDiagnosis
		for _, s := range want {
			out = append(out, diagnose(s, cat, updates[fmt.Sprint(s["uid"])], fmVersion, now))
		}
		healthy := len(cat)
		for _, s := range cat {
			if !strings.EqualFold(fmt.Sprint(s["health.status"]), "healthy") {
				healthy--
			}
		}
		r, err := jsonResult(map[string]any{"fleet": c.Name, "sensors_total": len(cat), "sensors_healthy": healthy, "diagnosed": out})
		return r, nil, err
	})
}

func diagnose(s map[string]any, cat []map[string]any, upd map[string]any, fmVersion string, now time.Time) sensorDiagnosis {
	st := s["extendedinformation.status"]
	dg := sensorDiagnosis{
		Name: fmt.Sprint(s["name"]), UID: fmt.Sprint(s["uid"]), MgmtIPv4: jsonview.Lookup(st, "/network.address.v4"),
		Health: s["health.status"], Connected: s["fleet.connected"], Group: s["group.name"], Policy: s["policy.name"],
		Model: jsonview.Lookup(st, "/model"), Version: str(jsonview.Lookup(st, "/os.version")), Bundle: s["bundle.id"],
		Findings: []string{},
	}
	finding := func(f string, a ...any) { dg.Findings = append(dg.Findings, fmt.Sprintf(f, a...)) }
	step := func(f string, a ...any) { dg.NextSteps = append(dg.NextSteps, fmt.Sprintf(f, a...)) }

	// Connection.
	if t, err := time.Parse(time.RFC3339Nano, str(s["ping.last"])); err == nil {
		age := humanAge(now.Sub(t))
		dg.LastPing = fmt.Sprintf("%s (%s ago)", str(s["ping.last"]), age)
		if s["fleet.connected"] != true {
			finding("not connected to Fleet Manager; last check-in %s ago, so everything below is as of then", age)
			step("check the sensor is powered on and can reach Fleet Manager (sensors connect out to Fleet Manager; Fleet Manager never connects in)")
		}
	}

	// Services: compare each problem with the peers on the same policy.
	peers := []map[string]any{}
	for _, p := range cat {
		if fmt.Sprint(p["uid"]) != dg.UID && fmt.Sprint(p["policy.id"]) == fmt.Sprint(s["policy.id"]) && p["fleet.connected"] == true {
			peers = append(peers, p)
		}
	}
	for _, sv := range asList(s["services.status"]) {
		m, ok := sv.(map[string]any)
		if !ok || okStatus[strings.ToLower(str(m["status"]))] {
			continue
		}
		pb := serviceProblem{ID: str(m["id"]), Name: str(m["name"]), Status: str(m["status"]), Message: strings.TrimSpace(str(m["message"]))}
		running := 0
		for _, p := range peers {
			ps := peerService(p, pb.ID)
			switch {
			case ps == "":
			case okStatus[strings.ToLower(ps)]:
				running++
			default:
				pb.peerBad = append(pb.peerBad, fmt.Sprint(p["name"]))
			}
		}
		switch {
		case len(peers) == 0:
		case len(pb.peerBad) == 0 && running == 0:
			pb.Peers = "only this sensor: the other sensors of the policy do not report this service"
		case len(pb.peerBad) == 0:
			pb.Peers = fmt.Sprintf("only this sensor: running on the other %d sensors of the policy", running)
		default:
			sort.Strings(pb.peerBad)
			pb.Peers = "also not running on " + strings.Join(pb.peerBad, ", ")
		}
		if mm := deployedVersion.FindStringSubmatch(pb.Message); mm != nil {
			dg.Deployed = mm[1]
		}
		dg.Problems = append(dg.Problems, pb)
	}
	sort.SliceStable(dg.Problems, func(i, j int) bool { return rank(dg.Problems[i].Status) < rank(dg.Problems[j].Status) })

	// Upgrade state.
	ngsFailed := false
	for _, pb := range dg.Problems {
		if strings.HasPrefix(pb.ID, "ngs") && strings.EqualFold(pb.Status, "failed") {
			ngsFailed = true
		}
	}
	if dg.Deployed != "" || ngsFailed {
		msg := "the software update did not finish its NGS (container platform) step"
		if dg.Deployed != "" {
			msg += fmt.Sprintf(": the sensor reports %s but still runs NGS %s", dg.Version, dg.Deployed)
		}
		finding("%s. Packet capture and exporting keep running on the old NGS layer; the health is failed because the upgrade is incomplete", msg)
		for _, pb := range dg.Problems {
			if strings.HasPrefix(pb.ID, "ngs") && pb.Message != "" && !strings.HasPrefix(pb.Message, "info:") {
				finding("%s: %s", pb.Name, pb.Message)
			}
		}
		if healthyPeers := countHealthy(peers); healthyPeers > 0 {
			finding("%d other sensors on policy %v took the same update and are healthy, so the update itself and the policy's content (including its bundle) are less likely the cause than something on this sensor", healthyPeers, s["policy.name"])
		}
		timedOut := false
		for _, pb := range dg.Problems {
			if strings.HasPrefix(pb.ID, "ngs") && jobTimeout.MatchString(pb.Message) {
				timedOut = true
			}
		}
		step("look on the sensor before changing anything: fm_sensor_shell check deploy (the latest deploy run) and check upgrade (every attempt: pre-flight, bootstrap, success or failure; the sensor reruns the deploy at boot and daily, so later attempts may have different errors), check datastore and check node (slow storage makes upgrade jobs time out) and check status")
		if timedOut {
			finding("the deploy failed on a timeout. On a virtual sensor that almost always means slow storage: the Kubernetes datastore and container start-up wait on disk I/O, worst when several sensors share a hypervisor datastore or upgrade at the same time. The sensor itself is usually fine")
			step("confirm with fm_sensor_shell check datastore (Slow SQL of tens of seconds) and check node (exec probe timeouts, pod start-ups of minutes); on the hypervisor, check the latency of the datastore holding the sensor's disk (tens of milliseconds per command while idle means it is saturated)")
			step("retry the deploy alone: fm_sensor_action reboot while the other VMs on that datastore are quiet, or let the daily automatic attempt run. If it keeps timing out, give the sensor faster storage (SSD, or a datastore it does not share with the other sensors) before opening a Corelight Support case")
		} else {
			step("if a reboot has not been tried, fm_sensor_action reboot reruns the deploy; if it keeps failing, open a Corelight Support case with the messages (root access on a sensor needs a Support escalation)")
		}
	}
	if newer, ok := newerThan(dg.Version, fmVersion); ok && newer {
		finding("the sensor runs %s but Fleet Manager is %s. Corelight recommends upgrading Fleet Manager before its sensors: an older Fleet Manager may not recognize settings added in the newer sensor release", dg.Version, fmVersion)
		step("upgrade Fleet Manager to %s or later", versionCore(dg.Version))
	}
	for _, pb := range dg.Problems {
		if strings.Contains(strings.ToLower(pb.Name), "base services") && strings.EqualFold(pb.Status, "failed") {
			step("Base Services (the sensor's Zeek services) failed: reboot first (fm_sensor_action reboot); if it stays failed, a custom package may conflict with the base packages: set the policy's custom package bundle to None (or disable the custom packages on an unassigned sensor), apply, retry a sync stuck in pending once, and reboot again")
		}
	}
	for _, pb := range dg.Problems {
		if !strings.HasPrefix(pb.ID, "ngs") && strings.EqualFold(pb.Status, "failed") {
			finding("service %s failed%s (%s)", pb.Name, msgSuffix(pb.Message), pb.Peers)
		}
	}

	// Config apply.
	if cs := str(s["configuration.apply.status"]); cs != "" && !strings.EqualFold(cs, "success") && !strings.EqualFold(cs, "unknown") {
		dg.Config = map[string]any{"status": cs, "error": s["configuration.apply.error-message"],
			"failed_fields": s["configuration.apply.failed-fields"], "diagnostics": s["configuration.apply.diagnostics"]}
		finding("the last configuration apply is %s%s", cs, msgSuffix(str(s["configuration.apply.error-message"])))
		step("compare the sensor's live and desired configuration with fm_sensor_get select /configuration.delta")
	}

	// Exceptions: settings this sensor overrides from its policy.
	if ex, ok := s["exceptions.current"].(map[string]any); ok && len(ex) > 0 {
		dg.Except = map[string]string{}
		data, _ := s["exceptions.data"].(map[string]any)
		for k, v := range ex {
			who := ""
			if m, ok := data[k].(map[string]any); ok {
				who = fmt.Sprintf(" (by %v at %v)", m["created-by"], m["created-at"])
			}
			dg.Except[k] = fmt.Sprintf("%v%s", v, who)
		}
		step("exceptions keep the listed settings off the policy. One not set on purpose may be left over from adding the sensor to a group with a policy (Fleet Manager then flags differing settings as exceptions instead of applying the policy): revert it to take the policy value")
	}

	// Licenses and metrics.
	if e, w := asList(s["licenses.end"]), asList(s["licenses.warn"]); len(e)+len(w) > 0 {
		dg.Licenses = map[string]any{"ended": e, "warning": w}
		if len(e) > 0 {
			finding("licenses ended: %v", e)
		}
	}
	if f, w, u := asList(s["metrics.failed"]), asList(s["metrics.warning"]), asList(s["metrics.unknown"]); len(f)+len(w)+len(u) > 0 {
		dg.Metrics = map[string]any{"failed": f, "warning": w, "unknown": u}
		if len(f) > 0 {
			finding("failed metrics: %v", f)
		}
	}

	// Last software update.
	if upd != nil {
		dg.Update = map[string]any{"message": upd["message"], "at": upd["timestamp"], "from": strings.TrimPrefix(str(upd["original_os"]), ":"),
			"status": upd["update_status"], "error": upd["error_message"], "offline": upd["is_offlineupdate"]}
		if upd["is_error"] == true {
			finding("the last software update failed: %v", upd["error_message"])
		}
	}

	if len(dg.Findings) == 0 && len(dg.Problems) > 0 {
		var names []string
		for _, pb := range dg.Problems {
			names = append(names, fmt.Sprintf("%s (%s)", pb.Name, pb.Status))
		}
		finding("services not OK as of the last check-in: %s; see service_problems for which parts failed. Right after a reboot or deploy this can be stale: compare with fm_sensor_shell status", strings.Join(names, ", "))
	}
	if len(dg.Findings) == 0 {
		if strings.EqualFold(fmt.Sprint(dg.Health), "healthy") {
			finding("Fleet Manager reports nothing wrong with this sensor")
		} else {
			finding("health is %v but Fleet Manager shows no failed service, config error, license or metric; look on the sensor with fm_sensor_shell", dg.Health)
		}
	}
	return dg
}

func peerService(p map[string]any, id string) string {
	for _, sv := range asList(p["services.status"]) {
		if m, ok := sv.(map[string]any); ok && str(m["id"]) == id {
			return str(m["status"])
		}
	}
	return ""
}

func countHealthy(ps []map[string]any) int {
	n := 0
	for _, p := range ps {
		if strings.EqualFold(fmt.Sprint(p["health.status"]), "healthy") {
			n++
		}
	}
	return n
}

func rank(status string) int {
	switch strings.ToLower(status) {
	case "failed", "error":
		return 0
	case "warning":
		return 1
	}
	return 2
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.1f hours", d.Hours())
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

func msgSuffix(m string) string {
	if m == "" {
		return ""
	}
	return ": " + m
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// versionCore returns the leading numbers of a version: "29.2.2" for
// "29.2.2-ca1" or "29.2.2-16847904621".
func versionCore(v string) string {
	end := 0
	for end < len(v) && (v[end] == '.' || v[end] >= '0' && v[end] <= '9') {
		end++
	}
	return strings.Trim(v[:end], ".")
}

// newerThan reports whether sensor version a is newer than Fleet Manager
// version b, comparing major.minor.patch; ok is false when either cannot
// be read.
func newerThan(a, b string) (newer, ok bool) {
	pa, pb := strings.Split(versionCore(a), "."), strings.Split(versionCore(b), ".")
	if pa[0] == "" || pb[0] == "" {
		return false, false
	}
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			fmt.Sscan(pa[i], &x)
		}
		if i < len(pb) {
			fmt.Sscan(pb[i], &y)
		}
		if x != y {
			return x > y, true
		}
	}
	return false, true
}
