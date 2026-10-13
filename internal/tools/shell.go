package tools

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/host"
	"github.com/jlagermann/fleet-mcp/internal/metrics"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
	"github.com/jlagermann/fleet-mcp/internal/sensorssh"
)

// fm_sensor_shell runs read-only diagnostics on a sensor as diag-shell.
// diag-shell is an unprivileged bash in a firejail sandbox (no root; root
// needs a Corelight Support escalation; no ps, top, awk, free or /proc).
// What it can read: /system-logs (corelightctl, k3s, containerd, ansible
// and other host logs) and, through sudo, "corelightctl sensor status",
// "corelightctl version", "corelightctl sensor logs" (service, container,
// exporter and topic logs) and "kubectl logs". sudo also allows
// "corelightctl sensor stop"; no check here ever uses it. Only these fixed
// checks run, with validated arguments: never a free-form command.

const (
	ctl     = "sudo -n /usr/bin/corelightctl"
	kubectl = "sudo -n /usr/local/bin/kubectl"
	maxLine = 800 // characters kept per output line
)

var (
	safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$`)
	safeFile = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,120}(/[A-Za-z0-9][A-Za-z0-9._-]{0,120})?$`)
	// upgradeNoise are corelightctl lines repeated every few seconds while
	// it waits; they hide the lines that matter.
	upgradeNoise = []string{"failed to get k8s node", "waiting for sensor-api", "failed to get auth token", "waiting for runit"}
)

// shellChecks describes each check for the tool description and errors.
var shellChecks = map[string]string{
	"status":        "corelightctl sensor status: platform, OS and NGS versions, license, every service and exporter with its state, and errors",
	"version":       "corelightctl version (the NGS version installed for the next deploy)",
	"deploy":        "the latest NGS deploy run (the sensor reruns it at every boot and daily): when it started, whether it succeeded, failed or is still running, and its steps; use it to follow a deploy after fm_sensor_action reboot",
	"upgrade":       "the NGS deploy/upgrade history from /system-logs/corelightctl.log: pre-flight checks, bootstrap, deploy success or failure, with the repeated wait messages removed (file: a rotated copy such as corelightctl.log-20261011)",
	"service_logs":  "corelightctl sensor logs for a service (service, optional container), e.g. sensor-operator, sensor-core, kafka",
	"exporter_logs": "corelightctl sensor logs for an exporter (exporter: its id, e.g. exporter-635n2t7kxj)",
	"pod_logs":      "kubectl logs for a pod (pod, optional container) in corelight-sensor or, with namespace kube-system, the Kubernetes system pods: rke2-canal (calico-node, kube-flannel: the pod network a deploy waits for), coredns, kube-controller-manager-brolin, kube-scheduler-brolin; pod names come from other logs (kubelet.log, containerd.log)",
	"system_logs":   "list the host logs in /system-logs with size and time",
	"system_log":    "the end of one host log in /system-logs (file, e.g. k3s.log, containerd.log, ansible.log, broala-apid.log), optionally only lines containing pattern",
	"disk":          "df -h",
	"node":          "whether the sensor host is starved, from kubelet.log: exec probe timeouts (10 s each) and the slowest and latest pod start-ups; probe timeouts and start-ups of minutes mean slow storage (or CPU), which makes deploy jobs time out (pattern narrows to lines containing it, e.g. a time such as \"Oct 12 14:5\")",
	"datastore":     "the Kubernetes datastore (kine) latency: how many Slow SQL warnings k3s logged and the slowest; tens of seconds means slow storage, which makes upgrade jobs time out",
}

type shellArgs struct {
	target
	Sensor     string `json:"sensor" jsonschema:"sensor uid or exact name"`
	SensorHost string `json:"sensor_host,omitempty" jsonschema:"SSH address of the sensor if Fleet Manager does not report its management address"`
	Check      string `json:"check" jsonschema:"one of: status, version, deploy, upgrade, service_logs, exporter_logs, pod_logs, system_logs, system_log, disk, datastore, node"`
	Service    string `json:"service,omitempty" jsonschema:"service_logs: the service name from status (e.g. sensor-operator)"`
	Exporter   string `json:"exporter,omitempty" jsonschema:"exporter_logs: the exporter id from status (e.g. exporter-635n2t7kxj)"`
	Pod        string `json:"pod,omitempty" jsonschema:"pod_logs: the pod name"`
	Namespace  string `json:"namespace,omitempty" jsonschema:"pod_logs: corelight-sensor (default) or kube-system"`
	Container  string `json:"container,omitempty" jsonschema:"service_logs or pod_logs: a container in it"`
	File       string `json:"file,omitempty" jsonschema:"system_log or upgrade: a file in /system-logs"`
	Pattern    string `json:"pattern,omitempty" jsonschema:"keep only lines containing this text (case-insensitive, plain text, not a regex)"`
	Lines      int    `json:"lines,omitempty" jsonschema:"how many lines from the end (default 200, at most 2000)"`
	HostKey    string `json:"host_key,omitempty" jsonschema:"the sensor's SSH host key fingerprint the user approved; needed only the first time fleet-mcp connects to a sensor"`
}

// shellCommand builds the command line for a check. Every argument is
// validated and quoted; nothing from the caller reaches the shell
// unquoted.
func shellCommand(a shellArgs) (string, error) {
	n := a.Lines
	if n <= 0 {
		n = 200
		if a.Check == "deploy" {
			n = 60
		}
	}
	if n > 2000 {
		n = 2000
	}
	need := func(field, v string, re *regexp.Regexp) error {
		if v == "" {
			return fmt.Errorf("check %s needs %s", a.Check, field)
		}
		if !re.MatchString(v) || strings.Contains(v, "..") {
			return fmt.Errorf("%s %q is not a valid name", field, v)
		}
		return nil
	}
	if a.Container != "" {
		if err := need("container", a.Container, safeName); err != nil {
			return "", err
		}
	}
	filter := ""
	if a.Pattern != "" {
		if len(a.Pattern) > 200 || strings.ContainsAny(a.Pattern, "\n\r\x00") {
			return "", errors.New("pattern must be one line of at most 200 characters")
		}
		filter = " | grep -i -F -e " + host.Quote(a.Pattern)
	}
	tail := fmt.Sprintf(" | tail -n %d | cut -c1-%d", n, maxLine)
	// fetch is how many lines to read from a service or pod log: with a
	// pattern, the last 2000, so the filter does not search only the last n.
	fetch := n
	if a.Pattern != "" {
		fetch = 2000
	}
	var cmd string
	switch a.Check {
	case "status":
		// sudoers allows exactly "sensor status", with no arguments.
		cmd = ctl + " sensor status"
	case "deploy":
		// A deploy run starts with a debug line naming the command; every
		// line of that run carries the same id.
		f := "/system-logs/corelightctl.log"
		run := `grep -F "$id" ` + f
		cmd = `id=$(grep -F 'running command \"sensor deploy\"' ` + f + ` | tail -n 1 | grep -o 'id="[A-Za-z0-9]*"'); ` +
			`if [ -z "$id" ]; then echo 'no deploy run in corelightctl.log (it may have rotated: use check upgrade with file)'; else ` +
			`printf 'run %s started: ' "$id"; ` + run + ` | head -n 1 | cut -c1-15; ` +
			`if ` + run + ` | grep -q -F 'sensor deploy success'; then echo 'result: deploy succeeded'; ` +
			`elif ` + run + ` | grep -q -E 'level="(error|fatal)"'; then echo 'result: errors logged (the deploy failed or is retrying)'; ` +
			`else echo 'result: still running'; fi; ` +
			run + ` | grep -E 'level="(info|warning|error|fatal)"' | grep -v -F` + quoteEach(upgradeNoise) + filter + tail + `; fi`
	case "node":
		// kubelet shows whether the node itself is starved:
		// exec probes that time out and pods that take minutes to start.
		kl := "/system-logs/kubelet.log"
		src := func(f string) string {
			if a.Pattern != "" {
				return "grep -i -F -e " + host.Quote(a.Pattern) + " " + f
			}
			return "cat " + f
		}
		probe := `ExecSync cmd from runtime service failed.*DeadlineExceeded`
		cmd = `printf 'exec probe timeouts (kubelet): '; ` + src(kl) + ` | grep -c '` + probe + `'; ` +
			`echo 'latest at:'; ` + src(kl) + ` | grep '` + probe + `' | tail -n 3 | cut -c1-15; ` +
			`echo 'slowest pod start-ups (seconds, without image pulls):'; ` + src(kl) + ` | grep -o 'pod="[^"]*" podStartSLOduration=[0-9.]*' | sort -t= -k3 -g | tail -n 5; ` +
			`echo 'latest pod start-ups:'; ` + src(kl) + ` | grep 'Observed pod startup duration' | tail -n 5 | grep -o '^[A-Z][a-z][a-z] [ 0-9]* [0-9:]*\|pod="[^"]*" podStartSLOduration=[0-9.]*' | paste -d' ' - -`
	case "version":
		cmd = ctl + " version"
	case "upgrade":
		file := "corelightctl.log"
		if a.File != "" {
			if err := need("file", a.File, safeFile); err != nil {
				return "", err
			}
			file = a.File
		}
		cmd = "grep -E 'level=\"(info|warning|error)\"' " + host.Quote("/system-logs/"+file) +
			" | grep -v -F" + quoteEach(upgradeNoise) + filter + tail
	case "service_logs":
		if err := need("service", a.Service, safeName); err != nil {
			return "", err
		}
		cmd = ctl + " sensor logs --no-color -s " + host.Quote(a.Service)
		if a.Container != "" {
			cmd += " -c " + host.Quote(a.Container)
		}
		cmd += fmt.Sprintf(" -l %d", fetch) + filter + tail
	case "exporter_logs":
		if err := need("exporter", a.Exporter, safeName); err != nil {
			return "", err
		}
		cmd = ctl + " sensor logs --no-color -e " + host.Quote(a.Exporter) + fmt.Sprintf(" -l %d", fetch) + filter + tail
	case "pod_logs":
		if err := need("pod", a.Pod, safeName); err != nil {
			return "", err
		}
		ns := a.Namespace
		if ns == "" {
			ns = "corelight-sensor"
		}
		if ns != "corelight-sensor" && ns != "kube-system" {
			return "", fmt.Errorf("namespace %q: only corelight-sensor or kube-system", ns)
		}
		cmd = kubectl + " logs -n " + ns + " " + host.Quote(a.Pod)
		if a.Container != "" {
			cmd += " -c " + host.Quote(a.Container)
		}
		cmd += fmt.Sprintf(" --tail %d", fetch) + filter + tail
	case "system_logs":
		cmd = "ls -la /system-logs"
	case "system_log":
		if err := need("file", a.File, safeFile); err != nil {
			return "", err
		}
		cmd = "cat " + host.Quote("/system-logs/"+a.File) + filter + tail
	case "disk":
		cmd = "df -h"
	case "datastore":
		cmd = "printf 'Slow SQL warnings in k3s.log: '; grep -c 'Slow SQL' /system-logs/k3s.log; echo 'slowest:'; grep -o 'duration=[0-9.]*[a-z]*' /system-logs/k3s.log | sort -t= -k2 -g | tail -n 5; echo 'latest:'; grep 'Slow SQL' /system-logs/k3s.log | tail -n 3 | cut -c1-120"
	default:
		names := make([]string, 0, len(shellChecks))
		for k := range shellChecks {
			names = append(names, k)
		}
		sort.Strings(names)
		return "", fmt.Errorf("unknown check %q; one of: %s", a.Check, strings.Join(names, ", "))
	}
	return cmd + " 2>&1", nil
}

func quoteEach(ss []string) string {
	var b strings.Builder
	for _, s := range ss {
		b.WriteString(" -e " + host.Quote(s))
	}
	return b.String()
}

func registerSensorShell(s *mcp.Server, d *Deps) {
	f := false
	var desc []string
	for _, k := range []string{"status", "version", "deploy", "upgrade", "service_logs", "exporter_logs", "pod_logs", "system_logs", "system_log", "disk", "datastore", "node"} {
		desc = append(desc, k+": "+shellChecks[k])
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_sensor_shell",
		Description: "Read-only diagnostics on a sensor itself, for what Fleet Manager cannot show (logs, upgrade history, datastore latency). fleet-mcp logs in over SSH as diag-shell (its own key if installed, else the sensor-admin-password secret) and runs one fixed check; it never runs free-form commands and never changes the sensor. diag-shell has no root (root needs a Corelight Support escalation). " +
			"Use fm_sensor_diagnose first. The first connection to a sensor returns its SSH host key fingerprint: show it to the user and call again with host_key once they approve it. Checks: " + strings.Join(desc, "; ") + ".",
		Annotations: &mcp.ToolAnnotations{Title: "Sensor diagnostics shell", ReadOnlyHint: true, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a shellArgs) (*mcp.CallToolResult, any, error) {
		cmd, err := shellCommand(a)
		if err != nil {
			return nil, nil, err
		}
		c, err := d.conn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		sensor, err := d.findSensor(ctx, c, a.Sensor)
		if err != nil {
			return nil, nil, err
		}
		uid, name := fmt.Sprint(sensor["uid"]), fmt.Sprint(sensor["name"])
		sshHost := a.SensorHost
		if sshHost == "" {
			sshHost = sensorAddress(sensor)
		}
		if sshHost == "" {
			return nil, nil, fmt.Errorf("%s does not report %s's management address; give sensor_host", c.Name, name)
		}
		pins := d.sensorPins()
		scan := metrics.Step(ctx, "read the sensor's SSH host key")
		hk, err := sensorssh.ScanHostKey(ctx, sshHost, pins)
		scan()
		if err != nil {
			return nil, nil, err
		}
		switch {
		case hk.Changed:
			return nil, nil, fmt.Errorf("%s presents SSH host key %s, which differs from the one fleet-mcp pinned earlier; if the sensor was reinstalled, remove its line from %s", sshHost, hk.Fingerprint, pins.Path)
		case !hk.Known && a.HostKey != hk.Fingerprint:
			r, err := jsonResult(map[string]any{"sensor": name, "address": sshHost, "host_key": hk,
				"next": fmt.Sprintf("fleet-mcp has not connected to %s before. Show the user its SSH host key (%s %s) and, once they approve it, call again with host_key set to it; it is then pinned.", name, hk.Type, hk.Fingerprint)})
			return r, nil, err
		}
		login := d.sensorLogin(ctx, c, uid)
		if login.Method == "" {
			return nil, nil, errors.New("no way to log in to the sensor: install fleet-mcp's SSH key with fm_sensor_ssh_key, or the user stores the admin password in a terminal: " + secrets.Command("secret", "set", secrets.SensorPassword))
		}
		run := metrics.Step(ctx, "run the check on the sensor")
		out, err := sensorssh.Run(ctx, sshHost, login.Auth, hk.Fingerprint, cmd, pins, login.Auth.Password)
		run()
		res := map[string]any{"fleet": c.Name, "sensor": name, "address": sshHost, "check": a.Check, "login": login.Method, "output": out}
		var notes []string
		if login.Auth.Password != "" && strings.Contains(out, "[REDACTED]") {
			notes = append(notes, "the stored sensor password was masked in the output; if it is a common word, ordinary text was masked too")
		}
		// corelightctl sensor status exits 1 when a service has failed;
		// its report is still the result.
		if err != nil && a.Check == "status" && strings.Contains(out, "Corelight System Status") {
			res["exit"] = "corelightctl reported a failed service or error (exit status 1)"
			err = nil
		}
		if err != nil {
			res["error"] = err.Error()
		}
		r, jerr := jsonResult(res, notes...)
		if err != nil && r != nil {
			r.IsError = true
		}
		return r, nil, jerr
	})
}
