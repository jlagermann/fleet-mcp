package tools

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/metrics"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
	"github.com/jlagermann/fleet-mcp/internal/sensorssh"
)

// fm_sensor_action runs one of a few fixed changing commands on a sensor
// as diag-shell, through corelight-client (which runs them with the
// sensor's admin rights). factory-reset, shutdown, flush-data and
// "corelightctl sensor stop" are never offered.

// sensorAction is one changing command.
type sensorAction struct {
	cmd    string // corelight-client arguments
	dryRun bool   // the preview runs it with --dry-run
	what   string
}

var sensorActions = map[string]sensorAction{
	"reboot": {cmd: "system reboot", dryRun: true,
		what: "reboots the sensor now. Capture and export stop until it is back; at boot the sensor reruns its NGS (container platform) deploy, which takes about 15 minutes and finishes an NGS upgrade that failed earlier"},
	"apply_updates": {cmd: "updates apply",
		what: "applies every pending software update now, whatever the policy's automatic update settings say; an update that needs a reboot reboots the sensor at the end"},
	"revert_update": {cmd: "system revert-update", dryRun: true,
		what: "reverts the sensor to its state before the most recent software update, then reboots it; changes made since that update are lost"},
}

const clientCmd = "corelight-client --noblock "

var updatingTrue = regexp.MustCompile(`(?m)^\s*updating\s+True\s*$`)

type sensorActionArgs struct {
	target
	Sensor       string `json:"sensor" jsonschema:"sensor uid or exact name"`
	SensorHost   string `json:"sensor_host,omitempty" jsonschema:"SSH address of the sensor if Fleet Manager does not report its management address"`
	Action       string `json:"action" jsonschema:"reboot, apply_updates or revert_update"`
	HostKey      string `json:"host_key,omitempty" jsonschema:"the sensor's SSH host key fingerprint the user approved; needed only the first time fleet-mcp connects to a sensor"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this action's preview; when it matches, the action runs"`
}

// actionBlockers reads the preview's update state and says why the action
// cannot run now.
func actionBlockers(action, updating, list string) []string {
	var b []string
	if updatingTrue.MatchString(updating) {
		b = append(b, "a software update is in progress on the sensor (corelight-client updates updating); wait for it to finish")
	}
	if action == "apply_updates" && strings.Contains(list, "No entries") {
		b = append(b, "no software updates are pending (corelight-client updates list shows none); applying would do nothing. An NGS deploy that failed after an update is retried by rebooting, not by applying updates")
	}
	return b
}

func registerSensorAction(s *mcp.Server, d *Deps) {
	t, f := true, false
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_sensor_action",
		Description: guideFirst("troubleshoot-sensor") + "Run one fixed action on a sensor itself, over SSH as diag-shell through corelight-client: reboot (reboot the sensor; at boot it reruns its NGS deploy, the usual fix for an NGS upgrade that failed on a job timeout), apply_updates (apply pending software updates now; refused when none are pending) or revert_update (go back to the state before the last software update; only when the user asks for it by name). " +
			"Fleet Manager's own update trigger only pushes policy; it never upgrades software. Nothing else can be run: no factory reset, shutdown, flush-data or service stop. Use fm_sensor_diagnose and fm_sensor_shell first. " +
			"Two steps: call without confirm_token for a preview (the sensor's update state and, for reboot and revert_update, a --dry-run of the command); after the user approves, call again with the same arguments plus confirm_token. Afterwards follow the deploy with fm_sensor_shell check deploy every few minutes (the sensor does not answer SSH for the first minutes after a reboot).",
		Annotations: &mcp.ToolAnnotations{Title: "Sensor action", DestructiveHint: &t, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a sensorActionArgs) (*mcp.CallToolResult, any, error) {
		act, ok := sensorActions[a.Action]
		if !ok {
			return nil, nil, fmt.Errorf("unknown action %q; one of: reboot, apply_updates, revert_update", a.Action)
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
		run := func(step, cmd string) (string, error) {
			defer metrics.Step(ctx, "%s", step)()
			return sensorssh.Run(ctx, sshHost, login.Auth, hk.Fingerprint, cmd+" 2>&1", pins, login.Auth.Password)
		}
		token := ConfirmToken(sshHost, "fm_sensor_action", uid, a.Action, hk.Fingerprint)

		if a.ConfirmToken == "" {
			updating, uerr := run("read the update state", clientCmd+"updates updating")
			list, lerr := run("list pending updates", clientCmd+"updates list")
			if uerr != nil || lerr != nil {
				return nil, nil, fmt.Errorf("reading the sensor's update state failed: %v %v", uerr, lerr)
			}
			out := map[string]any{
				"preview": true, "fleet": c.Name, "sensor": name, "uid": uid, "address": sshHost,
				"health": sensor["health.status"], "action": a.Action, "command": clientCmd + act.cmd, "effect": act.what,
				"update_state": strings.TrimSpace(updating), "pending_updates": strings.TrimSpace(list),
				"login": login.Method,
			}
			blockers := actionBlockers(a.Action, updating, list)
			if act.dryRun && len(blockers) == 0 {
				dry, err := run("dry-run the action", clientCmd+act.cmd+" --dry-run")
				// corelight-client prints the same text for a dry run as for
				// a real one ("System reboot initiated").
				out["dry_run"] = map[string]any{"output": strings.TrimSpace(dry),
					"note": "--dry-run: nothing was done; corelight-client words a dry run like a real one"}
				if err != nil {
					blockers = append(blockers, "the --dry-run failed: "+err.Error())
				}
			}
			out["ready"] = len(blockers) == 0
			if len(blockers) > 0 {
				out["blockers"] = blockers
				out["next"] = "Tell the user why the action cannot run now; nothing was changed."
			} else {
				out["confirm_token"] = token
				next := fmt.Sprintf("Show the user what %s does to %s (managed by %s). After they approve, call fm_sensor_action again with the same arguments plus confirm_token.", a.Action, name, c.Name)
				if a.Action == "revert_update" {
					next += " Run revert_update only if the user asked for a revert by name; otherwise suggest reboot."
				}
				out["next"] = next
			}
			r, err := jsonResult(out)
			return r, nil, err
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match these arguments or the sensor's host key; preview again")
		}
		output, runErr := run("run the action on the sensor", clientCmd+act.cmd)
		out := map[string]any{"executed": true, "fleet": c.Name, "sensor": name, "uid": uid, "action": a.Action, "output": strings.TrimSpace(output)}
		rec := audit.Record{Fleet: c.Name, User: sensorssh.User + "@" + sshHost, Tool: "fm_sensor_action", Token: token,
			Body: map[string]any{"sensor": name, "uid": uid, "action": a.Action, "command": clientCmd + act.cmd}, Response: output}
		if runErr != nil {
			rec.Error = runErr.Error()
			out["error"] = runErr.Error()
		} else {
			out["next"] = fmt.Sprintf("Follow the result with fm_sensor_shell check deploy on %s every few minutes until it reports success or failure (the sensor does not answer SSH for the first minutes after a reboot), then fm_sensor_diagnose.", name)
		}
		var notes []string
		if err := d.Audit.Write(rec); err != nil {
			notes = append(notes, "WARNING: audit log write failed: "+err.Error())
		}
		r, err := jsonResult(out, notes...)
		if runErr != nil && r != nil {
			r.IsError = true
		}
		return r, nil, err
	})
}
