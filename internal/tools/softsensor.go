package tools

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleets"
	"github.com/jlagermann/fleet-mcp/internal/softsensor"
	"github.com/jlagermann/fleet-mcp/internal/spec"
)

// platformSoftware is how Fleet Manager names a Software Sensor in
// extendedinformation.status.platform.
const platformSoftware = "Software Sensor"

// sensorStatus returns the platform and the version a sensor reports.
func sensorStatus(s map[string]any) (platform, version string) {
	ext, _ := s["extendedinformation.status"].(map[string]any)
	if ext == nil {
		return "", ""
	}
	platform, _ = ext["platform"].(string)
	version, _ = ext["os.version"].(string)
	return platform, version
}

// maxWaitMinutes keeps a waiting call under MCP clients' idle limit
// (Claude Code drops a tool call silent for 1800 s) even when the client
// sends no progress token.
const maxWaitMinutes = 25

// progress reports each status read as MCP progress, when the client asked
// for progress, so the client does not drop the long call.
func progress(ctx context.Context, req *mcp.CallToolRequest) func(*softsensor.Status) {
	if req == nil || req.Session == nil || req.Params == nil {
		return nil
	}
	tok := req.Params.GetProgressToken()
	if tok == nil {
		return nil
	}
	start := time.Now()
	return func(st *softsensor.Status) {
		msg := "running"
		if n := len(st.Stages); n > 0 {
			msg = st.Stages[n-1]
		}
		_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: tok, Progress: time.Since(start).Seconds(), Message: msg})
	}
}

type softUpgradeArgs struct {
	target
	Sensor         string `json:"sensor" jsonschema:"Software Sensor uid or exact name"`
	SensorHost     string `json:"sensor_host,omitempty" jsonschema:"SSH address of the sensor host (default: the management address Fleet Manager reports)"`
	SSHUser        string `json:"ssh_user,omitempty" jsonschema:"SSH user on the sensor host with passwordless sudo (default: FLEET_MCP_SSH_USER or your ssh config)"`
	SSHPort        int    `json:"ssh_port,omitempty" jsonschema:"SSH port (default 22)"`
	Version        string `json:"version,omitempty" jsonschema:"corelight-sensor version or prefix, e.g. 29.2.2 (default: the newest in the repository that is not newer than the Fleet Manager)"`
	AllowDowngrade bool   `json:"allow_downgrade,omitempty" jsonschema:"allow installing an older version than the installed one"`
	Status         bool   `json:"status,omitempty" jsonschema:"only report the latest upgrade run on the host (read-only); use it to follow an upgrade that was still running"`
	WaitMinutes    int    `json:"wait_minutes,omitempty" jsonschema:"how long the confirmed call waits for the upgrade to finish before returning (default 20, max 25: MCP clients drop a call that is silent for 30 minutes); the upgrade keeps running on the host either way"`
	ConfirmToken   string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this upgrade's preview; when it matches, the upgrade starts"`
}

func registerSoftSensorUpgrade(s *mcp.Server, d *Deps) {
	t := true
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_softsensor_upgrade",
		Description: guideFirst("upgrade-software-sensor") + "Upgrade a Software Sensor (a sensor Fleet Manager lists with platform \"Software Sensor\"), which cannot update itself, over SSH on its Ubuntu host: apt-get install the corelightctl and corelight-sensor packages of one version from the Corelight sensor-stable repository, corelightctl sensor prepare, then corelightctl sensor deploy. " +
			"The preview checks the installed, running and available versions, that the target is not newer than the Fleet Manager, free space (download plus corelightctl's own deploy requirement), storage write latency, the repository and the host. The upgrade runs on the host as a systemd unit; the call waits wait_minutes, then status: true follows it. " +
			"Two steps: call without confirm_token for a preview; after the user approves, call again with the same arguments plus confirm_token.",
		Annotations: &mcp.ToolAnnotations{Title: "Upgrade Software Sensor", DestructiveHint: &t, OpenWorldHint: &t},
	}, func(ctx context.Context, req *mcp.CallToolRequest, a softUpgradeArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.conn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		sensor, err := d.findSensor(ctx, c, a.Sensor)
		if err != nil {
			return nil, nil, err
		}
		uid, name := fmt.Sprint(sensor["uid"]), fmt.Sprint(sensor["name"])
		platform, running := sensorStatus(sensor)
		if platform != platformSoftware {
			return nil, nil, fmt.Errorf("%s reports platform %q, not a Software Sensor; appliance and virtual sensors update themselves (see fm_sensor_action)", name, platform)
		}
		sshHost := a.SensorHost
		if sshHost == "" {
			sshHost = sensorAddress(sensor)
		}
		if sshHost == "" {
			return nil, nil, fmt.Errorf("%s does not report %s's management address; give sensor_host", c.Name, name)
		}
		r, err := d.runner(hostArgs{Host: sshHost, SSHUser: a.SSHUser, SSHPort: a.SSHPort})
		if err != nil {
			return nil, nil, err
		}
		p := &softsensor.Planner{R: r}

		if a.Status {
			st, err := p.Status(ctx)
			if err != nil {
				return nil, nil, err
			}
			out := softStatusOut(ctx, d, c, uid, name, st)
			res, err := jsonResult(out)
			return res, nil, err
		}

		fmVersion, err := spec.Version(ctx, c.Client)
		if err != nil {
			return nil, nil, fmt.Errorf("reading %s's version: %w", c.Name, err)
		}
		opts := softsensor.Options{Version: a.Version, AllowDowngrade: a.AllowDowngrade, MaxVersion: fmVersion}
		plan, err := p.Plan(ctx, opts, running)
		if err != nil {
			return nil, nil, err
		}
		token := ConfirmToken(sshHost, "fm_softsensor_upgrade", r.Name(), a.SSHPort, c.Name, uid, opts, plan.State())
		if a.ConfirmToken == "" {
			out := map[string]any{"preview": true, "fleet": c.Name, "fleet_version": fmVersion, "sensor": name, "uid": uid, "health": sensor["health.status"], "plan": plan}
			switch {
			case len(plan.Blockers) > 0:
				out["next"] = "Resolve the blockers first; nothing can be changed yet."
			case !plan.Ready():
				out["next"] = "Nothing to install."
			default:
				out["confirm_token"] = token
				out["next"] = fmt.Sprintf("Show the versions, steps and warnings to the user, and suggest a VM snapshot or host backup first. After the user approves, call fm_softsensor_upgrade again with the same arguments plus confirm_token (sensor %s, managed by %s).", name, c.Name)
			}
			res, err := jsonResult(out)
			return res, nil, err
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match these arguments or the sensor changed since the preview; preview again")
		}
		runErr := p.Start(ctx, plan)
		body := map[string]any{"sensor": name, "uid": uid, "from": plan.Installed, "to": plan.Target, "deploy_only": plan.DeployOnly}
		rec := audit.Record{Fleet: c.Name, User: r.Name(), Tool: "fm_softsensor_upgrade", Token: token, Body: body}
		var st *softsensor.Status
		if runErr == nil {
			wait := a.WaitMinutes
			if wait <= 0 {
				wait = 20
			}
			wait = min(wait, maxWaitMinutes)
			p.OnPoll = progress(ctx, req)
			st, runErr = p.Wait(ctx, time.Duration(wait)*time.Minute)
			if st != nil {
				body["result"] = st
			}
		}
		if runErr != nil {
			rec.Error = runErr.Error()
		}
		var notes []string
		if err := d.Audit.Write(rec); err != nil {
			notes = append(notes, "WARNING: audit log write failed: "+err.Error())
		}
		var out map[string]any
		if st != nil {
			out = softStatusOut(ctx, d, c, uid, name, st)
		} else {
			out = map[string]any{"fleet": c.Name, "sensor": name}
		}
		out["executed"] = runErr == nil
		out["from"], out["to"] = plan.Installed, plan.Target
		if runErr != nil {
			out["error"] = runErr.Error()
		}
		res, err := jsonResult(out, notes...)
		if res != nil && (runErr != nil || (st != nil && st.Result == softsensor.ResultFailed)) {
			res.IsError = true
		}
		return res, nil, err
	})
}

// softStatusOut describes an upgrade run with what Fleet Manager now
// reports for the sensor, and what to do next.
func softStatusOut(ctx context.Context, d *Deps, c *fleets.Conn, uid, name string, st *softsensor.Status) map[string]any {
	out := map[string]any{"fleet": c.Name, "sensor": name, "uid": uid, "run": st}
	if s, err := d.findSensor(ctx, c, uid); err == nil {
		_, v := sensorStatus(s)
		out["fleet_reports"] = map[string]any{"version": v, "health": s["health.status"], "connected": s["fleet.connected"]}
	}
	switch st.Result {
	case softsensor.ResultRunning:
		out["next"] = "The upgrade is still running on the host. Check again with status: true every few minutes; a deploy on slow storage can take 40 minutes or more."
	case softsensor.ResultDone:
		out["next"] = fmt.Sprintf("Check %s with fm_sensor_diagnose. Fleet Manager may take a few minutes to report the new version and health.", name)
	case softsensor.ResultRebootRequired:
		out["next"] = "corelightctl needs a reboot of the host before it can deploy. Ask the user to reboot it, then run fm_softsensor_upgrade again: the preview offers the deploy only."
	case softsensor.ResultFailed:
		out["next"] = "Follow fm_guide topic upgrade-software-sensor, section \"If it fails\". The full output is in /var/log/fleet-mcp-softsensor-upgrade.log and /var/log/corelightctl.log on the host."
	default:
		out["next"] = "No upgrade has run on this host."
	}
	return out
}
