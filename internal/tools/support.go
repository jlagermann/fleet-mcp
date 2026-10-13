package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleets"
	"github.com/jlagermann/fleet-mcp/internal/metrics"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
	"github.com/jlagermann/fleet-mcp/internal/sensorssh"
)

// fm_sensor_support_access turns the sensor's "Enable Corelight remote
// interface" (remote.management) on or off, so Corelight Support can
// reach the sensor. It works through Fleet Manager (a per-sensor exception)
// or directly on the sensor (corelight-client as diag-shell). The direct
// route matters: when Fleet Manager has a large policy change or several
// changes queued for the sensor, or the sensor is unhealthy, a change sent
// through Fleet Manager may never be applied. In the worst cases the
// sensor has to be removed from Fleet Manager before the remote interface
// can be turned on; that is left to the user.

const (
	remoteMgmt = "remote.management"
	// bigDelta is how many differing settings between the sensor and its
	// desired configuration count as a large queued change; a few
	// differences are normal.
	bigDelta = 10
)

type supportArgs struct {
	target
	Sensor       string `json:"sensor" jsonschema:"sensor uid or exact name"`
	SensorHost   string `json:"sensor_host,omitempty" jsonschema:"SSH address of the sensor if Fleet Manager does not report its management address"`
	State        string `json:"state" jsonschema:"on (Corelight Support may reach the sensor) or off"`
	Method       string `json:"method,omitempty" jsonschema:"fleet (a per-sensor exception through Fleet Manager), sensor (corelight-client on the sensor as diag-shell) or auto (default: the preview picks one and says why)"`
	HostKey      string `json:"host_key,omitempty" jsonschema:"the sensor's SSH host key fingerprint the user approved; needed only the first time fleet-mcp connects to a sensor"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this change's preview; when it matches, the change is made"`
}

// fleetRouteProblems says why a change through Fleet Manager may not reach
// the sensor; empty means Fleet Manager should apply it.
func fleetRouteProblems(c *fleets.Conn, s map[string]any, delta map[string]any) []string {
	var p []string
	if c.ReadOnly {
		p = append(p, fmt.Sprintf("Fleet Manager %s is read-only for fleet-mcp", c.Name))
	}
	if s["fleet.connected"] != true {
		p = append(p, "the sensor is not connected to Fleet Manager, so it cannot receive the change")
	}
	if st := str(s["configuration.apply.status"]); st != "" && !strings.EqualFold(st, "success") && !strings.EqualFold(st, "unknown") {
		p = append(p, fmt.Sprintf("the last configuration apply on the sensor is %s, so a new change may queue behind it", st))
	}
	if len(delta) > bigDelta {
		p = append(p, fmt.Sprintf("%d settings differ between the sensor and what Fleet Manager wants it to have (a large or queued policy change), so a new change may not get through", len(delta)))
	}
	return p
}

func registerSupportAccess(s *mcp.Server, d *Deps) {
	t, f := true, false
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_sensor_support_access",
		Description: "Turn the sensor's \"Enable Corelight remote interface\" (remote.management) on or off, so Corelight Support can reach the sensor remotely; Support also needs the sensor's Device UID, which the preview shows. It needs Corelight Cloud Services (remote.enable) on. Turn it on only when Support asks and off again when they are done. " +
			"Two routes: fleet sets a per-sensor exception through Fleet Manager (refused on read-only Fleet Managers); sensor runs corelight-client configuration update on the sensor itself as diag-shell, which works when Fleet Manager has a large policy change or several changes queued for the sensor, or the sensor is unhealthy, and a change through Fleet Manager would not get through. auto (default) picks fleet when nothing stands in its way, else sensor. If neither works, the sensor may have to be removed from Fleet Manager first; tell the user, never do it. " +
			"Two steps: call without confirm_token for a preview; after the user approves, call again with the same arguments plus confirm_token. The result reads the setting back from the sensor.",
		Annotations: &mcp.ToolAnnotations{Title: "Corelight Support remote access", DestructiveHint: &f, OpenWorldHint: &t},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a supportArgs) (*mcp.CallToolResult, any, error) {
		var want bool
		switch a.State {
		case "on":
			want = true
		case "off":
		default:
			return nil, nil, errors.New("state must be on or off")
		}
		method := a.Method
		if method == "" {
			method = "auto"
		}
		if method != "auto" && method != "fleet" && method != "sensor" {
			return nil, nil, errors.New("method must be auto, fleet or sensor")
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

		// What Fleet Manager knows: the running values, the queued
		// difference, and whether this sensor already has an exception.
		live, delta := map[string]any{}, map[string]any{}
		if v, err := d.getDecoded(ctx, c, pathCatalog+"/"+uid, nil); err == nil {
			if m, ok := v.(map[string]any); ok {
				live, _ = m["configuration.live"].(map[string]any)
				delta, _ = m["configuration.delta"].(map[string]any)
			}
		}
		exc := map[string]any{}
		if v, err := d.getDecoded(ctx, c, sensorAPI(uid, "/configuration/exceptions"), nil); err == nil {
			exc, _ = v.(map[string]any)
		}
		_, hasExc := exc[remoteMgmt]
		problems := fleetRouteProblems(c, sensor, delta)
		if method == "auto" {
			method = "fleet"
			if len(problems) > 0 {
				method = "sensor"
			}
		}

		// The sensor route needs an SSH login and an approved host key.
		var (
			sshHost string
			hk      *sensorssh.HostKey
			fp      string // the host key fingerprint; empty on the fleet route
			login   sensorLogin
			pins    = d.sensorPins()
		)
		if method == "sensor" {
			sshHost = a.SensorHost
			if sshHost == "" {
				sshHost = sensorAddress(sensor)
			}
			if sshHost == "" {
				return nil, nil, fmt.Errorf("%s does not report %s's management address; give sensor_host", c.Name, name)
			}
			scan := metrics.Step(ctx, "read the sensor's SSH host key")
			hk, err = sensorssh.ScanHostKey(ctx, sshHost, pins)
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
			fp = hk.Fingerprint
			login = d.sensorLogin(ctx, c, uid)
			if login.Method == "" {
				return nil, nil, errors.New("no way to log in to the sensor: install fleet-mcp's SSH key with fm_sensor_ssh_key, or the user stores the admin password in a terminal: " + secrets.Command("secret", "set", secrets.SensorPassword))
			}
		}
		run := func(step, cmd string) (string, error) {
			defer metrics.Step(ctx, "%s", step)()
			return sensorssh.Run(ctx, sshHost, login.Auth, fp, cmd+" 2>&1", pins, login.Auth.Password)
		}
		token := ConfirmToken(c.Client.Host(), "fm_sensor_support_access", uid, a.State, method, fp)

		if a.ConfirmToken == "" {
			out := map[string]any{
				"preview": true, "fleet": c.Name, "sensor": name, "device_uid": uid, "health": sensor["health.status"],
				"connected": sensor["fleet.connected"], "state": a.State, "method": method,
				"fleet_view": map[string]any{"remote.enable": live["remote.enable"], remoteMgmt: live[remoteMgmt],
					"exception_set": hasExc, "settings_differing_from_desired": len(delta), "last_apply": sensor["configuration.apply.status"]},
			}
			var blockers, warnings []string
			if method == "fleet" && len(problems) > 0 {
				blockers = append(blockers, problems...)
				blockers = append(blockers, "use method sensor to change it on the sensor directly")
			} else if len(problems) > 0 {
				out["why_sensor"] = problems
			}
			if method == "sensor" {
				cur, err := run("read remote.* on the sensor", clientCmd+"configuration get --prefix remote. -j")
				if err != nil {
					blockers = append(blockers, "reading the sensor's settings failed: "+err.Error()+" (if SSH does not work either, the sensor may have to be removed from Fleet Manager before the remote interface can be turned on)")
				} else {
					out["sensor_view"] = parseRemote(cur)
				}
				out["command"] = fmt.Sprintf("%sconfiguration update --%s %v", clientCmd, remoteMgmt, want)
				warnings = append(warnings, "Fleet Manager did not make this change: it may show it as a difference or an exception on the sensor, and a later policy apply can set it back. Turn it off the same way when Support is done.")
			} else {
				if want {
					out["request"] = map[string]any{"method": "PUT", "path": sensorAPI(uid, "/configuration"), "body": map[string]any{remoteMgmt: true}}
				} else if hasExc {
					out["request"] = map[string]any{"method": "DELETE", "path": pathCatalog + "/" + uid + "/exceptions", "body": []string{remoteMgmt}, "note": "removes the exception, so the sensor takes the policy value again"}
				} else {
					out["request"] = map[string]any{"method": "PUT", "path": sensorAPI(uid, "/configuration"), "body": map[string]any{remoteMgmt: false}}
				}
			}
			if want && live["remote.enable"] == false {
				warnings = append(warnings, "Corelight Cloud Services (remote.enable) is off on the sensor; the remote interface needs it, so Support still cannot connect until it is on")
			}
			if want {
				warnings = append(warnings, "Give Support the Device UID "+uid+". Turn the remote interface off again once they are done.")
			}
			out["warnings"] = warnings
			out["ready"] = len(blockers) == 0
			if len(blockers) > 0 {
				out["blockers"] = blockers
				out["next"] = "Tell the user why this route cannot be used; nothing was changed."
			} else {
				out["confirm_token"] = token
				out["next"] = fmt.Sprintf("Show the user the change (turn the remote interface %s on %s, via %s; the Device UID and the warnings). After they approve, call fm_sensor_support_access again with the same arguments plus confirm_token.", a.State, name, method)
			}
			r, err := jsonResult(out)
			return r, nil, err
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match these arguments or the sensor's host key; preview again")
		}

		out := map[string]any{"executed": true, "fleet": c.Name, "sensor": name, "device_uid": uid, "state": a.State, "method": method}
		rec := audit.Record{Fleet: c.Name, Tool: "fm_sensor_support_access", Token: token,
			Body: map[string]any{"sensor": name, "uid": uid, remoteMgmt: want, "method": method}}
		var runErr error
		if method == "sensor" {
			rec.User = sensorssh.User + "@" + sshHost
			var o string
			o, runErr = run("change the setting on the sensor", fmt.Sprintf("%sconfiguration update --%s %v", clientCmd, remoteMgmt, want))
			rec.Response = o
			out["output"] = strings.TrimSpace(o)
			if runErr == nil {
				if cur, err := run("read it back", clientCmd+"configuration get --prefix remote. -j"); err == nil {
					out["sensor_view"] = parseRemote(cur)
				}
			}
		} else {
			wc, err := d.writeConn(a.Fleet)
			if err != nil {
				return nil, nil, err
			}
			rec.User = wc.Username
			var (
				m    = "PUT"
				p    = sensorAPI(uid, "/configuration")
				body any
			)
			body = map[string]any{remoteMgmt: want}
			if !want && hasExc {
				m, p, body = "DELETE", pathCatalog+"/"+uid+"/exceptions", []string{remoteMgmt}
			}
			b, _ := json.Marshal(body)
			rec.Method, rec.Path = m, p
			resp, err := wc.Client.Do(ctx, m, p, nil, b, "application/json")
			if resp != nil {
				rec.Status = resp.Status
				rec.Response = excerptRedacted(resp.Body)
				out["status"] = resp.Status
			}
			runErr = err
			if err == nil {
				out["fleet_view"] = d.waitForSetting(ctx, c, uid, want, 2*time.Minute)
			}
		}
		if runErr != nil {
			rec.Error = runErr.Error()
			out["error"] = runErr.Error()
		} else if want {
			out["next"] = "Give Corelight Support the Device UID " + uid + ". When they are done, call fm_sensor_support_access with state off, the same way."
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

// sensorAPI is the Fleet Manager path proxied to a sensor's own API.
func sensorAPI(uid, p string) string { return "/fleet/v1/sensor/instance/" + uid + "/api" + p }

// parseRemote reads corelight-client configuration get -j output.
func parseRemote(out string) any {
	var v any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &v); err == nil {
		return v
	}
	return strings.TrimSpace(out)
}

// waitForSetting polls Fleet Manager until the sensor reports
// remote.management as want, or limit passes.
func (d *Deps) waitForSetting(ctx context.Context, c *fleets.Conn, uid string, want bool, limit time.Duration) map[string]any {
	defer metrics.Step(ctx, "wait for the sensor to apply the change")()
	deadline := time.Now().Add(limit)
	for {
		if v, err := d.getDecoded(ctx, c, pathCatalog+"/"+uid, nil); err == nil {
			if m, ok := v.(map[string]any); ok {
				live, _ := m["configuration.live"].(map[string]any)
				if live[remoteMgmt] == want {
					return map[string]any{remoteMgmt: want, "applied": true}
				}
				if time.Now().After(deadline) {
					return map[string]any{remoteMgmt: live[remoteMgmt], "applied": false,
						"note": "the sensor has not applied it yet; if it stays this way, use method sensor"}
				}
			}
		}
		select {
		case <-ctx.Done():
			return map[string]any{"applied": false, "note": ctx.Err().Error()}
		case <-time.After(10 * time.Second):
		}
	}
}
