package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleets"
	"github.com/jlagermann/fleet-mcp/internal/host"
	"github.com/jlagermann/fleet-mcp/internal/metrics"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
	"github.com/jlagermann/fleet-mcp/internal/sensorssh"
)

// fleetPort is where sensors connect to Fleet Manager.
const fleetPort = "1443"

type sensorMoveArgs struct {
	target
	Sensor        string `json:"sensor" jsonschema:"sensor uid or name on the source Fleet Manager (fleet)"`
	TargetFleet   string `json:"target_fleet" jsonschema:"Fleet Manager to move the sensor to (see fm_fleets)"`
	SensorHost    string `json:"sensor_host,omitempty" jsonschema:"sensor management address for SSH (default: the address the source Fleet Manager reports)"`
	TargetAddress string `json:"target_address,omitempty" jsonschema:"host:port the sensor uses to reach the target Fleet Manager (default: the host in its URL, port 1443)"`
	ConfirmToken  string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this move's preview; when it matches, the move runs"`
}

func (d *Deps) sensorPins() sensorssh.Pins {
	return sensorssh.Pins{Path: filepath.Join(d.Secrets.Dir(), "sensor_known_hosts")}
}

// targetAddress is where a sensor reaches Fleet Manager c.
func targetAddress(c *fleets.Conn, override string) (string, error) {
	if override != "" {
		if _, _, err := net.SplitHostPort(override); err != nil {
			return net.JoinHostPort(override, fleetPort), nil
		}
		return override, nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("cannot tell the address of %s from %q; give target_address", c.Name, c.URL)
	}
	return net.JoinHostPort(u.Hostname(), fleetPort), nil
}

// findSensor returns the catalog record of a sensor (uid or name).
func (d *Deps) findSensor(ctx context.Context, c *fleets.Conn, ref string) (map[string]any, error) {
	uid, err := d.resolveSensor(ctx, c, ref)
	if err != nil {
		return nil, err
	}
	cat, err := d.catalog(ctx, c)
	if err != nil {
		return nil, err
	}
	for _, s := range cat {
		if fmt.Sprint(s["uid"]) == uid {
			return s, nil
		}
	}
	return nil, fmt.Errorf("sensor %s is not on %s", ref, c.Name)
}

func sensorAddress(s map[string]any) string {
	ext, _ := s["extendedinformation.status"].(map[string]any)
	if ext == nil {
		return ""
	}
	if v, _ := ext["network.address.v4"].(string); v != "" {
		return v
	}
	v, _ := ext["network.address.dns"].(string)
	return v
}

func registerSensorWrite(s *mcp.Server, d *Deps) {
	t, f := true, false
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_sensor_move",
		Description: "Move a sensor from one Fleet Manager (fleet) to another (target_fleet): fleet-mcp logs in to the sensor over SSH as diag-shell (password: the sensor-admin-password secret) and runs corelight-client configuration update in three steps: fleet.enable=false (so the current Fleet Manager cannot put its fleet.server_sslname back), then the target's address and community string with fleet.server_sslname cleared (it comes from each Fleet Manager's license), then fleet.enable=true. " +
			"The sensor keeps its configuration: it appears on the target in the UNASSIGNED group and only takes a new configuration when it is put in a sensor group with a policy. Its entry on the source Fleet Manager goes offline. " +
			"Two steps: call without confirm_token for a preview (sensor, addresses, SSH host key fingerprint, which secrets are present); after the user approves, call again with the same arguments plus confirm_token.",
		Annotations: &mcp.ToolAnnotations{Title: "Move sensor", DestructiveHint: &t, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a sensorMoveArgs) (*mcp.CallToolResult, any, error) {
		src, err := d.conn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		tgt, err := d.conn(a.TargetFleet)
		if err != nil {
			return nil, nil, err
		}
		if src.Name == tgt.Name {
			return nil, nil, errors.New("the sensor is already on that Fleet Manager")
		}
		sensor, err := d.findSensor(ctx, src, a.Sensor)
		if err != nil {
			return nil, nil, err
		}
		uid, name := fmt.Sprint(sensor["uid"]), fmt.Sprint(sensor["name"])
		sshHost := a.SensorHost
		if sshHost == "" {
			sshHost = sensorAddress(sensor)
		}
		if sshHost == "" {
			return nil, nil, fmt.Errorf("%s does not report %s's management address; give sensor_host", src.Name, name)
		}
		addr, err := targetAddress(tgt, a.TargetAddress)
		if err != nil {
			return nil, nil, err
		}
		pins := d.sensorPins()
		scan := metrics.Step(ctx, "read the sensor's SSH host key")
		hk, err := sensorssh.ScanHostKey(ctx, sshHost, pins)
		scan()
		if err != nil {
			return nil, nil, err
		}
		if hk.Changed {
			return nil, nil, fmt.Errorf("%s presents SSH host key %s, which differs from the one fleet-mcp pinned earlier; if the sensor was reinstalled, remove its line from %s", sshHost, hk.Fingerprint, pins.Path)
		}
		login := d.sensorLogin(ctx, src, uid)
		_, csErr := d.Secrets.GetString(tgt.Name, secrets.CommunityString)
		token := ConfirmToken(sshHost, "fm_sensor_move", uid, src.Name, tgt.Name, addr, hk.Fingerprint)

		if a.ConfirmToken == "" {
			var blockers []string
			if login.Method == "" {
				blockers = append(blockers, "no way to log in to the sensor: install fleet-mcp's SSH key with fm_sensor_ssh_key, or the user stores the admin password in a terminal: fleet-mcp secret set "+secrets.SensorPassword)
			}
			if csErr != nil {
				blockers = append(blockers, fmt.Sprintf("%s's community string is not stored; the user runs in a terminal: fleet-mcp secret set %s -host %s", tgt.Name, secrets.CommunityString, tgt.Name))
			}
			// A sensor new to the target lands in UNASSIGNED with no
			// policy; one that was there before rejoins its old group.
			toGroup, toPolicy, after := any("UNASSIGNED"), any("none"),
				fmt.Sprintf("%s keeps its configuration, appears on %s in UNASSIGNED, and goes offline on %s.", name, tgt.Name, src.Name)
			if prev, err := d.findSensor(ctx, tgt, uid); err == nil {
				toGroup, toPolicy = prev["group.name"], prev["policy.name"]
				if toPolicy == nil || toPolicy == "" {
					toPolicy = "none"
				}
				after = fmt.Sprintf("%s was on %s before and rejoins group %v there (policy %v): it takes that policy's configuration if the group has one. It goes offline on %s.", name, tgt.Name, toGroup, toPolicy, src.Name)
			}
			out := map[string]any{
				"preview": true, "sensor": name, "uid": uid, "health": sensor["health.status"],
				"from":            map[string]any{"fleet": src.Name, "group": sensor["group.name"], "policy": sensor["policy.name"]},
				"to":              map[string]any{"fleet": tgt.Name, "group": toGroup, "policy": toPolicy},
				"ssh":             map[string]any{"host": sshHost, "user": sensorssh.User, "host_key": hk, "login": login.Method},
				"sensor_settings": map[string]any{"fleet.server": addr, "fleet.community_string": "(" + tgt.Name + "'s community string)", "fleet.server_sslname": ""},
				"after":           after,
				"ready":           len(blockers) == 0,
			}
			if len(blockers) > 0 {
				out["blockers"] = blockers
				out["next"] = "Have the user store the missing secrets at the hidden prompts, then preview again."
			} else {
				out["confirm_token"] = token
				next := fmt.Sprintf("Show the move to the user. After they approve moving %s to %s, call fm_sensor_move again with the same arguments plus confirm_token.", name, tgt.Name)
				if !hk.Known {
					next += " This is the first SSH contact with the sensor: ask the user to confirm the host key fingerprint " + hk.Fingerprint + "; it is pinned when the move runs."
				}
				out["next"] = next
			}
			r, err := jsonResult(out)
			return r, nil, err
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match these arguments or the sensor's host key; preview again")
		}
		if login.Method == "" {
			return nil, nil, errors.New("no SSH key or password to log in to the sensor with; preview again")
		}
		if csErr != nil {
			return nil, nil, csErr
		}
		cs, _ := d.Secrets.GetString(tgt.Name, secrets.CommunityString)
		output, runErr := moveSteps(ctx, sshHost, login.Auth, hk.Fingerprint, pins, cs, addr, stepPause)

		out := map[string]any{"executed": true, "sensor": name, "uid": uid, "from": src.Name, "to": tgt.Name, "output": output}
		if runErr == nil {
			out["on_target"] = d.waitForSensor(ctx, tgt, uid, 3*time.Minute)
		}
		rec := audit.Record{Fleet: tgt.Name, User: sensorssh.User + "@" + sshHost, Tool: "fm_sensor_move", Token: token,
			Body: map[string]any{"sensor": name, "uid": uid, "from": src.Name, "to": tgt.Name, "fleet.server": addr}, Response: output}
		if runErr != nil {
			rec.Error = runErr.Error()
			out["error"] = runErr.Error()
		}
		auditErr := d.Audit.Write(rec)
		var notes []string
		if auditErr != nil {
			notes = append(notes, "WARNING: audit log write failed: "+auditErr.Error())
		}
		r, err := jsonResult(out, notes...)
		if runErr != nil && r != nil {
			r.IsError = true
		}
		return r, nil, err
	})
}

// waitForSensor polls the target's catalog until the sensor appears.
func (d *Deps) waitForSensor(ctx context.Context, c *fleets.Conn, uid string, limit time.Duration) map[string]any {
	defer metrics.Step(ctx, "wait for the sensor to appear on %s", c.Name)()
	deadline := time.Now().Add(limit)
	for {
		if cat, err := d.catalog(ctx, c); err == nil {
			for _, s := range cat {
				if fmt.Sprint(s["uid"]) == uid {
					return map[string]any{"present": true, "group": s["group.name"], "health": s["health.status"], "connection": s["connection.status"]}
				}
			}
		}
		if time.Now().After(deadline) {
			return map[string]any{"present": false, "note": fmt.Sprintf("not on %s after %s; check fm_sensors_list again shortly", c.Name, limit)}
		}
		select {
		case <-ctx.Done():
			return map[string]any{"present": false, "note": ctx.Err().Error()}
		case <-time.After(10 * time.Second):
		}
	}
}

// stepPause lets the sensor apply each configuration change; corelight-
// client returns while the change is still in progress.
var stepPause = 30 * time.Second

// moveSteps re-points a sensor in three steps. Disconnecting first matters:
// fleet.server_sslname comes from the Fleet Manager's license and the
// connected Fleet Manager would put its own value back. With fleet
// disabled, the cleared value stays cleared until the sensor connects to
// the new Fleet Manager, which then sets its own.
func moveSteps(ctx context.Context, sshHost string, auth sensorssh.Auth, fingerprint string, pins sensorssh.Pins, cs, addr string, pause time.Duration) (string, error) {
	steps := []struct{ label, cmd string }{
		{"disconnect from the current Fleet Manager", "corelight-client configuration update --fleet.enable=false"},
		{"point at the new Fleet Manager", "corelight-client configuration update --fleet.community_string=" + host.Quote(cs) +
			" --fleet.server=" + host.Quote(addr) + " --fleet.server_sslname=''"},
		{"connect to the new Fleet Manager", "corelight-client configuration update --fleet.enable=true"},
	}
	var log strings.Builder
	for i, s := range steps {
		if i > 0 {
			waited := metrics.Step(ctx, "wait %s for the sensor to apply the change", pause)
			select {
			case <-ctx.Done():
				return log.String(), ctx.Err()
			case <-time.After(pause):
			}
			waited()
		}
		fmt.Fprintf(&log, "step %d: %s\n", i+1, s.label)
		stepDone := metrics.Step(ctx, "SSH step %d: %s", i+1, s.label)
		out, err := sensorssh.Run(ctx, sshHost, auth, fingerprint, s.cmd, pins, cs, auth.Password)
		stepDone()
		log.WriteString(out)
		if err != nil {
			return log.String(), fmt.Errorf("step %d (%s): %w", i+1, s.label, err)
		}
	}
	return log.String(), nil
}

// sensorAdminKey is the per-sensor setting that authorizes an SSH key for
// the admin and diag-shell users.
const sensorAdminKey = "security.user.admin.ssh_public_key"

// sensorLogin is how fleet-mcp will log in to a sensor.
type sensorLogin struct {
	Auth   sensorssh.Auth
	Method string // "key", "password", "key or password", or "" (none)
}

func (d *Deps) sensorKeyPath() string {
	p, _ := d.Secrets.Path("", secrets.SensorSSHKey)
	return p
}

// keyBody is the type and base64 of an authorized-key line, without the
// comment.
func keyBody(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 {
		return ""
	}
	return f[0] + " " + f[1]
}

// installedKey reads the sensor's admin SSH key through its Fleet Manager.
func (d *Deps) installedKey(ctx context.Context, c *fleets.Conn, uid string) (string, error) {
	var cfg map[string]any
	if err := c.Client.GetJSON(ctx, "/fleet/v1/sensor/instance/"+uid+"/api/configuration", nil, &cfg); err != nil {
		return "", err
	}
	v, _ := cfg[sensorAdminKey].(string)
	return strings.TrimSpace(v), nil
}

// sensorLogin prefers fleet-mcp's key when the sensor has it installed and
// keeps the admin password, if stored, as the fallback.
func (d *Deps) sensorLogin(ctx context.Context, c *fleets.Conn, uid string) sensorLogin {
	var l sensorLogin
	if pw, err := d.Secrets.GetString("", secrets.SensorPassword); err == nil {
		l.Auth.Password, l.Method = pw, "password"
	}
	pub, err := sensorssh.PublicKey(d.sensorKeyPath())
	if err != nil {
		return l
	}
	if have, err := d.installedKey(ctx, c, uid); err == nil && keyBody(have) == keyBody(pub) {
		l.Auth.KeyPath = d.sensorKeyPath()
		l.Method = "key"
		if l.Auth.Password != "" {
			l.Method = "key or password"
		}
	}
	return l
}

func registerSensorKeyWrite(s *mcp.Server, d *Deps) {
	f := false
	type keyArgs struct {
		target
		Sensor       string `json:"sensor" jsonschema:"sensor uid or name on this Fleet Manager"`
		Replace      bool   `json:"replace,omitempty" jsonschema:"replace a different admin SSH key already on the sensor (the sensor holds only one)"`
		ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this change's preview"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_sensor_ssh_key",
		Description: "Install fleet-mcp's own SSH public key on a sensor, as that sensor's individual setting " + sensorAdminKey + " on its Fleet Manager, so fleet-mcp can log in as diag-shell (e.g. for fm_sensor_move) without the admin password. The key pair is created on first use and the private key stays in fleet-mcp's secret store. " +
			"The sensor holds a single admin key: a different key already set is only replaced with replace: true. Two steps: preview, then confirm_token after the user approves.",
		Annotations: &mcp.ToolAnnotations{Title: "Install SSH key on sensor", DestructiveHint: &f, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a keyArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.writeConn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		sensor, err := d.findSensor(ctx, c, a.Sensor)
		if err != nil {
			return nil, nil, err
		}
		uid, name := fmt.Sprint(sensor["uid"]), fmt.Sprint(sensor["name"])
		keyPath := d.sensorKeyPath()
		pub, keyErr := sensorssh.PublicKey(keyPath)
		have, err := d.installedKey(ctx, c, uid)
		if err != nil {
			return nil, nil, fmt.Errorf("reading %s's current admin key through %s: %w", name, c.Name, err)
		}
		installed := keyErr == nil && keyBody(have) == keyBody(pub)
		token := ConfirmToken(c.Client.Host(), "fm_sensor_ssh_key", uid, keyBody(have), a.Replace)

		if a.ConfirmToken == "" {
			out := map[string]any{"preview": true, "fleet": c.Name, "sensor": name, "uid": uid, "group": sensor["group.name"],
				"setting": sensorAdminKey, "current": have, "key_exists": keyErr == nil}
			switch {
			case installed:
				out["ready"] = false
				out["next"] = "fleet-mcp's key is already installed on this sensor; nothing to do."
			case have != "" && !a.Replace:
				out["ready"] = false
				out["next"] = "The sensor already has a different admin SSH key (shown in current). Installing fleet-mcp's key would replace it; ask the user, and only with their approval preview again with replace: true."
			default:
				out["ready"] = true
				if keyErr == nil {
					out["new"] = pub
				} else {
					out["new"] = "(a new ed25519 key pair is created when this runs)"
				}
				out["confirm_token"] = token
				out["next"] = fmt.Sprintf("Show the change to the user. After they approve setting %s on %s (on %s), call again with the same arguments plus confirm_token.", sensorAdminKey, name, c.Name)
			}
			r, err := jsonResult(out)
			return r, nil, err
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match these arguments or the sensor's current key; preview again")
		}
		if installed {
			return nil, nil, errors.New("fleet-mcp's key is already installed")
		}
		if keyErr != nil {
			if pub, err = sensorssh.NewKey(keyPath, "fleet-mcp"); err != nil {
				return nil, nil, err
			}
		}
		// The UI sends the sensor's group with its individual settings.
		var rec0 struct {
			Information map[string]any `json:"information"`
		}
		if err := c.Client.GetJSON(ctx, pathCatalog+"/"+uid, nil, &rec0); err != nil {
			return nil, nil, err
		}
		body := map[string]any{"group.id": rec0.Information["group.id"], "exceptions.current": map[string]any{sensorAdminKey: pub}}
		set := metrics.Step(ctx, "set the key on %s and apply it", c.Name)
		resp, runErr := c.Client.Do(ctx, "PUT", pathCatalog+"/"+uid, nil, mustJSON(body), "application/json")
		if runErr == nil {
			resp, runErr = c.Client.Do(ctx, "POST", pathCatalog+"/"+uid+"/apply-changes", nil, []byte("{}"), "application/json")
		}
		set()
		rec := audit.Record{Fleet: c.Name, User: c.Username, Tool: "fm_sensor_ssh_key", Token: token,
			Body: map[string]any{"sensor": name, "uid": uid, sensorAdminKey: pub}}
		if resp != nil {
			rec.Status = resp.Status
		}
		out := map[string]any{"executed": true, "fleet": c.Name, "sensor": name, sensorAdminKey: pub,
			"next": "The sensor applies the change within about a minute; fm_sensor_move then logs in with the key."}
		if runErr != nil {
			rec.Error = runErr.Error()
			out["error"] = runErr.Error()
			delete(out, "next")
		}
		auditErr := d.Audit.Write(rec)
		var notes []string
		if auditErr != nil {
			notes = append(notes, "WARNING: audit log write failed: "+auditErr.Error())
		}
		r, err := jsonResult(out, notes...)
		if runErr != nil && r != nil {
			r.IsError = true
		}
		return r, nil, err
	})
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
