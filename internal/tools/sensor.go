package tools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleets"
	"github.com/jlagermann/fleet-mcp/internal/host"
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
		Description: "Move a sensor from one Fleet Manager (fleet) to another (target_fleet): fleet-mcp logs in to the sensor over SSH as diag-shell (password: the sensor-admin-password secret) and runs corelight-client configuration update with the target's address and community string, clearing fleet.server_sslname. " +
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
		hk, err := sensorssh.ScanHostKey(ctx, sshHost, pins)
		if err != nil {
			return nil, nil, err
		}
		if hk.Changed {
			return nil, nil, fmt.Errorf("%s presents SSH host key %s, which differs from the one fleet-mcp pinned earlier; if the sensor was reinstalled, remove its line from %s", sshHost, hk.Fingerprint, pins.Path)
		}
		_, pwErr := d.Secrets.GetString("", secrets.SensorPassword)
		_, csErr := d.Secrets.GetString(tgt.Name, secrets.CommunityString)
		token := ConfirmToken(sshHost, "fm_sensor_move", uid, src.Name, tgt.Name, addr, hk.Fingerprint)

		if a.ConfirmToken == "" {
			var blockers []string
			if pwErr != nil {
				blockers = append(blockers, "the sensor admin password is not stored; the user runs in a terminal: fleet-mcp secret set "+secrets.SensorPassword)
			}
			if csErr != nil {
				blockers = append(blockers, fmt.Sprintf("%s's community string is not stored; the user runs in a terminal: fleet-mcp secret set %s -host %s", tgt.Name, secrets.CommunityString, tgt.Name))
			}
			out := map[string]any{
				"preview": true, "sensor": name, "uid": uid, "from": src.Name, "to": tgt.Name,
				"group": sensor["group.name"], "policy": sensor["policy.name"], "health": sensor["health.status"],
				"ssh":             map[string]any{"host": sshHost, "user": sensorssh.User, "host_key": hk},
				"sensor_settings": map[string]any{"fleet.server": addr, "fleet.community_string": "(" + tgt.Name + "'s community string)", "fleet.server_sslname": ""},
				"after":           fmt.Sprintf("%s keeps its configuration, appears on %s in UNASSIGNED, and goes offline on %s.", name, tgt.Name, src.Name),
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
		if pwErr != nil {
			return nil, nil, pwErr
		}
		if csErr != nil {
			return nil, nil, csErr
		}
		pw, _ := d.Secrets.GetString("", secrets.SensorPassword)
		cs, _ := d.Secrets.GetString(tgt.Name, secrets.CommunityString)
		cmd := "corelight-client configuration update --fleet.community_string=" + host.Quote(cs) +
			" --fleet.server=" + host.Quote(addr) + " --fleet.server_sslname=''"
		output, runErr := sensorssh.Run(ctx, sshHost, pw, hk.Fingerprint, cmd, pins, cs, pw)

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
