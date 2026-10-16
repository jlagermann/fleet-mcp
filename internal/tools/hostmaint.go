package tools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleets"
	"github.com/jlagermann/fleet-mcp/internal/install"
)

// maintArgs pick a Fleet Manager host: by host, or by the fleet whose
// URL names it.
type maintArgs struct {
	Host    string `json:"host,omitempty" jsonschema:"host name or IP address of the Fleet Manager host (default: the host in the Fleet Manager's URL, from fleet)"`
	Fleet   string `json:"fleet,omitempty" jsonschema:"name of the Fleet Manager (see fm_fleets) whose host to change, when host is not given"`
	SSHUser string `json:"ssh_user,omitempty" jsonschema:"SSH user with passwordless sudo (default: FLEET_MCP_SSH_USER or your ssh config)"`
	SSHPort int    `json:"ssh_port,omitempty" jsonschema:"SSH port (default 22)"`
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// sameHost reports whether two host names or addresses name the same host.
func sameHost(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if strings.EqualFold(a, b) {
		return true
	}
	ips := func(h string) []string {
		if net.ParseIP(h) != nil {
			return []string{h}
		}
		addrs, _ := net.LookupHost(h)
		return addrs
	}
	for _, x := range ips(a) {
		for _, y := range ips(b) {
			if net.ParseIP(x).Equal(net.ParseIP(y)) {
				return true
			}
		}
	}
	return false
}

// maintTarget resolves the host and its Fleet Manager entry (nil when no
// fleet points at the host), refusing hosts of read-only Fleet Managers.
func (d *Deps) maintTarget(a maintArgs) (string, *fleets.Fleet, error) {
	var list []fleets.Fleet
	if d.Fleets != nil {
		list, _ = d.Fleets.List()
	}
	h := a.Host
	var match *fleets.Fleet
	if a.Fleet != "" {
		c, err := d.conn(a.Fleet)
		if err != nil {
			return "", nil, err
		}
		f := c.Fleet
		match = &f
		if h == "" {
			if h = hostOf(f.URL); h == "" {
				return "", nil, errors.New("cannot take a host from the Fleet Manager's URL; give host")
			}
		}
	} else if h == "" {
		return "", nil, errors.New("give host, or fleet to use the host of that Fleet Manager")
	}
	for i := range list {
		if sameHost(hostOf(list[i].URL), h) {
			if list[i].ReadOnly {
				return "", nil, fmt.Errorf("%s is the host of fleet %s, which is read-only (read_only in %s); changes are refused", h, list[i].Name, list[i].Source)
			}
			if match == nil {
				match = &list[i]
			}
		}
	}
	if match != nil && match.ReadOnly {
		return "", nil, fmt.Errorf("fleet %s is read-only (read_only in %s); changes are refused", match.Name, match.Source)
	}
	return h, match, nil
}

func registerHostMaint(s *mcp.Server, d *Deps) {
	t, f := true, false
	type configureArgs struct {
		maintArgs
		Settings        map[string]any `json:"settings,omitempty" jsonschema:"corelight-fleetd.conf values by path with / between levels: log-level, expose-swagger, development-mode, messaging/http-options/bind-address, tacacs-plus/enable, ...; null removes a key. Secrets are never set here"`
		CommunityString bool           `json:"community_string,omitempty" jsonschema:"install the sensor community string the user stored for this host (fleet-mcp secret set community-string -host <host>); every sensor loses its connection until given the new one"`
		IdentityCert    bool           `json:"identity_cert,omitempty" jsonschema:"install the product identity certificate stored as identity-cert.pem (fm_secret_import_file), e.g. a renewed one"`
		TLSCert         bool           `json:"tls_cert,omitempty" jsonschema:"install the web interface and API certificate stored for this host as tls-cert.pem (fm_secret_import_file with host)"`
		License         bool           `json:"license,omitempty" jsonschema:"install the Software Sensor license stored as sensor-license.txt"`
		ConfirmToken    string         `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this change's preview; when it matches, the change is made"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_host_configure",
		Description: guideFirst("maintain-fleet-manager") + "Change an installed Fleet Manager host over SSH: corelight-fleetd.conf settings, the sensor community string, a renewed product identity certificate, the web interface certificate, or the Software Sensor license. " +
			"Certificates, licenses and the community string come from fleet-mcp's secret store, never from the chat. Each replaced file is backed up root-only, corelight-fleetd is restarted and its API awaited; if it does not come up, the backups are restored and it is restarted again. " +
			"When the web certificate changes, the certificate fleet-mcp pins is updated. Refused for hosts of read-only Fleet Managers. " +
			"Two steps: call without confirm_token for a preview; after the user approves, call again with the same arguments plus confirm_token.",
		Annotations: &mcp.ToolAnnotations{Title: "Configure Fleet Manager host", DestructiveHint: &t, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a configureArgs) (*mcp.CallToolResult, any, error) {
		if d.Secrets == nil {
			return nil, nil, errors.New("no secret store configured")
		}
		h, _, err := d.maintTarget(a.maintArgs)
		if err != nil {
			return nil, nil, err
		}
		r, err := d.runner(hostArgs{Host: h, SSHUser: a.SSHUser, SSHPort: a.SSHPort})
		if err != nil {
			return nil, nil, err
		}
		opts := install.ConfigureOptions{Settings: a.Settings, CommunityString: a.CommunityString, IdentityCert: a.IdentityCert, TLSCert: a.TLSCert, License: a.License}
		m := &install.Maintainer{R: r, Secrets: d.Secrets, Host: h}
		plan, err := m.PlanConfigure(ctx, opts)
		if err != nil {
			return nil, nil, err
		}
		token := ConfirmToken(h, "fm_host_configure", r.Name(), a.SSHPort, opts, plan.State())
		if a.ConfirmToken == "" {
			out := map[string]any{"preview": true, "plan": plan}
			switch {
			case len(plan.Blockers) > 0:
				out["next"] = "Resolve the blockers first; nothing can be changed yet."
			case len(plan.Changes) == 0:
				out["next"] = "Nothing to change."
			default:
				out["confirm_token"] = token
				out["next"] = "Show the changes, steps and warnings to the user. After the user approves, call fm_host_configure again with the same arguments plus confirm_token."
			}
			res, err := jsonResult(out)
			return res, nil, err
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match these arguments or the host changed since the preview; preview again")
		}
		done, runErr := m.ApplyConfigure(ctx, plan)
		rec := audit.Record{Fleet: h, User: r.Name(), Tool: "fm_host_configure", Body: map[string]any{"changes": plan.Changes, "result": done}, Token: token}
		if runErr != nil {
			rec.Error = runErr.Error()
		}
		auditErr := d.Audit.Write(rec)
		if done != nil && done.Pin != "" && d.Fleets != nil {
			d.Fleets.Reload()
		}
		out := map[string]any{"executed": runErr == nil, "host": r.Name(), "result": done}
		if runErr != nil {
			out["error"] = runErr.Error()
		} else {
			out["next"] = "Check the host with fm_host_diagnose; after a community string change, give each sensor the new one with fm_sensor_move."
		}
		var notes []string
		if auditErr != nil {
			notes = append(notes, "WARNING: audit log write failed: "+auditErr.Error())
		}
		res, err := jsonResult(out, notes...)
		if runErr != nil && res != nil {
			res.IsError = true
		}
		return res, nil, err
	})

	type upgradeArgs struct {
		maintArgs
		Version        string `json:"version,omitempty" jsonschema:"corelight-fleet version or prefix to install, e.g. 29.2.2 (default: the newest in the repository)"`
		AllowDowngrade bool   `json:"allow_downgrade,omitempty" jsonschema:"allow installing an older version than the installed one"`
		Backup         *bool  `json:"backup,omitempty" jsonschema:"make a Fleet Manager backup first (default true; needs the Fleet Manager's API, found from fleet or host)"`
		ConfirmToken   string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this upgrade's preview; when it matches, the upgrade runs"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_host_upgrade",
		Description: guideFirst("maintain-fleet-manager") + "Upgrade (or, with allow_downgrade, downgrade) Fleet Manager on its host over SSH from the Corelight package repository. " +
			"The preview lists the installed and available versions and checks free space and the repository. The upgrade makes a Fleet Manager backup first (default), installs the package keeping corelight-fleetd.conf, restarts and waits for the API, and checks the version. " +
			"Sensor software is not changed. Refused for hosts of read-only Fleet Managers. " +
			"Two steps: call without confirm_token for a preview; after the user approves, call again with the same arguments plus confirm_token.",
		Annotations: &mcp.ToolAnnotations{Title: "Upgrade Fleet Manager", DestructiveHint: &t, OpenWorldHint: &t},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a upgradeArgs) (*mcp.CallToolResult, any, error) {
		h, fl, err := d.maintTarget(a.maintArgs)
		if err != nil {
			return nil, nil, err
		}
		r, err := d.runner(hostArgs{Host: h, SSHUser: a.SSHUser, SSHPort: a.SSHPort})
		if err != nil {
			return nil, nil, err
		}
		backup := a.Backup == nil || *a.Backup
		u := &install.Upgrader{R: r}
		if backup && fl != nil {
			name := fl.Name
			u.StartBackup = func(ctx context.Context) error {
				c, err := d.writeConn(name)
				if err != nil {
					return err
				}
				_, err = c.Client.Do(ctx, http.MethodPost, pathBackups, nil, nil, "")
				return err
			}
		}
		opts := install.UpgradeOptions{Version: a.Version, AllowDowngrade: a.AllowDowngrade, Backup: backup}
		plan, err := u.Plan(ctx, opts)
		if err != nil {
			return nil, nil, err
		}
		fleetName := ""
		if fl != nil {
			fleetName = fl.Name
		}
		token := ConfirmToken(h, "fm_host_upgrade", r.Name(), a.SSHPort, opts, fleetName, plan.State())
		if a.ConfirmToken == "" {
			out := map[string]any{"preview": true, "plan": plan}
			if fleetName != "" {
				out["fleet"] = fleetName
			}
			switch {
			case len(plan.Blockers) > 0:
				out["next"] = "Resolve the blockers first; nothing can be changed yet."
			case !plan.Ready():
				out["next"] = "Nothing to install."
			default:
				out["confirm_token"] = token
				out["next"] = "Show the versions, steps and warnings to the user. After the user approves, call fm_host_upgrade again with the same arguments plus confirm_token."
			}
			res, err := jsonResult(out)
			return res, nil, err
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match these arguments or the host changed since the preview; preview again")
		}
		done, runErr := u.Apply(ctx, plan)
		rec := audit.Record{Fleet: h, User: r.Name(), Tool: "fm_host_upgrade", Body: map[string]any{"from": plan.Installed, "to": plan.Target, "result": done}, Token: token}
		if runErr != nil {
			rec.Error = runErr.Error()
		}
		auditErr := d.Audit.Write(rec)
		out := map[string]any{"executed": runErr == nil, "host": r.Name(), "from": plan.Installed, "to": plan.Target, "result": done}
		if runErr != nil {
			out["error"] = runErr.Error()
			out["next"] = "Check the host with fm_host_diagnose. To go back, run fm_host_upgrade with the previous version and allow_downgrade; the backup can be restored in the Fleet Manager web interface."
		} else {
			out["next"] = "Check the host with fm_host_diagnose and the sensors with fm_fleet_health."
		}
		var notes []string
		if auditErr != nil {
			notes = append(notes, "WARNING: audit log write failed: "+auditErr.Error())
		}
		res, err := jsonResult(out, notes...)
		if runErr != nil && res != nil {
			res.IsError = true
		}
		return res, nil, err
	})
}
