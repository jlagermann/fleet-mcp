package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/host"
	"github.com/jlagermann/fleet-mcp/internal/install"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
)

type hostArgs struct {
	Host    string `json:"host" jsonschema:"host name or IP address of the Fleet Manager host"`
	SSHUser string `json:"ssh_user,omitempty" jsonschema:"SSH user with passwordless sudo (default: FLEET_MCP_SSH_USER or your ssh config)"`
	SSHPort int    `json:"ssh_port,omitempty" jsonschema:"SSH port (default 22)"`
}

func (d *Deps) runner(a hostArgs) (*host.SSH, error) {
	user := a.SSHUser
	if user == "" {
		user = d.SSHUser
	}
	r, err := host.NewSSH(a.Host, user, a.SSHPort)
	if err != nil {
		return nil, err
	}
	r.Binary = d.SSHBinary
	return r, nil
}

func registerHost(s *mcp.Server, d *Deps) {
	f := false
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_host_check",
		Description: "Read-only readiness check of a Linux host for Fleet Manager over SSH: OS and architecture, CPUs, memory, free space on /var and /tmp, ports 443/1443, access to the Corelight package repository, an existing installation, firewall and time sync. " +
			"Findings are graded pass/warn/fail against the documented requirements; ready is false if anything fails.",
		Annotations: &mcp.ToolAnnotations{Title: "Check Fleet Manager host", ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a hostArgs) (*mcp.CallToolResult, any, error) {
		r, err := d.runner(a)
		if err != nil {
			return nil, nil, err
		}
		rep, err := install.Check(ctx, r)
		if err != nil {
			return nil, nil, err
		}
		res, err := jsonResult(rep)
		return res, nil, err
	})

	type checklistArgs struct {
		Host    string `json:"host,omitempty" jsonschema:"the intended Fleet Manager host; when given, it is checked over SSH"`
		SSHUser string `json:"ssh_user,omitempty" jsonschema:"SSH user with passwordless sudo (default: FLEET_MCP_SSH_USER or your ssh config)"`
		SSHPort int    `json:"ssh_port,omitempty" jsonschema:"SSH port (default 22)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_install_checklist",
		Description: guideFirst("install-fleet-manager") + "Everything a user must provide or decide before installing Fleet Manager (host access and resources, the Corelight repository token and product identity certificate, optional community string and Software Sensor license, version, agent user name, address), each with its current status and how to provide it. " +
			"Call this first whenever the user wants to install Fleet Manager, and show the returned markdown to the user. Read-only; values of secrets are never returned.",
		Annotations: &mcp.ToolAnnotations{Title: "Install checklist", ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a checklistArgs) (*mcp.CallToolResult, any, error) {
		var r host.Runner
		if a.Host != "" {
			ssh, err := d.runner(hostArgs(a))
			if err != nil {
				return nil, nil, err
			}
			r = ssh
		}
		items, err := install.Checklist(ctx, d.Secrets, a.Host, r)
		if err != nil {
			return nil, nil, err
		}
		md := install.RenderChecklist(items)
		res, err := jsonResult(map[string]any{"ready": install.ChecklistReady(items), "items": items, "markdown": md})
		if res != nil {
			// Put the display text first so clients show it readably.
			res.Content = append([]mcp.Content{&mcp.TextContent{Text: md}}, res.Content...)
		}
		return res, nil, err
	})

	type secretsArgs struct {
		Host string `json:"host,omitempty" jsonschema:"also show the secrets generated for this Fleet Manager host"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_secrets_status",
		Description: "Which credentials and license files fleet-mcp has stored for installing and managing Fleet Manager, and how to provide missing ones. Never returns values. " +
			"Tokens and passwords must be entered by the user at a hidden terminal prompt (fleet-mcp secret set <name>); never ask the user to paste them into the chat.",
		Annotations: &mcp.ToolAnnotations{Title: "Secrets status", ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a secretsArgs) (*mcp.CallToolResult, any, error) {
		if d.Secrets == nil {
			return nil, nil, errors.New("no secret store configured")
		}
		out := map[string]any{"store": d.Secrets.Dir(), "secrets": d.Secrets.List(a.Host)}
		if a.Host != "" {
			if p, err := install.ReadProfile(d.Secrets, a.Host); err == nil {
				out["profile"] = p
			}
		}
		res, err := jsonResult(out)
		return res, nil, err
	})

	type importArgs struct {
		Name string `json:"name" jsonschema:"identity-cert.pem (Fleet Manager product identity certificate), sensor-license.txt, or tls-cert.pem (a Fleet Manager host's web certificate; needs host)"`
		Host string `json:"host,omitempty" jsonschema:"the Fleet Manager host the file belongs to (for tls-cert.pem)"`
		Path string `json:"path" jsonschema:"path of the file on this machine"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_secret_import_file",
		Description: "Import a license or certificate file into fleet-mcp's local secret store (readable only by the current user) for fm_host_install and fm_host_configure. " +
			"The file is validated (the identity certificate must contain a certificate and its matching key); only a summary such as subject and expiry is returned, never the contents.",
		Annotations: &mcp.ToolAnnotations{Title: "Import secret file", DestructiveHint: &f, IdempotentHint: true, OpenWorldHint: &f, ReadOnlyHint: false},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a importArgs) (*mcp.CallToolResult, any, error) {
		if d.Secrets == nil {
			return nil, nil, errors.New("no secret store configured")
		}
		spec, ok := secrets.Lookup(a.Name)
		if !ok || spec.Kind != secrets.File {
			return nil, nil, fmt.Errorf("%q is not a file secret; use identity-cert.pem, sensor-license.txt or tls-cert.pem (tokens are set with: fleet-mcp secret set <name>)", a.Name)
		}
		summary, err := ImportFile(d.Secrets, a.Host, a.Name, a.Path)
		if err != nil {
			return nil, nil, err
		}
		res, err := jsonResult(map[string]any{"stored": a.Name, "summary": summary})
		return res, nil, err
	})
}

// ImportFile validates a file and stores it as a secret.
func ImportFile(s *secrets.Store, hostName, name, path string) (any, error) {
	if spec, ok := secrets.Lookup(name); ok && spec.Scope == secrets.Host && hostName == "" {
		return nil, fmt.Errorf("%s belongs to one Fleet Manager host: give the host", name)
	}
	path = filepath.Clean(strings.Trim(strings.TrimSpace(path), `"'`))
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > 1<<20 {
		return nil, fmt.Errorf("%s is %d bytes; a license or certificate file is much smaller", path, fi.Size())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	summary, err := secrets.Validate(name, b)
	if err != nil {
		return summary, err
	}
	if err := s.Set(hostName, name, b); err != nil {
		return nil, err
	}
	return summary, nil
}

func registerHostWrite(s *mcp.Server, d *Deps) {
	t, f := true, false
	type installArgs struct {
		hostArgs
		Version       string `json:"version,omitempty" jsonschema:"corelight-fleet version to install, e.g. 29.2.2 (default: newest)"`
		ExposeSwagger *bool  `json:"expose_swagger,omitempty" jsonschema:"serve the REST API spec (expose-swagger in corelight-fleetd.conf); default true, because Fleet Manager otherwise serves no REST spec; false removes it"`
		MCPUser       string `json:"agent_user,omitempty" jsonschema:"Fleet Manager admin user the agent logs in as, created by the install (default claude); the install also creates the admin user for you"`
		URL           string `json:"url,omitempty" jsonschema:"URL this machine uses to reach the new Fleet Manager (default https://<host>)"`
		ConfirmToken  string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this install's preview; when it matches, the plan is executed"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_host_install",
		Description: guideFirst("install-fleet-manager") + "Install and set up Fleet Manager on an Ubuntu 22.04/24.04 host over SSH, following the Corelight installation guide: repository key, source and token, the corelight-fleet package, the product identity certificate, corelight-fleetd.conf (sensor community-string: the user's own if set with fleet-mcp secret set community-string -host <host>, otherwise generated; optional expose-swagger), the service, a local admin user for fleet-mcp (password generated and kept only by fleet-mcp), and the \"admin\" user. The admin's temporary password is returned in admin_temporary_password: give it to the user, who must change it at first login; fleet-mcp does not keep it. An existing admin is never changed. " +
			"Needs the repo-token and identity-cert.pem secrets (see fm_secrets_status) and passwordless sudo. Generated secrets are stored locally, never returned. " +
			"Every step checks first and is skipped when already done, so a failed install can be re-run. " +
			"Two steps: call without confirm_token for a preview of each step's state; after the user approves, call again with the same arguments plus confirm_token. Run fm_host_check first.",
		Annotations: &mcp.ToolAnnotations{Title: "Install Fleet Manager", DestructiveHint: &t, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a installArgs) (*mcp.CallToolResult, any, error) {
		if d.Secrets == nil {
			return nil, nil, errors.New("no secret store configured")
		}
		r, err := d.runner(a.hostArgs)
		if err != nil {
			return nil, nil, err
		}
		opts := install.Options{Version: a.Version, ExposeSwagger: a.ExposeSwagger, MCPUser: a.MCPUser, URL: a.URL}
		if err := opts.Validate(); err != nil {
			return nil, nil, err
		}
		in := &install.Installer{R: r, Secrets: d.Secrets, Host: a.Host, Opts: opts, Bootstrap: &install.APIBootstrap{UserAgent: "fleet-mcp"}}
		token := ConfirmToken(a.Host, "fm_host_install", r.Name(), a.SSHPort, opts)

		if a.ConfirmToken == "" {
			plan, err := in.Plan(ctx)
			if err != nil {
				return nil, nil, err
			}
			items, _ := install.Checklist(ctx, d.Secrets, a.Host, r)
			out := map[string]any{
				"preview": true, "host": r.Name(), "url": in.URL(), "options": opts, "steps": plan,
				"checklist": install.RenderChecklist(items), "checklist_ready": install.ChecklistReady(items),
				"confirm_token": token,
				"next":          "Show the steps to the user. Blocked steps must be resolved first (for missing secrets see fm_secrets_status). After the user approves, call fm_host_install again with the same arguments plus confirm_token.",
			}
			res, err := jsonResult(out)
			return res, nil, err
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match these arguments; preview again")
		}
		steps, runErr := in.Execute(ctx)
		rec := audit.Record{Fleet: a.Host, User: r.Name(), Tool: "fm_host_install", Body: map[string]any{"options": opts, "steps": steps}, Token: token}
		if runErr != nil {
			rec.Error = runErr.Error()
		}
		auditErr := d.Audit.Write(rec)
		out := map[string]any{"executed": true, "host": r.Name(), "steps": steps}
		if in.AdminTempPassword != "" {
			out["admin_temporary_password"] = in.AdminTempPassword
			out["admin_login"] = "Give this temporary password to the user: log in at " + in.URL() + " as admin; Fleet Manager requires a new password at first login. fleet-mcp does not keep it."
		}
		if runErr != nil {
			out["error"] = runErr.Error()
			out["next"] = "Fix the failed step and run fm_host_install again; completed steps are skipped."
		} else {
			if p, err := install.ReadProfile(d.Secrets, a.Host); err == nil {
				out["profile"] = p
				if d.Fleets != nil {
					d.Fleets.Reload()
				}
				out["next"] = fmt.Sprintf("Fleet Manager is installed and is now available to the other tools as fleet %q (see fm_fleets).", a.Host)
			}
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
