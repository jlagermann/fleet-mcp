package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/content"
	"github.com/jlagermann/fleet-mcp/internal/suritest"
)

func registerSuricataTest(s *mcp.Server, d *Deps) {
	type testArgs struct {
		target
		SuricataPolicy string `json:"suricata_policy,omitempty" jsonschema:"Suricata policy id or name: its address and port groups (settings and suricata.yaml snippet) are used, and without file its generated ruleset is tested"`
		Policy         string `json:"policy,omitempty" jsonschema:"sensor policy id or name, to use its Suricata policy"`
		File           string `json:"file,omitempty" jsonschema:"local rules file to test instead of the policy's generated ruleset (for example before fm_content_push)"`
		Host           string `json:"host" jsonschema:"SSH host with Suricata to test on (ask the user; use the same Suricata version as the sensors)"`
		SSHUser        string `json:"ssh_user,omitempty" jsonschema:"SSH user (default: fleet-mcp's SSH user setting, else ssh_config)"`
		Suricata       string `json:"suricata,omitempty" jsonschema:"Suricata binary on the host (default suricata)"`
		Config         string `json:"config,omitempty" jsonschema:"local suricata.yaml to test with (default: the host's /etc/suricata/suricata.yaml); one matching the sensors' configuration gives the closest result"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_suricata_test",
		Description: guideFirst("tune-suricata") + "Test a Suricata ruleset with a real Suricata (suricata -T) on a host the user names, over SSH: Fleet Manager only parses rules, this loads them as a sensor does. " +
			"Tests a local rules file, or the ruleset Fleet Manager generated for a Suricata policy (after rule sources, tuning and flowbit dependencies). The policy's address and port groups (settings and suricata.yaml snippet) are passed to Suricata. " +
			"Returns the Suricata version, rules loaded and failed, failed SIDs, failure reasons and undefined variables. Changes nothing on Fleet Manager; on the host it uses a temporary directory it removes.",
		Annotations: &mcp.ToolAnnotations{Title: "Test Suricata ruleset", ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a testArgs) (*mcp.CallToolResult, any, error) {
		if a.Host == "" {
			return nil, nil, errors.New("host is required: ask the user which host with Suricata (same version as the sensors) to test on")
		}
		opts := suritest.Options{Host: a.Host, User: a.SSHUser, SSHBinary: d.SSHBinary, Suricata: a.Suricata}
		if opts.User == "" {
			opts.User = d.SSHUser
		}
		var notes []string
		var rules []byte
		source := ""
		if a.SuricataPolicy != "" || a.Policy != "" {
			c, err := d.conn(a.Fleet)
			if err != nil {
				return nil, nil, err
			}
			sp, _, err := content.SuricataPolicy(ctx, c.Client, a.SuricataPolicy, a.Policy)
			if err != nil {
				return nil, nil, err
			}
			vars, vnotes, err := content.SuricataVars(ctx, c.Client, sp)
			if err != nil {
				return nil, nil, err
			}
			opts.Vars, notes = vars, vnotes
			if a.File == "" {
				if rules, err = content.GeneratedRuleset(ctx, c.Client, sp); err != nil {
					return nil, nil, err
				}
				source = fmt.Sprintf("the ruleset Fleet Manager %s generated for Suricata policy %q", c.Name, fmt.Sprint(sp["name"]))
			}
		}
		if a.File != "" {
			b, err := os.ReadFile(a.File)
			if err != nil {
				return nil, nil, err
			}
			rules, source = b, a.File
		}
		if rules == nil {
			return nil, nil, errors.New("give file, or suricata_policy/policy to test its generated ruleset")
		}
		if a.Config != "" {
			b, err := os.ReadFile(a.Config)
			if err != nil {
				return nil, nil, err
			}
			opts.Config = b
		}
		rep, err := suritest.Test(ctx, opts, rules)
		if err != nil {
			return nil, nil, err
		}
		out := map[string]any{"tested": source, "report": rep, "notes": notes}
		switch {
		case rep.OK:
			out["summary"] = fmt.Sprintf("all %d rules loaded with %s", rep.Loaded, rep.Version)
		case len(rep.UndefinedVars) > 0:
			out["summary"] = fmt.Sprintf("%d rules failed; variables not defined: %s (define them in the Suricata policy's address/port groups or suricata.yaml snippet, or pass suricata_policy)", rep.Failed, strings.Join(rep.UndefinedVars, ", "))
		default:
			out["summary"] = fmt.Sprintf("%d of %d rules failed with %s", rep.Failed, rep.Failed+rep.Loaded, rep.Version)
		}
		r, err := jsonResult(out)
		return r, nil, err
	})
}

func registerSuricataModify(s *mcp.Server, d *Deps) {
	t, f := true, false
	type modArgs struct {
		target
		content.SRMRequest
		ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this change's preview; when it matches, the change is made"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_suricata_modify",
		Description: guideFirst("tune-suricata") + "Tune single rules of a Suricata policy in Fleet Manager's Suricata rules manager (a policy with Suricata automation in the recommended rules-manager mode, not configuration files): disable, enable or modify the rules a SID (or another match) selects, and remove modifiers. " +
			"The preview shows each rule's current effective state, what it should be after, existing modifiers that are replaced or updated, and Fleet Manager's validation of the new modifiers. After applying, fleet-mcp waits for the ruleset rebuild and checks the rules. " +
			"For policies using configuration files, push disable.conf, enable.conf or modify.conf with fm_content_push instead. " +
			"Two steps: call without confirm_token for the preview; after the user approves, call again with the same arguments plus confirm_token.",
		Annotations: &mcp.ToolAnnotations{Title: "Tune Suricata rules", DestructiveHint: &f, OpenWorldHint: &t},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a modArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.writeConn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		plan, err := content.PrepareSRM(ctx, c.Client, a.SRMRequest)
		if err != nil {
			return nil, nil, err
		}
		token := ConfirmToken(c.Client.Host(), "fm_suricata_modify", c.Name, a.SRMRequest, plan.State())
		if a.ConfirmToken == "" {
			out := map[string]any{"preview": true, "fleet": c.Name, "ready": plan.Ready(), "plan": plan}
			switch {
			case plan.Ready():
				out["confirm_token"] = issueToken(token)
				out["next"] = fmt.Sprintf("Show the user the rules now, what changes and the expected result. After they approve the change to Suricata policy %q on %s, call fm_suricata_modify again with the same arguments plus confirm_token.", plan.SuricataPolicy.Name, c.Name)
			case len(plan.Blockers) == 0:
				out["next"] = "Nothing to do: the requested modifiers are already in place. Tell the user."
			default:
				out["next"] = "Explain the blockers to the user and preview again with corrected changes."
			}
			r, err := jsonResult(out)
			return r, nil, err
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match: the arguments or the policy's modifiers changed since the preview; preview again")
		}
		if err := redeemToken(token); err != nil {
			return nil, nil, err
		}
		res, runErr := content.ApplySRM(ctx, c.Client, plan)
		rec := audit.Record{Fleet: c.Name, User: c.Username, Tool: "fm_suricata_modify", Token: token,
			Body: map[string]any{"suricata_policy": plan.SuricataPolicy, "add": plan.Add, "update": plan.Update, "remove": plan.Remove, "result": res}}
		if runErr != nil {
			rec.Error = runErr.Error()
		}
		var notes []string
		if err := d.Audit.Write(rec); err != nil {
			notes = append(notes, "WARNING: audit log write failed: "+err.Error())
		}
		out := map[string]any{"executed": true, "fleet": c.Name, "result": res}
		if runErr != nil {
			out["error"] = runErr.Error()
		} else if res != nil && len(res.Verification) == 0 {
			out["verification"] = "read back: every changed rule has its expected state in the rebuilt ruleset"
		}
		r, err := jsonResult(out, notes...)
		if runErr != nil && r != nil {
			r.IsError = true
		}
		return r, nil, err
	})
}
