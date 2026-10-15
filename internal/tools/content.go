package tools

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/content"
)

func registerContentWrite(s *mcp.Server, d *Deps) {
	t, f := true, false
	type pushArgs struct {
		target
		content.Request
		ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this push's preview; when it matches, the push is carried out"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_content_push",
		Description: guideFirst("push-content") + "Push a local content file to Fleet Manager as it is: an intel or input file (file source, updated in place by alias), YARA rules (YARA source), " +
			"a Suricata rules file (a rule source of a Suricata policy with rules automation, or its rule set), a Suricata configuration file (suricata.yaml snippet, threshold, classification or reference config) " +
			"or a Zeek package bundle (replaces a sensor policy's bundle, keeping its enabled packages). The preview diffs the file against what Fleet Manager has (SIDs, indicators, records, YARA rules, bundle packages), " +
			"has Fleet Manager validate Suricata rules and YARA files, notes objects another tool manages, and for intel, input and YARA can add the source to a sensor policy's collection or ruleset. " +
			"Two steps: call without confirm_token for the preview; after the user approves, call again with the same arguments plus confirm_token.",
		Annotations: &mcp.ToolAnnotations{Title: "Push content", DestructiveHint: &f, OpenWorldHint: &t},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a pushArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.writeConn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		plan, err := content.Prepare(ctx, c.Client, a.Request)
		if err != nil {
			return nil, nil, err
		}
		token := ConfirmToken(c.Client.Host(), "fm_content_push", c.Name, a.Request, plan.State())
		if a.ConfirmToken == "" {
			out := map[string]any{"preview": true, "fleet": c.Name, "ready": plan.Ready(), "plan": plan}
			switch {
			case plan.Ready():
				out["confirm_token"] = token
				out["next"] = fmt.Sprintf("Show the user the steps, the diff, the validation, who gets it (used_by_sensor_policies) and the notes and warnings. After they approve pushing %s to %s, call fm_content_push again with the same arguments plus confirm_token.", plan.File.Path, c.Name)
			case plan.Unchanged:
				out["next"] = "Nothing to push: Fleet Manager already has this file. Tell the user."
			default:
				out["next"] = "Explain the blockers to the user; fix the file or the arguments and preview again."
			}
			r, err := jsonResult(out)
			return r, nil, err
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match: the arguments, the file or Fleet Manager changed since the preview; preview again")
		}
		res, runErr := content.Apply(ctx, c.Client, plan)
		rec := audit.Record{Fleet: c.Name, User: c.Username, Tool: "fm_content_push", Token: token,
			Body: map[string]any{"kind": plan.Kind, "file": plan.File, "target": plan.Target, "policy": plan.Policy, "result": res}}
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
			out["verification"] = "read back: every change is in place, and nothing else in a changed sensor policy changed"
			out["next"] = "Fleet Manager sends the change to the sensors of the policies that use it (used_by_sensor_policies in the preview, plus any newly linked policy)."
		}
		r, err := jsonResult(out, notes...)
		if runErr != nil && r != nil {
			r.IsError = true
		}
		return r, nil, err
	})
}
