package tools

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/newpolicy"
)

func registerNewPolicy(s *mcp.Server, d *Deps) {
	type profileArgs struct {
		Profile string `json:"profile,omitempty" jsonschema:"north-south or east-west to list only what that profile enables; omit for every package with both recommendations"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_policy_profiles",
		Description: "List the Zeek package recommendations fm_policy_create starts from: for every Corelight package, whether the north-south (border, egress) and east-west (internal) profiles enable it, why, and where the recommendation comes from (the sensor docs' deployment table, a docs package page, or fleet-mcp's own call for packages added since). Opt-in packages (ICS/OT, advanced) are never enabled by a profile.",
		Annotations: readOnly("List policy profiles"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a profileArgs) (*mcp.CallToolResult, any, error) {
		var rows []newpolicy.Package
		for _, p := range newpolicy.Sorted() {
			switch a.Profile {
			case "":
				rows = append(rows, p)
			case newpolicy.NorthSouth:
				if p.NS && !p.OptIn {
					rows = append(rows, p)
				}
			case newpolicy.EastWest:
				if p.EW && !p.OptIn {
					rows = append(rows, p)
				}
			default:
				return nil, nil, fmt.Errorf("profile must be north-south or east-west")
			}
		}
		r, err := jsonResult(map[string]any{"count": len(rows), "packages": rows,
			"note": "Machine learning and anomaly detection are separate options of fm_policy_create (on by default). Packages loaded by default on every sensor are left as they are."})
		return r, nil, err
	})
}

func registerNewPolicyWrite(s *mcp.Server, d *Deps) {
	t, f := true, false
	type createArgs struct {
		target
		newpolicy.Spec
		ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this policy's preview; when it matches, the policy is created"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_policy_create",
		Description: guideFirst("create-sensor-policy") + "Create a new sensor policy from scratch on a Fleet Manager: a package profile (north-south or east-west, from the sensor docs' recommendations and fleet-mcp's for newer packages) plus remote access, machine learning and anomaly detection, local networks, traffic filter, NTP, syslog, proxy, batch export, streaming exporters, a custom bundle, Suricata, YARA, input and intel collections, performance monitoring and automatic updates. Everything not asked for stays at the sensor default and is listed as such. " +
			"Two steps: call without confirm_token for a preview of every setting and package (with why), the defaults left alone, warnings and blockers; after the user approves, call again with the same arguments plus confirm_token.",
		Annotations: &mcp.ToolAnnotations{Title: "Create sensor policy", DestructiveHint: &f, OpenWorldHint: &t},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a createArgs) (*mcp.CallToolResult, any, error) {
		if d.Secrets == nil {
			return nil, nil, errors.New("no secret store configured")
		}
		c, err := d.writeConn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		plan, err := newpolicy.Prepare(ctx, c.Client, d.Secrets, a.Spec)
		if err != nil {
			return nil, nil, err
		}
		token := ConfirmToken(c.Client.Host(), "fm_policy_create", c.Name, a.Spec)
		if a.ConfirmToken == "" {
			out := map[string]any{"preview": true, "fleet": c.Name, "ready": plan.Ready(), "plan": plan,
				"sections": groupItems(plan.Built.Items), "packages_by_collection": groupPackages(plan.Built.Packages)}
			if plan.Ready() {
				out["confirm_token"] = issueToken(token)
				out["next"] = fmt.Sprintf("Show the user the policy: every section, the packages and why, what is left at the default, the enrichment chain and the warnings, and ask plan.questions_for_user if there are any (answers go in input_readers or change the packages; preview again after). After they approve creating %q on %s, call fm_policy_create again with the same arguments plus confirm_token.", a.Name, c.Name)
			} else {
				out["next"] = "Resolve the blockers with the user (secrets go through fleet-mcp secret set-setting in their terminal) and preview again."
			}
			r, err := jsonResult(out)
			return r, nil, err
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match these arguments; preview again")
		}
		if err := redeemToken(token); err != nil {
			return nil, nil, err
		}
		if !plan.Ready() {
			return nil, nil, fmt.Errorf("the policy can no longer be created: %v", plan.Blockers)
		}
		id, verification, runErr := newpolicy.Create(ctx, c.Client, plan)
		if runErr == nil {
			for _, name := range plan.UsedSecrets() {
				_ = d.Secrets.DeleteSetting(name)
			}
		}
		rec := audit.Record{Fleet: c.Name, User: c.Username, Tool: "fm_policy_create", Token: token,
			Body: map[string]any{"name": a.Name, "profile": a.Profile, "policy_id": id, "packages": len(plan.Built.Packages)}}
		if runErr != nil {
			rec.Error = runErr.Error()
		}
		auditErr := d.Audit.Write(rec)
		out := map[string]any{"executed": true, "fleet": c.Name, "policy_id": id, "name": a.Name, "verification": verification}
		if runErr == nil && len(verification) == 0 {
			out["verification"] = "read back: every setting, secret and link matches the plan"
		}
		var notes []string
		if auditErr != nil {
			notes = append(notes, "WARNING: audit log write failed: "+auditErr.Error())
		}
		if runErr != nil {
			out["error"] = runErr.Error()
		} else {
			out["next"] = fmt.Sprintf("Sensor policy %d was created on %s. Secrets used were removed from the secret store. Assign the policy to a sensor group separately.", id, c.Name)
		}
		r, err := jsonResult(out, notes...)
		if runErr != nil && r != nil {
			r.IsError = true
		}
		return r, nil, err
	})
}

func groupItems(items []newpolicy.Item) map[string][]newpolicy.Item {
	out := map[string][]newpolicy.Item{}
	for _, it := range items {
		out[it.Section] = append(out[it.Section], it)
	}
	return out
}

func groupPackages(ps []newpolicy.Package) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for _, p := range ps {
		out[p.Collection] = append(out[p.Collection], map[string]any{"name": p.Name, "source": p.Source, "why": p.Why})
	}
	return out
}
