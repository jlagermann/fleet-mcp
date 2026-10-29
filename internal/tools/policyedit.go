package tools

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/policyedit"
)

// editFlow is the shared preview -> confirm -> audit flow of the
// policyedit tools.
type editFlow struct {
	fleet, token        string
	ready               bool
	preview             any
	nextReady, nextIdle string
	blockers            []string
}

func (f editFlow) previewResult() (*mcp.CallToolResult, any, error) {
	out := map[string]any{"preview": true, "fleet": f.fleet, "ready": f.ready, "plan": f.preview}
	switch {
	case f.ready:
		out["confirm_token"] = issueToken(f.token)
		out["next"] = f.nextReady
	case len(f.blockers) > 0:
		out["next"] = "Explain the blockers to the user and preview again with corrected arguments."
	default:
		out["next"] = f.nextIdle
	}
	r, err := jsonResult(out)
	return r, nil, err
}

func registerPolicyEdit(s *mcp.Server, d *Deps) {
	t, f := true, false
	finish := func(name, fleet, user, token string, body map[string]any, res any, runErr error, verification []string, ok string) (*mcp.CallToolResult, any, error) {
		rec := audit.Record{Fleet: fleet, User: user, Tool: name, Token: token, Body: body}
		if runErr != nil {
			rec.Error = runErr.Error()
		}
		var notes []string
		if err := d.Audit.Write(rec); err != nil {
			notes = append(notes, "WARNING: audit log write failed: "+err.Error())
		}
		out := map[string]any{"executed": true, "fleet": fleet, "result": res}
		if runErr != nil {
			out["error"] = runErr.Error()
		} else if len(verification) == 0 {
			out["verification"] = ok
		}
		r, err := jsonResult(out, notes...)
		if runErr != nil && r != nil {
			r.IsError = true
		}
		return r, nil, err
	}

	type updateArgs struct {
		target
		policyedit.UpdateRequest
		ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this change's preview; when it matches, the change is made"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_policy_update",
		Description: guideFirst("change-sensor-policy") + "Change an existing sensor policy in one step: settings (null resets to the default), secret settings from fleet-mcp's store, Corelight and custom bundle packages (enable/disable by name), and the linked Suricata policy, YARA ruleset, intel/input/resource/CA bundle collections and package bundle (or none to unlink). " +
			"The preview shows every change from -> to, licensed features turned on, Fleet Manager's validation (plus a check of IP and CIDR lists, which Fleet Manager does not validate), the enrichment chain of the linked collections and which sensor groups get the change. After applying, it reads the policy back and checks nothing else changed. " +
			"Two steps: call without confirm_token for the preview; after the user approves, call again with the same arguments plus confirm_token.",
		Annotations: &mcp.ToolAnnotations{Title: "Change sensor policy", DestructiveHint: &f, OpenWorldHint: &t},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a updateArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.writeConn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		secrets := map[string]string{}
		for _, k := range a.SecretSettings {
			if d.Secrets == nil {
				return nil, nil, errors.New("no secret store configured")
			}
			if v, err := d.Secrets.GetSetting(k); err == nil {
				secrets[k] = v
			}
		}
		plan, err := policyedit.PrepareUpdate(ctx, c.Client, a.UpdateRequest, secrets)
		if err != nil {
			return nil, nil, err
		}
		token := ConfirmToken(c.Client.Host(), "fm_policy_update", c.Name, a.UpdateRequest, plan.State())
		if a.ConfirmToken == "" {
			return editFlow{fleet: c.Name, token: token, ready: plan.Ready(), preview: plan, blockers: plan.Blockers,
				nextReady: fmt.Sprintf("Show the user every change, the warnings, the enrichment notes and the sensor groups that get it. After they approve changing sensor policy %s on %s, call fm_policy_update again with the same arguments plus confirm_token.", plan.Policy, c.Name),
				nextIdle:  "Nothing to change: the policy already has these values. Tell the user."}.previewResult()
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match: the arguments or the policy changed since the preview; preview again")
		}
		if err := redeemToken(token); err != nil {
			return nil, nil, err
		}
		res, runErr := policyedit.ApplyUpdate(ctx, c.Client, plan)
		if runErr == nil {
			for _, k := range a.SecretSettings {
				_ = d.Secrets.DeleteSetting(k)
			}
		}
		var ver []string
		if res != nil {
			ver = res.Verification
		}
		return finish("fm_policy_update", c.Name, c.Username, token, map[string]any{"policy": plan.Policy, "changes": plan.Changes, "result": res}, res, runErr, ver,
			"read back: every change is in place and nothing else in the policy changed; secrets used were removed from the secret store")
	})

	type deleteArgs struct {
		target
		policyedit.DeleteRequest
		ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this delete's preview; when it matches, the policy is deleted"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_policy_delete",
		Description: guideFirst("delete-sensor-policy") + "Delete a sensor policy and, if the user wants, the objects only it uses (Suricata policy, YARA ruleset, intel/input/resource/CA bundle collections, package bundle). " +
			"The preview lists every reference and which other policies use it; objects another policy uses are always kept. A policy a sensor group uses, or the global policy, cannot be deleted. " +
			"Two steps: call without confirm_token for the preview, ask the user which unused objects to remove (remove_unused), and after they approve call again with the same arguments plus confirm_token.",
		Annotations: &mcp.ToolAnnotations{Title: "Delete sensor policy", DestructiveHint: &t, OpenWorldHint: &t},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a deleteArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.writeConn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		plan, err := policyedit.PrepareDelete(ctx, c.Client, a.DeleteRequest)
		if err != nil {
			return nil, nil, err
		}
		token := ConfirmToken(c.Client.Host(), "fm_policy_delete", c.Name, a.DeleteRequest, plan.State())
		if a.ConfirmToken == "" {
			return editFlow{fleet: c.Name, token: token, ready: plan.Ready(), preview: plan, blockers: plan.Blockers,
				nextReady: fmt.Sprintf("Show the user the references, which are used only by this policy and which will be removed. Ask whether to remove the unused ones too (remove_unused; preview again if that changes). After they approve deleting sensor policy %s on %s, call fm_policy_delete again with the same arguments plus confirm_token.", plan.Policy, c.Name)}.previewResult()
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match: the arguments or the policy changed since the preview; preview again")
		}
		if err := redeemToken(token); err != nil {
			return nil, nil, err
		}
		res, runErr := policyedit.ApplyDelete(ctx, c.Client, plan)
		var ver []string
		if res != nil {
			ver = res.Verification
		}
		return finish("fm_policy_delete", c.Name, c.Username, token, map[string]any{"policy": plan.Policy, "references": plan.References, "result": res}, res, runErr, ver,
			"read back: the policy and the removed objects are gone")
	})

	type groupArgs struct {
		target
		policyedit.GroupRequest
		ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this change's preview; when it matches, the change is made"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_group_manage",
		Description: guideFirst("change-sensor-policy") + "Create, change or delete a sensor group: its name, description and sensor policy, and which sensors are in it (a sensor is in one group; moving it gives it the group's policy). " +
			"The preview shows each sensor's group and policy before and after, licensed features the new policy turns on that a sensor has no active license for, and sensors that are not connected. Sensors taken out of a group, or left by a deleted group, become unassigned and keep their configuration. " +
			"Two steps: call without confirm_token for the preview; after the user approves, call again with the same arguments plus confirm_token.",
		Annotations: &mcp.ToolAnnotations{Title: "Manage sensor group", DestructiveHint: &f, OpenWorldHint: &t},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a groupArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.writeConn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		plan, err := policyedit.PrepareGroup(ctx, c.Client, a.GroupRequest)
		if err != nil {
			return nil, nil, err
		}
		token := ConfirmToken(c.Client.Host(), "fm_group_manage", c.Name, a.GroupRequest, plan.State())
		if a.ConfirmToken == "" {
			return editFlow{fleet: c.Name, token: token, ready: plan.Ready(), preview: plan, blockers: plan.Blockers,
				nextReady: fmt.Sprintf("Show the user the group change, every sensor's group and policy before and after, and the license warnings. After they approve, call fm_group_manage again on %s with the same arguments plus confirm_token.", c.Name),
				nextIdle:  "Nothing to change. Tell the user."}.previewResult()
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match: the arguments, groups or sensors changed since the preview; preview again")
		}
		if err := redeemToken(token); err != nil {
			return nil, nil, err
		}
		res, runErr := policyedit.ApplyGroup(ctx, c.Client, plan)
		var ver []string
		if res != nil {
			ver = res.Verification
		}
		return finish("fm_group_manage", c.Name, c.Username, token, map[string]any{"action": plan.Action, "group": plan.Group, "changes": plan.Changes, "sensors": plan.Sensors, "result": res}, res, runErr, ver,
			"read back: the group and every moved sensor are as planned")
	})

	type collectionArgs struct {
		target
		policyedit.CollectionRequest
		ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this change's preview; when it matches, the change is made"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_collection_manage",
		Description: guideFirst("manage-collections") + "Create, change or delete a content collection of any kind: intel, input, asset classification (resource) or CA bundle collection, or a YARA ruleset. In the same call, add or remove existing sources (by id, alias or file name; including ones another tool such as Corelight-update created, with no upload), rename it, and link it to or unlink it from sensor policies. " +
			"The preview shows the sources and policies after the change, a policy's current collection that a link replaces, disabled sources, sources sharing a file name, sources another tool manages, the sensor groups affected and, for input collections, which loaded package on the connected sensors reads each file. A collection a policy still uses cannot be deleted unless the same call unlinks it; deleting a collection keeps its sources. After applying, it reads the collection and the policies back. " +
			"Use fm_content_push to upload a file. Two steps: call without confirm_token for the preview; after the user approves, call again with the same arguments plus confirm_token.",
		Annotations: &mcp.ToolAnnotations{Title: "Manage collection", DestructiveHint: &t, OpenWorldHint: &t},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a collectionArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.writeConn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		plan, err := policyedit.PrepareCollection(ctx, c.Client, a.CollectionRequest)
		if err != nil {
			return nil, nil, err
		}
		token := ConfirmToken(c.Client.Host(), "fm_collection_manage", c.Name, a.CollectionRequest, plan.State())
		if a.ConfirmToken == "" {
			return editFlow{fleet: c.Name, token: token, ready: plan.Ready(), preview: plan, blockers: plan.Blockers,
				nextReady: fmt.Sprintf("Show the user the changes, the sources and policies after it, the warnings, the enrichment notes and the sensor groups affected. After they approve the %s of %s %q on %s, call fm_collection_manage again with the same arguments plus confirm_token.", plan.Action, plan.What, plan.Collection.Name, c.Name),
				nextIdle:  "Nothing to change: the collection already is as asked. Tell the user."}.previewResult()
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match: the arguments, collections, sources or policies changed since the preview; preview again")
		}
		if err := redeemToken(token); err != nil {
			return nil, nil, err
		}
		res, runErr := policyedit.ApplyCollection(ctx, c.Client, plan)
		var ver []string
		if res != nil {
			ver = res.Verification
		}
		return finish("fm_collection_manage", c.Name, c.Username, token, map[string]any{"action": plan.Action, "kind": plan.Kind, "collection": plan.Collection, "changes": plan.Changes, "result": res}, res, runErr, ver,
			"read back: the collection's sources and every changed policy link are as planned")
	})
}
