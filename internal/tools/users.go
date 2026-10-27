package tools

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
	"github.com/jlagermann/fleet-mcp/internal/users"
)

func registerUsers(s *mcp.Server, d *Deps) {
	type listArgs struct {
		Fleets []string `json:"fleets,omitempty" jsonschema:"names of the Fleet Managers to read (default: all, see fm_fleets)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_users_list",
		Description: "List the user accounts of every Fleet Manager (or the ones named), read in parallel: username, id, roles, admin, 2FA state (off, required but not enrolled, enrolled), pending password change, failed logins, per-group permissions and which account fleet-mcp itself uses; " +
			"the roles with their number of permissions, the login providers (LDAP, SAML, RADIUS, TACACS+) and whether they are on, and findings such as admins without 2FA, everyone being admin, unused or test accounts. Use fm_user_manage to change a user.",
		Annotations: readOnly("List users"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a listArgs) (*mcp.CallToolResult, any, error) {
		d.Fleets.Reload()
		list, _ := d.Fleets.List()
		var all []string
		for _, f := range list {
			all = append(all, f.Name)
		}
		names, err := pickFleets(all, a.Fleets)
		if err != nil {
			return nil, nil, err
		}
		type fleetUsers struct {
			Fleet string `json:"fleet"`
			*users.Report
			Error string `json:"error,omitempty"`
		}
		out := make([]fleetUsers, len(names))
		var wg sync.WaitGroup
		for i, n := range names {
			wg.Add(1)
			go func(i int, name string) {
				defer wg.Done()
				out[i].Fleet = name
				cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
				defer cancel()
				c, err := d.conn(name)
				if err != nil {
					out[i].Error = err.Error()
					return
				}
				r, err := users.List(cctx, c.Client, c.Username)
				if err != nil {
					out[i].Error = err.Error()
					return
				}
				out[i].Report = r
			}(i, n)
		}
		wg.Wait()
		res, err := jsonResult(map[string]any{"fleets": out})
		return res, nil, err
	})
}

// pickFleets returns the names in all that want lists, in all's order, or
// all of them when want is empty.
func pickFleets(all, want []string) ([]string, error) {
	if len(want) == 0 {
		return all, nil
	}
	known := map[string]bool{}
	for _, n := range all {
		known[n] = true
	}
	wanted := map[string]bool{}
	for _, n := range want {
		if !known[n] {
			return nil, fmt.Errorf("no Fleet Manager %q (see fm_fleets)", n)
		}
		wanted[n] = true
	}
	var out []string
	for _, n := range all {
		if wanted[n] {
			out = append(out, n)
		}
	}
	return out, nil
}

func registerUserManage(s *mcp.Server, d *Deps) {
	t := true
	type manageArgs struct {
		target
		users.Request
		ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this change's preview; when it matches, the change is made"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_user_manage",
		Description: guideFirst("manage-users") + "Create, update (role, name, require 2FA), reset the 2FA of, or delete one Fleet Manager user, by username (fleet-mcp looks up the id the API needs). " +
			"A role change (and a create) previews the permissions gained and lost, from the roles' own permission lists, so custom roles are covered. Updates send back every field Fleet Manager returned with only the change applied, so 2FA enrollment and permissions are kept. A new user's initial password comes from a secret the user stores at a hidden prompt (fleet-mcp secret set-setting), never from the chat, and must be changed at first login. " +
			"Refuses to delete or demote the last admin or fleet-mcp's own account, and to turn on 2FA for fleet-mcp's own account. " +
			"Two steps: call without confirm_token for a preview; after the user approves, call again with the same arguments plus confirm_token.",
		Annotations: &mcp.ToolAnnotations{Title: "Manage Fleet Manager user", DestructiveHint: &t, OpenWorldHint: &t},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a manageArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.writeConn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		var sec users.Secrets
		if d.Secrets != nil {
			sec = d.Secrets
		}
		plan, err := users.PlanChange(ctx, c.Client, sec, c.Username, a.Request)
		if err != nil {
			return nil, nil, err
		}
		token := ConfirmToken(c.Client.Host(), "fm_user_manage", c.Name, a.Request, plan.State())
		if a.ConfirmToken == "" {
			out := map[string]any{"preview": true, "fleet": c.Name, "ready": plan.Ready(), "plan": plan}
			switch {
			case len(plan.Blockers) > 0 && a.Action == users.Create:
				out["next"] = "Explain the blockers to the user and preview again once they are resolved. The initial password never goes through the chat: the user stores it at a hidden prompt in their terminal with " + secrets.Command("secret", "set-setting", users.DefaultPasswordSetting(plan.Username)) + " (or the name given as password_setting)."
			case len(plan.Blockers) > 0:
				out["next"] = "Explain the blockers to the user; nothing can be changed as asked."
			case !plan.Ready():
				out["next"] = "Nothing to change."
			default:
				out["confirm_token"] = issueToken(token)
				out["next"] = fmt.Sprintf("Show the user the changes, steps and warnings. After they approve the %s of %s on %s, call fm_user_manage again with the same arguments plus confirm_token.", a.Action, plan.Username, c.Name)
			}
			r, err := jsonResult(out)
			return r, nil, err
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match: the arguments or the user changed since the preview; preview again")
		}
		if err := redeemToken(token); err != nil {
			return nil, nil, err
		}
		res, runErr := users.Apply(ctx, c.Client, sec, plan)
		body := map[string]any{"action": plan.Action, "username": plan.Username, "id": plan.ID, "changes": plan.Changes}
		if res != nil {
			body["result"] = res
		}
		rec := audit.Record{Fleet: c.Name, User: c.Username, Tool: "fm_user_manage", Token: token, Body: body}
		if runErr != nil {
			rec.Error = runErr.Error()
		}
		var notes []string
		if err := d.Audit.Write(rec); err != nil {
			notes = append(notes, "WARNING: audit log write failed: "+err.Error())
		}
		out := map[string]any{"executed": runErr == nil, "fleet": c.Name, "action": plan.Action, "username": plan.Username, "result": res}
		if runErr != nil {
			out["error"] = runErr.Error()
		}
		r, err := jsonResult(out, notes...)
		if r != nil && (runErr != nil || (res != nil && len(res.Problems) > 0)) {
			r.IsError = true
		}
		return r, nil, err
	})
}
