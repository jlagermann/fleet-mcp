package users

import (
	"context"
	"sort"
	"strings"
)

const (
	allActionsPath = "/fleet/v1/roles/all_actions"
	// notInCatalog is the category of an action a role grants that the
	// permission catalog does not list (29.2: list_tokens, revoke_tokens,
	// rotate_global_key).
	notInCatalog = "(not in the permission catalog)"
)

// Permission is one action a role grants.
type Permission struct {
	Action   string `json:"action"`
	Display  string `json:"display,omitempty"`
	Category string `json:"category,omitempty"`
}

// PermissionChange is what a role change grants and takes away. It comes
// from the roles' own permission lists, so custom roles are covered too.
type PermissionChange struct {
	From      string       `json:"from,omitempty"`
	To        string       `json:"to"`
	Gained    []Permission `json:"gained,omitempty"`
	Lost      []Permission `json:"lost,omitempty"`
	Unchanged int          `json:"unchanged"`
	// Note says when the catalog with display names could not be read.
	Note string `json:"note,omitempty"`
}

// sensitive names the actions worth calling out in a warning.
var sensitive = []struct{ action, what string }{
	{"edit_all_users", "manage users and their roles"},
	{"update_auth_providers", "change login providers (LDAP, SAML, RADIUS, TACACS+)"},
	{"edit_system_security_settings", "change system security settings"},
	{"edit_backups", "create and restore backups"},
	{"rotate_global_key", "rotate the global key"},
	{"revoke_tokens", "revoke API tokens"},
	{"edit_all_oauth2_clients", "manage OAuth2 API clients"},
	{"edit_secrets", "change secrets"},
	{"edit_tenants_meta", "manage organizations"},
	{"get_audit_log", "download audit logs"},
	{"edit_sensors", "change sensors"},
	{"edit_policies", "change sensor policies"},
	{"edit_global_policy", "change the global policy"},
	{"edit_suricata_policies", "change Suricata policies"},
}

// catalog returns the permission catalog by action; an error leaves only
// the action names.
func catalog(ctx context.Context, c Client) (map[string]Permission, error) {
	var cats []struct {
		Category string `json:"category"`
		Actions  []struct {
			Action  string `json:"action"`
			Display string `json:"display"`
		} `json:"actions"`
	}
	if err := c.GetJSON(ctx, allActionsPath, nil, &cats); err != nil {
		return nil, err
	}
	out := map[string]Permission{}
	for _, cat := range cats {
		for _, a := range cat.Actions {
			out[a.Action] = Permission{Action: a.Action, Display: a.Display, Category: cat.Category}
		}
	}
	return out, nil
}

// actions returns the permission actions of the roles with these ids,
// falling back to the copies inside the user record.
func (st *state) actions(roles []map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, r := range roles {
		src := r
		for _, ro := range st.roles {
			if str(ro["id"]) == str(r["id"]) {
				src = ro
			}
		}
		for _, a := range strings.Split(str(src["permission_actions"]), ",") {
			if a = strings.TrimSpace(a); a != "" {
				out[a] = true
			}
		}
	}
	return out
}

// permissionChange compares the actions of the old roles with the new role.
func permissionChange(from, to map[string]bool, fromName, toName string, cat map[string]Permission) *PermissionChange {
	pc := &PermissionChange{From: fromName, To: toName}
	perm := func(a string) Permission {
		if p, ok := cat[a]; ok {
			return p
		}
		if cat != nil {
			return Permission{Action: a, Category: notInCatalog}
		}
		return Permission{Action: a}
	}
	for a := range to {
		if from[a] {
			pc.Unchanged++
		} else {
			pc.Gained = append(pc.Gained, perm(a))
		}
	}
	for a := range from {
		if !to[a] {
			pc.Lost = append(pc.Lost, perm(a))
		}
	}
	order := func(ps []Permission) {
		sort.Slice(ps, func(i, j int) bool {
			if ps[i].Category != ps[j].Category {
				return ps[i].Category < ps[j].Category
			}
			return ps[i].Action < ps[j].Action
		})
	}
	order(pc.Gained)
	order(pc.Lost)
	return pc
}

// describeRoleChange adds the permission change of a role change to p.
func describeRoleChange(ctx context.Context, c Client, st *state, p *Plan, oldRoles []map[string]any, newRole map[string]any, groupPerms int) {
	cat, err := catalog(ctx, c)
	fromName := ""
	if p.Current != nil {
		fromName = strings.Join(p.Current.Roles, ", ")
	}
	pc := permissionChange(st.actions(oldRoles), st.actions([]map[string]any{newRole}), fromName, str(newRole["display_name"]), cat)
	if err != nil {
		pc.Note = "the permission catalog could not be read (" + err.Error() + "); only action names are shown"
	}
	p.Permissions = pc
	has := func(ps []Permission, a string) bool {
		for _, x := range ps {
			if x.Action == a {
				return true
			}
		}
		return false
	}
	var gained, lost []string
	for _, s := range sensitive {
		if has(pc.Gained, s.action) {
			gained = append(gained, s.what)
		}
		if has(pc.Lost, s.action) {
			lost = append(lost, s.what)
		}
	}
	who := p.Username
	if p.Action == Create {
		p.warn("%s gets %d permissions from the %s role (permission_changes lists them)", who, len(pc.Gained), pc.To)
	} else {
		p.warn("role %s → %s: %s gains %d and loses %d permissions, %d stay (permission_changes lists them)", pc.From, pc.To, who, len(pc.Gained), len(pc.Lost), pc.Unchanged)
	}
	if len(gained) > 0 {
		p.warn("%s will be able to: %s", who, strings.Join(gained, "; "))
	}
	if len(lost) > 0 {
		p.warn("%s will no longer be able to: %s", who, strings.Join(lost, "; "))
	}
	if groupPerms > 0 {
		p.warn("%s also has %d per-group permission(s); they stay as they are", who, groupPerms)
	}
	if str(newRole["type"]) != "" && str(newRole["type"]) != "predefined" {
		p.warn("%s is a custom (%s) role: check its permissions in permission_changes", pc.To, str(newRole["type"]))
	}
}
