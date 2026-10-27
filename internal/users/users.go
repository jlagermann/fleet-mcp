// Package users reads and changes Fleet Manager user accounts: users,
// their roles and 2FA state, roles and login providers.
//
// What the Fleet Manager 29.2 API does (tested live):
//   - Users are addressed by their UUID (GET /fleet/v1/users lists id and
//     username); a username in the path gives 404 "User not found".
//   - PUT /fleet/v1/users/{id} takes only names, roles, group permissions,
//     settings, tenant and theme, and may reset what it omits, so an update
//     sends back everything it read with only the change applied.
//   - settings holds the 2FA state (2fa.enabled, 2fa.is_enrolled and the
//     TOTP secret), so it is sent back exactly as read.
//   - POST /fleet/v1/users/{id}/2fa/reset clears 2fa.is_enrolled and keeps
//     2fa.enabled, so the user enrolls again at the next login; it also
//     sets require_password_change. It answers 409 when 2FA is not enabled.
//   - PATCH /fleet/v1/users (bulk update) is not used: its semantics are
//     undocumented.
package users

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
)

const (
	usersPath     = "/fleet/v1/users"
	rolesPath     = "/fleet/v1/roles"
	providersPath = "/fleet/v1/auth/providers"
	// adminRole is the predefined role with access to user management.
	adminRole = "global_admin"
)

// Client is the part of the Fleet Manager client this package uses.
type Client interface {
	GetJSON(ctx context.Context, path string, query url.Values, out any) error
	Do(ctx context.Context, method, path string, query url.Values, body []byte, contentType string) (*fleet.Response, error)
}

// Summary is one user as the list shows it.
type Summary struct {
	Username      string   `json:"username"`
	ID            string   `json:"id"`
	Name          string   `json:"name,omitempty"`
	Authenticator string   `json:"authenticator,omitempty"`
	Roles         []string `json:"roles"`
	Admin         bool     `json:"admin"`
	// GroupPermissions is the number of per-group permissions on top of
	// the roles.
	GroupPermissions int    `json:"group_permissions,omitempty"`
	NewGroups        string `json:"permission_for_new_groups,omitempty"`
	// TwoFA is off, "required, not enrolled" or enrolled.
	TwoFA                 string `json:"two_factor"`
	PasswordChangePending bool   `json:"password_change_pending,omitempty"`
	FailedLogins          int    `json:"failed_logins,omitempty"`
	LastFailedLogin       string `json:"last_failed_login,omitempty"`
	Tenant                string `json:"tenant,omitempty"`
	// Self marks the account this server logs in with.
	Self bool `json:"fleet_mcp_account,omitempty"`
}

// Role is a Fleet Manager role.
type Role struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Display     string `json:"display_name"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
	Actions     int    `json:"actions"`
}

// Provider is a login provider (LDAP, SAML, RADIUS, TACACS+).
type Provider struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Enabled      bool   `json:"enabled"`
	RoleMappings int    `json:"role_mappings,omitempty"`
}

// Report is the user overview of one Fleet Manager.
type Report struct {
	Users     []Summary  `json:"users"`
	Roles     []Role     `json:"roles"`
	Providers []Provider `json:"login_providers,omitempty"`
	// ProvidersError is set when the providers could not be read.
	ProvidersError string   `json:"login_providers_error,omitempty"`
	Findings       []string `json:"findings,omitempty"`
}

// state is what the list and the planner read.
type state struct {
	users []map[string]any
	roles []map[string]any
}

func read(ctx context.Context, c Client) (*state, error) {
	st := &state{}
	if err := c.GetJSON(ctx, usersPath, nil, &st.users); err != nil {
		return nil, fmt.Errorf("reading users: %w", err)
	}
	var roles struct {
		Roles []map[string]any `json:"roles"`
	}
	if err := c.GetJSON(ctx, rolesPath, nil, &roles); err != nil {
		return nil, fmt.Errorf("reading roles: %w", err)
	}
	st.roles = roles.Roles
	return st, nil
}

// List reads the users, roles and login providers. self is the username
// this server logs in with.
func List(ctx context.Context, c Client, self string) (*Report, error) {
	st, err := read(ctx, c)
	if err != nil {
		return nil, err
	}
	r := &Report{}
	for _, u := range st.users {
		r.Users = append(r.Users, summarize(u, self))
	}
	sort.Slice(r.Users, func(i, j int) bool {
		return strings.ToLower(r.Users[i].Username) < strings.ToLower(r.Users[j].Username)
	})
	for _, ro := range st.roles {
		r.Roles = append(r.Roles, toRole(ro))
	}
	var prov struct {
		Providers []map[string]any `json:"providers"`
	}
	if err := c.GetJSON(ctx, providersPath, nil, &prov); err != nil {
		r.ProvidersError = err.Error()
	}
	for _, p := range prov.Providers {
		maps, _ := p["role_mappings"].([]any)
		r.Providers = append(r.Providers, Provider{ID: str(p["id"]), Type: str(p["type"]), Enabled: p["enable"] == true, RoleMappings: len(maps)})
	}
	r.Findings = findings(r)
	return r, nil
}

func findings(r *Report) []string {
	var out, admins, admin2fa, pending, failed, tests []string
	for _, u := range r.Users {
		if u.Admin {
			admins = append(admins, u.Username)
			if u.TwoFA != "enrolled" && !u.Self && u.Authenticator == "local" {
				admin2fa = append(admin2fa, u.Username)
			}
		}
		if u.PasswordChangePending {
			pending = append(pending, u.Username)
		}
		if u.FailedLogins > 0 {
			failed = append(failed, fmt.Sprintf("%s (%d)", u.Username, u.FailedLogins))
		}
		if l := strings.ToLower(u.Username); strings.Contains(l, "test") || strings.Contains(l, "demo") {
			tests = append(tests, u.Username)
		}
	}
	if n := len(r.Users); n > 2 && len(admins) == n {
		out = append(out, fmt.Sprintf("all %d users are admins; users who only view or change sensors and policies need the monitor or editor role", n))
	} else if len(admins) > 3 {
		out = append(out, fmt.Sprintf("%d of %d users are admins: %s", len(admins), len(r.Users), strings.Join(admins, ", ")))
	}
	if len(admin2fa) > 0 {
		out = append(out, "admins without 2FA: "+strings.Join(admin2fa, ", ")+" (for accounts people log in with: fm_user_manage update with require_2fa: true, and they enroll at their next login; leave it off for accounts integrations use, such as Corelight-update or a threat-intel or SIEM connector, which cannot answer a 2FA prompt)")
	}
	if len(pending) > 0 {
		out = append(out, "password change still pending (initial or reset password not changed yet; an unused account?): "+strings.Join(pending, ", "))
	}
	if len(failed) > 0 {
		out = append(out, "failed logins since the last good one: "+strings.Join(failed, ", "))
	}
	if len(tests) > 0 {
		out = append(out, "accounts that look like tests or demos: "+strings.Join(tests, ", "))
	}
	enabled := false
	for _, p := range r.Providers {
		enabled = enabled || p.Enabled
	}
	if !enabled && r.ProvidersError == "" && len(r.Providers) > 0 {
		out = append(out, "only local accounts: no LDAP, SAML, RADIUS or TACACS+ login is enabled")
	}
	return out
}

func summarize(u map[string]any, self string) Summary {
	s := Summary{
		Username:      str(u["username"]),
		ID:            str(u["id"]),
		Name:          strings.TrimSpace(str(u["first_name"]) + " " + str(u["last_name"])),
		Authenticator: str(u["authenticator"]),
		Admin:         u["is_fleet_admin"] == true,
		NewGroups:     str(u["permission_for_new_groups"]),
		Tenant:        str(u["tenant_id"]),
		TwoFA:         twoFA(u),
		FailedLogins:  num(u["pw_current_strikes"]),
	}
	s.PasswordChangePending = u["require_password_change"] == true
	s.Self = self != "" && s.Username == self
	if perms, ok := u["permissions"].([]any); ok {
		s.GroupPermissions = len(perms)
	}
	for _, ro := range roleList(u) {
		name := str(ro["display_name"])
		if name == "" {
			name = str(ro["name"])
		}
		s.Roles = append(s.Roles, name)
		if str(ro["name"]) == adminRole {
			s.Admin = true
		}
	}
	if t := str(u["pw_last_strike_time"]); t != "" && !strings.HasPrefix(t, "0001-") {
		s.LastFailedLogin = t
	}
	if s.NewGroups == "none" {
		s.NewGroups = ""
	}
	return s
}

func twoFA(u map[string]any) string {
	st, _ := u["settings"].(map[string]any)
	switch {
	case st["2fa.is_enrolled"] == true:
		return "enrolled"
	case st["2fa.enabled"] == true:
		return "required, not enrolled"
	}
	return "off"
}

func roleList(u map[string]any) []map[string]any {
	var out []map[string]any
	rs, _ := u["roles"].([]any)
	for _, r := range rs {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func toRole(ro map[string]any) Role {
	r := Role{ID: num(ro["id"]), Name: str(ro["name"]), Display: str(ro["display_name"]), Type: str(ro["type"]), Description: str(ro["description"])}
	if a := str(ro["permission_actions"]); a != "" {
		r.Actions = len(strings.Split(a, ","))
	}
	return r
}

// findUser returns the user with this username (exact, else the only
// case-insensitive match) or id.
func (st *state) findUser(ref string) map[string]any {
	var fold []map[string]any
	for _, u := range st.users {
		if str(u["username"]) == ref || str(u["id"]) == ref {
			return u
		}
		if strings.EqualFold(str(u["username"]), ref) {
			fold = append(fold, u)
		}
	}
	if len(fold) == 1 {
		return fold[0]
	}
	return nil
}

// findRole matches a role by name (global_viewer), display name (monitor)
// or id.
func (st *state) findRole(ref string) map[string]any {
	for _, ro := range st.roles {
		if strings.EqualFold(str(ro["name"]), ref) || strings.EqualFold(str(ro["display_name"]), ref) || str(ro["id"]) == ref {
			return ro
		}
	}
	return nil
}

func (st *state) roleNames() string {
	var n []string
	for _, ro := range st.roles {
		n = append(n, fmt.Sprintf("%s (%s)", str(ro["display_name"]), str(ro["name"])))
	}
	return strings.Join(n, ", ")
}

// admins returns the usernames that have the admin role.
func (st *state) admins() []string {
	var out []string
	for _, u := range st.users {
		if summarize(u, "").Admin {
			out = append(out, str(u["username"]))
		}
	}
	return out
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func num(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	}
	return 0
}

// do sends a request and turns an HTTP error into a Go error.
func do(ctx context.Context, c Client, method, path string, body any) (*fleet.Response, error) {
	var b []byte
	ct := ""
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return nil, err
		}
		ct = "application/json"
	}
	resp, err := c.Do(ctx, method, path, nil, b, ct)
	if err != nil {
		return nil, err
	}
	if resp.Status >= http.StatusBadRequest {
		return resp, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.Status, strings.TrimSpace(string(resp.Body)))
	}
	return resp, nil
}
