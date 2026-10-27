package users

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Actions of a Request.
const (
	Create   = "create"
	Update   = "update"
	Reset2FA = "reset_2fa"
	Delete   = "delete"
)

// Request is one change to one user.
type Request struct {
	Action    string  `json:"action" jsonschema:"create, update, reset_2fa or delete"`
	Username  string  `json:"username" jsonschema:"the user's username (or id); fleet-mcp looks up the id Fleet Manager needs"`
	Role      string  `json:"role,omitempty" jsonschema:"create (required) or update: role by display name (admin, monitor, editor, rules_editor, downloader), name (global_viewer) or id; fm_users_list shows the roles"`
	FirstName *string `json:"first_name,omitempty" jsonschema:"create or update: first name"`
	LastName  *string `json:"last_name,omitempty" jsonschema:"create or update: last name"`
	// Require2FA turns 2fa.enabled on or off.
	Require2FA *bool `json:"require_2fa,omitempty" jsonschema:"create or update: require two-factor authentication (the user enrolls an authenticator app at the next login); false turns it off"`
	// PasswordSetting names the setting secret with a new user's initial
	// password.
	PasswordSetting string `json:"password_setting,omitempty" jsonschema:"create: name of the secret holding the initial password, which the user stores at a hidden prompt with fleet-mcp secret set-setting <name> (default fm-user:<username>); it is deleted after the user is created, and the new user must change the password at first login"`
}

// Secrets is the part of the secret store a create uses.
type Secrets interface {
	GetSetting(name string) (string, error)
	DeleteSetting(name string) error
}

// Change is one field an action changes.
type Change struct {
	Field string `json:"field"`
	From  any    `json:"from,omitempty"`
	To    any    `json:"to,omitempty"`
}

// Plan is what a Request will do.
type Plan struct {
	Action   string   `json:"action"`
	Username string   `json:"username"`
	ID       string   `json:"id,omitempty"`
	Current  *Summary `json:"current,omitempty"`
	Changes  []Change `json:"changes,omitempty"`
	Steps    []string `json:"steps,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Blockers []string `json:"blockers,omitempty"`

	body      map[string]any
	pwSetting string
	stateHash string
	nothing   bool
}

// Ready reports whether the plan changes something and nothing blocks it.
func (p *Plan) Ready() bool { return len(p.Blockers) == 0 && !p.nothing }

// State identifies the user record the plan was built from, so a confirm
// token goes stale when the user changes after the preview.
func (p *Plan) State() string { return p.stateHash }

func (p *Plan) block(f string, a ...any) { p.Blockers = append(p.Blockers, fmt.Sprintf(f, a...)) }
func (p *Plan) warn(f string, a ...any)  { p.Warnings = append(p.Warnings, fmt.Sprintf(f, a...)) }

// DefaultPasswordSetting is the setting a create reads when the request
// names none.
func DefaultPasswordSetting(username string) string { return "fm-user:" + username }

// PlanChange reads the users and roles and plans r; it changes nothing.
// self is the username this server logs in with; sec may be nil except for
// a create.
func PlanChange(ctx context.Context, c Client, sec Secrets, self string, r Request) (*Plan, error) {
	r.Username = strings.TrimSpace(r.Username)
	if r.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	st, err := read(ctx, c)
	if err != nil {
		return nil, err
	}
	p := &Plan{Action: r.Action, Username: r.Username}
	u := st.findUser(r.Username)
	if u != nil {
		p.Username, p.ID = str(u["username"]), str(u["id"])
		s := summarize(u, self)
		p.Current = &s
	}
	isSelf := u != nil && self != "" && p.Username == self
	admins := st.admins()
	lastAdmin := p.Current != nil && p.Current.Admin && len(admins) == 1

	switch r.Action {
	case Create:
		planCreate(st, sec, r, p, u)
	case Update:
		if u == nil {
			p.block("no user %q on this Fleet Manager", r.Username)
			break
		}
		planUpdate(st, r, p, u, isSelf, lastAdmin)
	case Reset2FA:
		if u == nil {
			p.block("no user %q on this Fleet Manager", r.Username)
			break
		}
		switch p.Current.TwoFA {
		case "off":
			p.block("2FA is not enabled for %s, so there is nothing to reset (Fleet Manager answers 409 \"2FA must be enabled for it to be reset\"); turn it on with action update, require_2fa: true", p.Username)
		case "required, not enrolled":
			p.nothing = true
			p.warn("%s has 2FA turned on but has not enrolled yet; they enroll at their next login, so there is nothing to reset", p.Username)
		default:
			p.Changes = append(p.Changes, Change{Field: "2fa.is_enrolled", From: true, To: false})
			p.Steps = append(p.Steps, fmt.Sprintf("POST /fleet/v1/users/%s/2fa/reset", p.ID))
			p.warn("%s must enroll an authenticator app again at the next login, and Fleet Manager also requires a new password then", p.Username)
		}
	case Delete:
		if u == nil {
			p.block("no user %q on this Fleet Manager", r.Username)
			break
		}
		if isSelf {
			p.block("%s is the account fleet-mcp logs in with on this Fleet Manager; it cannot delete itself", p.Username)
		}
		if lastAdmin {
			p.block("%s is the only admin; deleting it would leave nobody who can manage users", p.Username)
		}
		p.Changes = append(p.Changes, Change{Field: "user", From: p.Username})
		p.Steps = append(p.Steps, fmt.Sprintf("DELETE /fleet/v1/users/%s", p.ID))
		p.warn("this cannot be undone; an integration that logs in as %s (e.g. Corelight-update or a SIEM connector) stops working", p.Username)
	default:
		return nil, fmt.Errorf("action must be create, update, reset_2fa or delete")
	}
	if len(p.Changes) == 0 && len(p.Blockers) == 0 {
		p.nothing = true
	}
	raw, _ := json.Marshal(u)
	h := sha256.Sum256(raw)
	p.stateHash = hex.EncodeToString(h[:8])
	if r.Action == Create {
		p.stateHash += "|" + p.pwSetting
	}
	return p, nil
}

func planCreate(st *state, sec Secrets, r Request, p *Plan, existing map[string]any) {
	if existing != nil {
		p.block("a user %q already exists; use action update", p.Username)
	}
	p.Current = nil
	if r.Role == "" {
		p.block("a new user needs a role: %s", st.roleNames())
	}
	body := map[string]any{"username": r.Username, "authenticator": "local", "require_password_change": true}
	if r.Role != "" {
		ro := st.findRole(r.Role)
		if ro == nil {
			p.block("no role %q; roles: %s", r.Role, st.roleNames())
		} else {
			body["roles"] = []any{map[string]any{"id": ro["id"]}}
			p.Changes = append(p.Changes, Change{Field: "role", To: str(ro["display_name"])})
			if str(ro["name"]) == adminRole {
				p.warn("admin can manage users, backups, secrets and every sensor; give it only to people who administer Fleet Manager")
			}
		}
	}
	if r.FirstName != nil {
		body["first_name"] = *r.FirstName
		p.Changes = append(p.Changes, Change{Field: "first_name", To: *r.FirstName})
	}
	if r.LastName != nil {
		body["last_name"] = *r.LastName
		p.Changes = append(p.Changes, Change{Field: "last_name", To: *r.LastName})
	}
	if r.Require2FA != nil {
		body["settings"] = map[string]any{"2fa.enabled": *r.Require2FA}
		p.Changes = append(p.Changes, Change{Field: "2fa.enabled", To: *r.Require2FA})
	}
	p.pwSetting = r.PasswordSetting
	if p.pwSetting == "" {
		p.pwSetting = DefaultPasswordSetting(r.Username)
	}
	switch {
	case sec == nil:
		p.block("no secret store configured, so there is no way to pass the initial password")
	default:
		if _, err := sec.GetSetting(p.pwSetting); err != nil {
			p.block("the initial password is not stored: %v", err)
		}
	}
	p.Changes = append(p.Changes, Change{Field: "password", To: "initial password from secret " + p.pwSetting + "; must be changed at first login"})
	p.body = body
	p.Steps = append(p.Steps, "POST /fleet/v1/users (local account)", "read the user back and check role and 2FA", "delete the stored initial password "+p.pwSetting)
	p.warn("give the user the initial password outside the chat; Fleet Manager makes them choose a new one at first login")
}

// putFields are the fields PUT /fleet/v1/users/{id} accepts.
var putFields = []string{"id", "first_name", "last_name", "permission_for_new_groups", "permissions", "roles", "settings", "tenant_id", "theme"}

func planUpdate(st *state, r Request, p *Plan, u map[string]any, isSelf, lastAdmin bool) {
	body := map[string]any{}
	for _, k := range putFields {
		if v, ok := u[k]; ok {
			body[k] = v
		}
	}
	if r.Role != "" {
		ro := st.findRole(r.Role)
		cur := roleList(u)
		switch {
		case ro == nil:
			p.block("no role %q; roles: %s", r.Role, st.roleNames())
		case len(cur) == 1 && str(cur[0]["id"]) == str(ro["id"]):
			p.warn("%s already has the %s role", p.Username, str(ro["display_name"]))
		default:
			body["roles"] = []any{map[string]any{"id": ro["id"]}}
			p.Changes = append(p.Changes, Change{Field: "role", From: strings.Join(p.Current.Roles, ", "), To: str(ro["display_name"])})
			demote := p.Current.Admin && str(ro["name"]) != adminRole
			if demote && isSelf {
				p.block("%s is the account fleet-mcp logs in with; taking its admin role away would stop fleet-mcp from managing users and more", p.Username)
			}
			if demote && lastAdmin {
				p.block("%s is the only admin; demoting it would leave nobody who can manage users", p.Username)
			}
			if str(ro["name"]) == adminRole {
				p.warn("admin can manage users, backups, secrets and every sensor")
			}
		}
	}
	setName := func(field string, v *string) {
		if v != nil && str(u[field]) != *v {
			body[field] = *v
			p.Changes = append(p.Changes, Change{Field: field, From: str(u[field]), To: *v})
		}
	}
	setName("first_name", r.FirstName)
	setName("last_name", r.LastName)
	if r.Require2FA != nil {
		settings := map[string]any{}
		if cur, ok := u["settings"].(map[string]any); ok {
			for k, v := range cur {
				settings[k] = v
			}
		}
		if (settings["2fa.enabled"] == true) != *r.Require2FA {
			if *r.Require2FA && isSelf {
				p.block("fleet-mcp logs in to Fleet Manager as %s through the API and cannot answer a 2FA prompt; keep 2FA off for this account (use a dedicated account with a strong password)", p.Username)
			}
			settings["2fa.enabled"] = *r.Require2FA
			body["settings"] = settings
			p.Changes = append(p.Changes, Change{Field: "2fa.enabled", From: !*r.Require2FA, To: *r.Require2FA})
			if *r.Require2FA {
				p.warn("%s must enroll an authenticator app at the next login", p.Username)
			} else if settings["2fa.is_enrolled"] == true {
				p.warn("%s is enrolled; turning 2FA off removes the second factor from their logins", p.Username)
			}
		}
	}
	p.body = body
	p.Steps = append(p.Steps, fmt.Sprintf("PUT /fleet/v1/users/%s with every field as read and only the change applied (settings, which hold the 2FA enrollment, are sent back unchanged otherwise)", p.ID), "read the user back and check the change")
}

// Result is what Apply did.
type Result struct {
	Done     []string `json:"done"`
	Verified []string `json:"verified,omitempty"`
	Problems []string `json:"problems,omitempty"`
	ID       string   `json:"id,omitempty"`
}

// Apply carries out a ready plan and reads the user back.
func Apply(ctx context.Context, c Client, sec Secrets, p *Plan) (*Result, error) {
	if !p.Ready() {
		return nil, fmt.Errorf("nothing to do, or blocked: %s", strings.Join(p.Blockers, "; "))
	}
	res := &Result{ID: p.ID}
	switch p.Action {
	case Create:
		pw, err := sec.GetSetting(p.pwSetting)
		if err != nil {
			return nil, err
		}
		body := map[string]any{"password": pw}
		for k, v := range p.body {
			body[k] = v
		}
		resp, err := do(ctx, c, http.MethodPost, usersPath, body)
		if err != nil {
			return nil, err
		}
		var created struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(resp.Body, &created)
		res.ID = created.ID
		res.Done = append(res.Done, "created "+p.Username)
		if err := sec.DeleteSetting(p.pwSetting); err != nil {
			res.Problems = append(res.Problems, "deleting the stored initial password failed: "+err.Error())
		} else {
			res.Done = append(res.Done, "deleted the stored initial password "+p.pwSetting)
		}
	case Update:
		if _, err := do(ctx, c, http.MethodPut, usersPath+"/"+p.ID, p.body); err != nil {
			return nil, err
		}
		res.Done = append(res.Done, "updated "+p.Username)
	case Reset2FA:
		if _, err := do(ctx, c, http.MethodPost, usersPath+"/"+p.ID+"/2fa/reset", nil); err != nil {
			return nil, err
		}
		res.Done = append(res.Done, "reset 2FA of "+p.Username)
	case Delete:
		if _, err := do(ctx, c, http.MethodDelete, usersPath+"/"+p.ID, nil); err != nil {
			return nil, err
		}
		res.Done = append(res.Done, "deleted "+p.Username)
	}
	verify(ctx, c, p, res)
	return res, nil
}

// verify reads the user back and records whether the change holds.
func verify(ctx context.Context, c Client, p *Plan, res *Result) {
	st, err := read(ctx, c)
	if err != nil {
		res.Problems = append(res.Problems, "reading the users back failed: "+err.Error())
		return
	}
	u := st.findUser(p.Username)
	if p.Action == Delete {
		if u == nil {
			res.Verified = append(res.Verified, p.Username+" is gone")
		} else {
			res.Problems = append(res.Problems, p.Username+" is still listed")
		}
		return
	}
	if u == nil {
		res.Problems = append(res.Problems, p.Username+" is not listed after the change")
		return
	}
	s := summarize(u, "")
	settings, _ := u["settings"].(map[string]any)
	for _, ch := range p.Changes {
		var got any
		switch ch.Field {
		case "role":
			got = strings.Join(s.Roles, ", ")
		case "first_name", "last_name":
			got = str(u[ch.Field])
		case "2fa.enabled", "2fa.is_enrolled":
			got = settings[ch.Field] == true
		default:
			continue
		}
		if fmt.Sprint(got) == fmt.Sprint(ch.To) {
			res.Verified = append(res.Verified, fmt.Sprintf("%s is %v", ch.Field, got))
		} else {
			res.Problems = append(res.Problems, fmt.Sprintf("%s is %v, expected %v", ch.Field, got, ch.To))
		}
	}
	if p.Action == Create && !s.PasswordChangePending {
		res.Problems = append(res.Problems, "the new user is not required to change the initial password")
	}
	if p.Action == Update && p.Current != nil && p.Current.TwoFA == "enrolled" && s.TwoFA != "enrolled" && !hasChange(p, "2fa.enabled") {
		res.Problems = append(res.Problems, "the user's 2FA enrollment was lost by the update")
	}
}

func hasChange(p *Plan, field string) bool {
	for _, ch := range p.Changes {
		if ch.Field == field {
			return true
		}
	}
	return false
}
