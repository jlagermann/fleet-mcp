package users

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
)

// fakeFM keeps users and roles in memory and answers like Fleet Manager
// 29.2 did in live tests.
type fakeFM struct {
	users []map[string]any
	roles []map[string]any
	sent  []string
}

func role(id int, name, display string) map[string]any {
	return map[string]any{"id": float64(id), "name": name, "display_name": display, "type": "predefined", "permission_actions": "a,b,c"}
}

func user(id, name string, roleID int, enabled, enrolled bool) map[string]any {
	return map[string]any{"id": id, "username": name, "authenticator": "local", "first_name": "F", "last_name": "L",
		"is_fleet_admin": roleID == 1, "permissions": []any{}, "permission_for_new_groups": "none", "tenant_id": "", "theme": "dark-theme",
		"require_password_change": false, "pw_last_strike_time": "0001-01-01T00:00:00Z",
		"roles":    []any{map[string]any{"id": float64(roleID), "name": map[int]string{1: "global_admin", 2: "global_viewer", 3: "global_editor"}[roleID], "display_name": map[int]string{1: "admin", 2: "monitor", 3: "editor"}[roleID]}},
		"settings": map[string]any{"2fa.enabled": enabled, "2fa.is_enrolled": enrolled, "passcode_2fa": "TOTPSECRET", "isMenuOpen": false}}
}

func newFake() *fakeFM {
	return &fakeFM{
		roles: []map[string]any{role(1, "global_admin", "admin"), role(2, "global_viewer", "monitor"), role(3, "global_editor", "editor")},
		users: []map[string]any{
			user("u-claude", "claude", 1, false, false),
			user("u-alice", "alice", 1, true, true),
			user("u-bob", "bob", 2, false, false),
		},
	}
}

// roundTrip passes v through JSON, as a real response would.
func roundTrip(v, out any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func (f *fakeFM) GetJSON(_ context.Context, path string, _ url.Values, out any) error {
	switch path {
	case usersPath:
		return roundTrip(f.users, out)
	case rolesPath:
		return roundTrip(map[string]any{"roles": f.roles}, out)
	case providersPath:
		return roundTrip(map[string]any{"providers": []any{map[string]any{"id": "ldap", "type": "ldap", "enable": false, "role_mappings": []any{}}}}, out)
	}
	return errors.New("unexpected GET " + path)
}

func (f *fakeFM) find(id string) (int, map[string]any) {
	for i, u := range f.users {
		if u["id"] == id {
			return i, u
		}
	}
	return -1, nil
}

func (f *fakeFM) Do(_ context.Context, method, path string, _ url.Values, body []byte, _ string) (*fleet.Response, error) {
	f.sent = append(f.sent, method+" "+path+" "+string(body))
	ok := &fleet.Response{Status: http.StatusOK, Body: []byte("{}")}
	rest := strings.TrimPrefix(path, usersPath)
	id := strings.Trim(strings.TrimSuffix(rest, "/2fa/reset"), "/")
	switch {
	case method == http.MethodPost && path == usersPath:
		var b map[string]any
		_ = json.Unmarshal(body, &b)
		u := user("u-new", fmt.Sprint(b["username"]), 2, false, false)
		if rs, ok := b["roles"].([]any); ok && len(rs) == 1 {
			rid := int(rs[0].(map[string]any)["id"].(float64))
			u = user("u-new", fmt.Sprint(b["username"]), rid, false, false)
		}
		if st, ok := b["settings"].(map[string]any); ok {
			u["settings"].(map[string]any)["2fa.enabled"] = st["2fa.enabled"]
		}
		u["require_password_change"] = b["require_password_change"]
		f.users = append(f.users, u)
		return &fleet.Response{Status: http.StatusCreated, Body: []byte(`{"id":"u-new"}`)}, nil
	case method == http.MethodPost && strings.HasSuffix(path, "/2fa/reset"):
		_, u := f.find(id)
		if u == nil {
			return &fleet.Response{Status: 404, Body: []byte(`{"message":"User not found"}`)}, nil
		}
		s := u["settings"].(map[string]any)
		if s["2fa.enabled"] != true {
			return &fleet.Response{Status: 409, Body: []byte(`{"message":"2FA must be enabled for it to be reset"}`)}, nil
		}
		s["2fa.is_enrolled"] = false
		u["require_password_change"] = true
		return &fleet.Response{Status: http.StatusNoContent}, nil
	case method == http.MethodPut:
		i, u := f.find(id)
		if u == nil {
			return &fleet.Response{Status: 404, Body: []byte(`{"message":"User not found"}`)}, nil
		}
		var b map[string]any
		_ = json.Unmarshal(body, &b)
		// Like a PUT: the accepted fields are replaced by what was sent.
		for _, k := range putFields {
			delete(u, k)
			if v, ok := b[k]; ok {
				u[k] = v
			}
		}
		if rs, ok := b["roles"].([]any); ok && len(rs) == 1 {
			rid := int(rs[0].(map[string]any)["id"].(float64))
			u["roles"] = user("", "", rid, false, false)["roles"]
			u["is_fleet_admin"] = rid == 1
		}
		u["id"] = id
		f.users[i] = u
		return ok, nil
	case method == http.MethodDelete:
		i, _ := f.find(id)
		if i < 0 {
			return &fleet.Response{Status: 404, Body: []byte(`{"message":"User not found"}`)}, nil
		}
		f.users = append(f.users[:i], f.users[i+1:]...)
		return &fleet.Response{Status: http.StatusNoContent}, nil
	}
	return nil, errors.New("unexpected " + method + " " + path)
}

type fakeSecrets map[string]string

func (s fakeSecrets) GetSetting(n string) (string, error) {
	if v, ok := s[n]; ok {
		return v, nil
	}
	return "", errors.New(n + " is not stored")
}
func (s fakeSecrets) DeleteSetting(n string) error { delete(s, n); return nil }

func ptr[T any](v T) *T { return &v }

func plan(t *testing.T, f *fakeFM, sec Secrets, r Request) *Plan {
	t.Helper()
	p, err := PlanChange(context.Background(), f, sec, "claude", r)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func apply(t *testing.T, f *fakeFM, sec Secrets, p *Plan) *Result {
	t.Helper()
	if !p.Ready() {
		t.Fatalf("plan not ready: blockers %v warnings %v", p.Blockers, p.Warnings)
	}
	res, err := Apply(context.Background(), f, sec, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) > 0 {
		t.Fatalf("problems: %v", res.Problems)
	}
	return res
}

func joined(s []string) string { return strings.Join(s, "\n") }

func TestList(t *testing.T) {
	f := newFake()
	f.users = append(f.users, user("u-t", "test", 1, false, false))
	f.users[3]["require_password_change"] = true
	f.users[3]["pw_current_strikes"] = float64(3)
	r, err := List(context.Background(), f, "claude")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Users) != 4 || r.Users[0].Username != "alice" || r.Users[0].TwoFA != "enrolled" || !r.Users[0].Admin {
		t.Fatalf("users: %+v", r.Users)
	}
	var self *Summary
	for i := range r.Users {
		if r.Users[i].Self {
			self = &r.Users[i]
		}
	}
	if self == nil || self.Username != "claude" {
		t.Error("fleet-mcp's account not marked")
	}
	if len(r.Roles) != 3 || r.Roles[1].Display != "monitor" || r.Roles[1].Actions != 3 {
		t.Errorf("roles: %+v", r.Roles)
	}
	fs := joined(r.Findings)
	for _, want := range []string{"admins without 2FA: test", "password change still pending", "test", "failed logins since the last good one: test (3)", "look like tests", "only local accounts"} {
		if !strings.Contains(fs, want) {
			t.Errorf("findings lack %q:\n%s", want, fs)
		}
	}
	if strings.Contains(fs, "admins without 2FA: claude") {
		t.Error("fleet-mcp's own account flagged for 2FA, which it cannot use")
	}
}

func TestCreate(t *testing.T) {
	f := newFake()
	p := plan(t, f, fakeSecrets{}, Request{Action: Create, Username: "carol", Role: "editor", Require2FA: ptr(true)})
	if !strings.Contains(joined(p.Blockers), "initial password is not stored") {
		t.Fatalf("no password blocker: %v", p.Blockers)
	}
	sec := fakeSecrets{DefaultPasswordSetting("carol"): "Initial-Pass-1"}
	p = plan(t, f, sec, Request{Action: Create, Username: "carol", Role: "editor", Require2FA: ptr(true)})
	if b, _ := json.Marshal(p); strings.Contains(string(b), "Initial-Pass-1") {
		t.Fatal("plan contains the password")
	}
	res := apply(t, f, sec, p)
	if res.ID != "u-new" || len(sec) != 0 {
		t.Errorf("id %q, secrets left %v", res.ID, sec)
	}
	last := f.sent[len(f.sent)-1]
	for _, want := range []string{`"password":"Initial-Pass-1"`, `"require_password_change":true`, `"roles":[{"id":3}]`, `"2fa.enabled":true`} {
		if !strings.Contains(last, want) {
			t.Errorf("POST lacks %s: %s", want, last)
		}
	}
	if p := plan(t, f, sec, Request{Action: Create, Username: "carol", Role: "editor"}); !strings.Contains(joined(p.Blockers), "already exists") {
		t.Errorf("duplicate not blocked: %v", p.Blockers)
	}
	if p := plan(t, f, sec, Request{Action: Create, Username: "dan"}); !strings.Contains(joined(p.Blockers), "needs a role") {
		t.Errorf("missing role not blocked: %v", p.Blockers)
	}
	if p := plan(t, f, sec, Request{Action: Create, Username: "dan", Role: "superuser"}); !strings.Contains(joined(p.Blockers), `no role "superuser"`) {
		t.Errorf("unknown role not blocked: %v", p.Blockers)
	}
}

// TestUpdateKeepsEnrollment checks that a role change sends the settings
// back as read, so an enrolled user keeps 2FA.
func TestUpdateKeepsEnrollment(t *testing.T) {
	f := newFake()
	f.users = append(f.users, user("u-erin", "erin", 3, true, true))
	p := plan(t, f, nil, Request{Action: Update, Username: "Erin", Role: "monitor"})
	if p.ID != "u-erin" || len(p.Changes) != 1 || p.Changes[0].To != "monitor" {
		t.Fatalf("plan: %+v", p)
	}
	apply(t, f, nil, p)
	_, u := f.find("u-erin")
	s := u["settings"].(map[string]any)
	if s["2fa.is_enrolled"] != true || s["passcode_2fa"] != "TOTPSECRET" || u["first_name"] != "F" || u["theme"] != "dark-theme" {
		t.Errorf("update lost fields: %v", u)
	}
	if p := plan(t, f, nil, Request{Action: Update, Username: "erin", Role: "monitor"}); p.Ready() {
		t.Error("same role again is not a no-op")
	}
}

func TestUpdate2FAAndNames(t *testing.T) {
	f := newFake()
	p := plan(t, f, nil, Request{Action: Update, Username: "bob", Require2FA: ptr(true), FirstName: ptr("Robert")})
	apply(t, f, nil, p)
	_, u := f.find("u-bob")
	if u["settings"].(map[string]any)["2fa.enabled"] != true || u["first_name"] != "Robert" || u["last_name"] != "L" {
		t.Errorf("bob: %v", u)
	}
	if p := plan(t, f, nil, Request{Action: Update, Username: "claude", Require2FA: ptr(true)}); !strings.Contains(joined(p.Blockers), "cannot answer a 2FA prompt") {
		t.Errorf("2FA on fleet-mcp's account not blocked: %v", p.Blockers)
	}
}

func TestGuards(t *testing.T) {
	f := newFake()
	if p := plan(t, f, nil, Request{Action: Delete, Username: "claude"}); !strings.Contains(joined(p.Blockers), "cannot delete itself") {
		t.Errorf("self delete not blocked: %v", p.Blockers)
	}
	if p := plan(t, f, nil, Request{Action: Update, Username: "claude", Role: "monitor"}); !strings.Contains(joined(p.Blockers), "fleet-mcp logs in with") {
		t.Errorf("self demotion not blocked: %v", p.Blockers)
	}
	// alice becomes the only admin once claude is gone.
	f.users = f.users[1:]
	if p := plan(t, f, nil, Request{Action: Delete, Username: "alice"}); !strings.Contains(joined(p.Blockers), "only admin") {
		t.Errorf("last admin delete not blocked: %v", p.Blockers)
	}
	if p := plan(t, f, nil, Request{Action: Update, Username: "alice", Role: "editor"}); !strings.Contains(joined(p.Blockers), "only admin") {
		t.Errorf("last admin demotion not blocked: %v", p.Blockers)
	}
	if p := plan(t, f, nil, Request{Action: Delete, Username: "nobody"}); !strings.Contains(joined(p.Blockers), "no user") {
		t.Errorf("unknown user: %v", p.Blockers)
	}
	if _, err := PlanChange(context.Background(), f, nil, "claude", Request{Action: "disable", Username: "bob"}); err == nil {
		t.Error("unknown action accepted")
	}
}

func TestReset2FAAndDelete(t *testing.T) {
	f := newFake()
	if p := plan(t, f, nil, Request{Action: Reset2FA, Username: "bob"}); !strings.Contains(joined(p.Blockers), "not enabled") {
		t.Errorf("reset with 2FA off: %v", p.Blockers)
	}
	f.users = append(f.users, user("u-pending", "pending", 2, true, false))
	if p := plan(t, f, nil, Request{Action: Reset2FA, Username: "pending"}); p.Ready() || len(p.Blockers) > 0 {
		t.Errorf("reset of a not-enrolled user should be a no-op: %+v", p)
	}
	p := plan(t, f, nil, Request{Action: Reset2FA, Username: "alice"})
	apply(t, f, nil, p)
	if last := f.sent[len(f.sent)-1]; !strings.HasPrefix(last, "POST /fleet/v1/users/u-alice/2fa/reset") {
		t.Errorf("reset used %q", last)
	}
	p = plan(t, f, nil, Request{Action: Delete, Username: "u-bob"})
	apply(t, f, nil, p)
	if i, _ := f.find("u-bob"); i >= 0 {
		t.Error("bob still there")
	}
}

func TestStateChangesWithUser(t *testing.T) {
	f := newFake()
	a := plan(t, f, nil, Request{Action: Update, Username: "bob", Role: "editor"}).State()
	if a != plan(t, f, nil, Request{Action: Update, Username: "bob", Role: "editor"}).State() {
		t.Error("state differs without a change")
	}
	_, u := f.find("u-bob")
	u["first_name"] = "Changed"
	if a == plan(t, f, nil, Request{Action: Update, Username: "bob", Role: "editor"}).State() {
		t.Error("state unchanged after the user changed")
	}
}
