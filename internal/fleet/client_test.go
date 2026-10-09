package fleet_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/fleettest"
)

func newClient(t *testing.T, fm *fleettest.Server) *fleet.Client {
	t.Helper()
	c, err := fleet.New(fleet.Options{
		BaseURL: fm.URL, Username: fleettest.Username, PasswordFile: fm.PasswordFile,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGetLogsInOnce(t *testing.T) {
	fm := fleettest.New(t)
	fm.Route("GET /fleet/v1/info", map[string]any{"server_version": "29.2.2-1"})
	c := newClient(t, fm)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		var info struct {
			ServerVersion string `json:"server_version"`
		}
		if err := c.GetJSON(ctx, "/fleet/v1/info", nil, &info); err != nil {
			t.Fatal(err)
		}
		if info.ServerVersion != "29.2.2-1" {
			t.Fatalf("version = %q", info.ServerVersion)
		}
	}
	if fm.LoginCount() != 1 {
		t.Fatalf("logins = %d, want 1", fm.LoginCount())
	}
}

func TestReloginAfterTokenExpiry(t *testing.T) {
	fm := fleettest.New(t)
	fm.Route("GET /fleet/v1/info", map[string]any{"ok": true})
	c := newClient(t, fm)
	ctx := context.Background()
	if _, err := c.Get(ctx, "/fleet/v1/info", nil); err != nil {
		t.Fatal(err)
	}
	fm.ExpireToken()
	if _, err := c.Get(ctx, "/fleet/v1/info", nil); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if fm.LoginCount() != 2 {
		t.Fatalf("logins = %d, want 2", fm.LoginCount())
	}
}

func TestBadPassword(t *testing.T) {
	fm := fleettest.New(t)
	if err := os.WriteFile(fm.PasswordFile, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, fm)
	_, err := c.Get(context.Background(), "/fleet/v1/info", nil)
	var apiErr *fleet.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 401 {
		t.Fatalf("err = %v, want 401", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Fatal("error leaks the password")
	}
}

func TestPasswordFileBOM(t *testing.T) {
	fm := fleettest.New(t)
	if err := os.WriteFile(fm.PasswordFile, []byte("\xEF\xBB\xBF"+fleettest.Password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newClient(t, fm).Login(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestGraphQLSendsCSRFAndPassesErrors(t *testing.T) {
	fm := fleettest.New(t)
	c := newClient(t, fm)
	ctx := context.Background()
	resp, err := c.GraphQL(ctx, "{ hello { message } }", nil)
	if err != nil {
		t.Fatalf("GraphQL: %v", err)
	}
	if !strings.Contains(string(resp.Body), `"hi"`) {
		t.Fatalf("body = %s", resp.Body)
	}
	resp, err = c.GraphQL(ctx, "{ invalidField }", nil)
	if err != nil {
		t.Fatalf("validation errors should not be a Go error: %v", err)
	}
	if !strings.Contains(string(resp.Body), "Cannot query field") {
		t.Fatalf("body = %s", resp.Body)
	}
}

func TestLogout(t *testing.T) {
	fm := fleettest.New(t)
	fm.Route("GET /fleet/v1/info", map[string]any{})
	c := newClient(t, fm)
	ctx := context.Background()
	if err := c.Logout(ctx); err != nil {
		t.Fatalf("logout without session: %v", err)
	}
	if _, err := c.Get(ctx, "/fleet/v1/info", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	if fm.LogoutCount() != 1 {
		t.Fatalf("logouts = %d", fm.LogoutCount())
	}
}

func TestNotFoundIsAPIError(t *testing.T) {
	fm := fleettest.New(t)
	_, err := newClient(t, fm).Get(context.Background(), "/fleet/v1/nope", nil)
	var apiErr *fleet.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 404 {
		t.Fatalf("err = %v", err)
	}
}

func TestValidatePath(t *testing.T) {
	for path, ok := range map[string]bool{
		"/fleet/v1/info":           true,
		"/fleet/v1/sensor/catalog": true,
		"fleet/v1/info":            false,
		"//evil.example/x":         false,
		"/x?y=1":                   false,
		"/fleet/v1/../../etc":      false,
		"/https://evil":            false,
		"":                         false,
	} {
		if err := fleet.ValidatePath(path); (err == nil) != ok {
			t.Errorf("ValidatePath(%q) = %v, want ok=%v", path, err, ok)
		}
	}
}

func TestParseBaseURL(t *testing.T) {
	for in, want := range map[string]string{
		"fleet.example.com":          "https://fleet.example.com",
		"fleet.example.com:8443":     "https://fleet.example.com:8443",
		"https://fleet.example.com/": "https://fleet.example.com",
	} {
		u, err := fleet.ParseBaseURL(in)
		if err != nil || u.String() != want {
			t.Errorf("ParseBaseURL(%q) = %v, %v; want %s", in, u, err, want)
		}
	}
	for _, bad := range []string{"", "http://fleet.example.com", "https://"} {
		if _, err := fleet.ParseBaseURL(bad); err == nil {
			t.Errorf("ParseBaseURL(%q) succeeded", bad)
		}
	}
}
