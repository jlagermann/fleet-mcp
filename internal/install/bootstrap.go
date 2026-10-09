package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
)

const adminUser = "admin"

// APIBootstrap finishes setup through the Fleet Manager REST API. It pins
// the certificate Fleet Manager serves, read over SSH, because a new Fleet
// Manager presents Corelight's identity certificate, which this machine
// does not trust.
type APIBootstrap struct {
	UserAgent string
	pin       string
}

// servedCertSHA256 reads the fingerprint of the certificate on port 443
// from the host itself.
func (b *APIBootstrap) servedCertSHA256(ctx context.Context, in *Installer) (string, error) {
	if b.pin != "" {
		return b.pin, nil
	}
	res, err := in.R.Run(ctx, "echo | openssl s_client -connect 127.0.0.1:443 2>/dev/null | openssl x509 -noout -fingerprint -sha256")
	if err != nil {
		return "", err
	}
	pin, err := fleet.NormalizeFingerprint(res.Stdout)
	if err != nil {
		return "", fmt.Errorf("reading the served certificate on %s: %w", in.R.Name(), err)
	}
	b.pin = pin
	return pin, nil
}

func (b *APIBootstrap) client(ctx context.Context, in *Installer, user, password string) (*fleet.Client, error) {
	pin, err := b.servedCertSHA256(ctx, in)
	if err != nil {
		return nil, err
	}
	return fleet.New(fleet.Options{
		BaseURL: in.URL(), Username: user, Password: password, PinSHA256: pin,
		Timeout: 60 * time.Second, UserAgent: b.UserAgent,
	})
}

// loginOK logs in and reports whether the password is usable as is.
func (b *APIBootstrap) loginOK(ctx context.Context, in *Installer, user, password string) (bool, string) {
	c, err := b.client(ctx, in, user, password)
	if err != nil {
		return false, err.Error()
	}
	defer c.Logout(ctx)
	if err := c.Login(ctx); err != nil {
		return false, "login failed: " + err.Error()
	}
	if c.RequirePasswordChange() {
		return false, "login works but Fleet Manager requires a password change"
	}
	return true, "stored password logs in"
}

// AdminReady implements Bootstrapper.
func (b *APIBootstrap) AdminReady(ctx context.Context, in *Installer) (bool, string) {
	pw, err := in.Secrets.GetString(in.Host, secrets.AdminPassword)
	if err != nil {
		return false, "no stored admin password"
	}
	return b.loginOK(ctx, in, adminUser, pw)
}

// changePassword logs in with cur and sets a new generated password,
// storing it under name before the change so it cannot be lost.
func (b *APIBootstrap) changePassword(ctx context.Context, in *Installer, user, cur, name string) error {
	c, err := b.client(ctx, in, user, cur)
	if err != nil {
		return err
	}
	if err := c.Login(ctx); err != nil {
		return fmt.Errorf("logging in as %s with the temporary password: %w", user, err)
	}
	newPW := Generate(24, true)
	if err := in.Secrets.Set(in.Host, name, []byte(newPW)); err != nil {
		return fmt.Errorf("storing the new %s password: %w", user, err)
	}
	body, _ := json.Marshal(map[string]string{"password": newPW, "cur_password": cur})
	if _, err := c.Do(ctx, http.MethodPut, "/fleet/v1/current/password-reset", nil, body, "application/json"); err != nil {
		return fmt.Errorf("setting the %s password: %w", user, err)
	}
	_ = c.Logout(ctx)
	if ok, detail := b.loginOK(ctx, in, user, newPW); !ok {
		return fmt.Errorf("the new %s password does not work: %s", user, detail)
	}
	return nil
}

// SetAdmin implements Bootstrapper.
func (b *APIBootstrap) SetAdmin(ctx context.Context, in *Installer, temp string) error {
	return b.changePassword(ctx, in, adminUser, temp, secrets.AdminPassword)
}

// MCPUserReady implements Bootstrapper.
func (b *APIBootstrap) MCPUserReady(ctx context.Context, in *Installer) (bool, string) {
	pw, err := in.Secrets.GetString(in.Host, secrets.MCPPassword)
	if err != nil {
		return false, "no stored password for " + in.Opts.MCPUser
	}
	ok, detail := b.loginOK(ctx, in, in.Opts.MCPUser, pw)
	if ok {
		if err := b.writeProfile(in); err != nil {
			return false, err.Error()
		}
	}
	return ok, detail
}

// CreateMCPUser implements Bootstrapper.
func (b *APIBootstrap) CreateMCPUser(ctx context.Context, in *Installer) error {
	adminPW, err := in.Secrets.GetString(in.Host, secrets.AdminPassword)
	if err != nil {
		return err
	}
	admin, err := b.client(ctx, in, adminUser, adminPW)
	if err != nil {
		return err
	}
	defer admin.Logout(ctx)
	var users []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := admin.GetJSON(ctx, "/fleet/v1/users", nil, &users); err != nil {
		return fmt.Errorf("listing users: %w", err)
	}
	for _, u := range users {
		if strings.EqualFold(u.Username, in.Opts.MCPUser) {
			return fmt.Errorf("user %q already exists in Fleet Manager but its password is not stored here; delete it in Fleet Manager or choose another mcp_user", u.Username)
		}
	}
	pw := Generate(24, true)
	if err := in.Secrets.Set(in.Host, secrets.MCPPassword, []byte(pw)); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{
		"username":                in.Opts.MCPUser,
		"password":                pw,
		"authenticator":           "local",
		"first_name":              "fleet-mcp",
		"last_name":               "",
		"is_fleet_admin":          true,
		"roles":                   []any{map[string]any{"id": 1, "name": "global_admin"}},
		"require_password_change": false,
		"settings":                map[string]any{"2fa.enabled": false},
	})
	if _, err := admin.Do(ctx, http.MethodPost, "/fleet/v1/users", nil, body, "application/json"); err != nil {
		return fmt.Errorf("creating %s: %w", in.Opts.MCPUser, err)
	}
	// Some policies force a change at first login; complete it.
	c, err := b.client(ctx, in, in.Opts.MCPUser, pw)
	if err != nil {
		return err
	}
	if err := c.Login(ctx); err != nil {
		return fmt.Errorf("logging in as the new %s: %w", in.Opts.MCPUser, err)
	}
	must := c.RequirePasswordChange()
	_ = c.Logout(ctx)
	if must {
		if err := b.changePassword(ctx, in, in.Opts.MCPUser, pw, secrets.MCPPassword); err != nil {
			return err
		}
	}
	return b.writeProfile(in)
}

// Profile is what a fleet-mcp server needs to manage this Fleet Manager.
type Profile struct {
	URL          string    `json:"url"`
	Username     string    `json:"username"`
	PasswordFile string    `json:"password_file"`
	CertSHA256   string    `json:"cert_sha256"`
	Written      time.Time `json:"written"`
}

func (b *APIBootstrap) writeProfile(in *Installer) error {
	pwFile, err := in.Secrets.Path(in.Host, secrets.MCPPassword)
	if err != nil {
		return err
	}
	dir, err := in.Secrets.HostDir(in.Host)
	if err != nil {
		return err
	}
	p := Profile{URL: in.URL(), Username: in.Opts.MCPUser, PasswordFile: pwFile, CertSHA256: b.pin, Written: time.Now().UTC()}
	if p.CertSHA256 == "" {
		return errors.New("no pinned certificate")
	}
	data, _ := json.MarshalIndent(p, "", "  ")
	return os.WriteFile(filepath.Join(dir, "profile.json"), data, 0o600)
}

// ReadProfile loads a host's profile.
func ReadProfile(s *secrets.Store, host string) (*Profile, error) {
	dir, err := s.HostDir(host)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "profile.json"))
	if err != nil {
		return nil, err
	}
	var p Profile
	return &p, json.Unmarshal(b, &p)
}
