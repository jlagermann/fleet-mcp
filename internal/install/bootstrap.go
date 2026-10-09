package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
)

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

// ActivateMCPUser implements Bootstrapper: it logs in with the temporary
// password from corelight-fleetd and sets a generated one, which is stored
// before the change so it cannot be lost.
func (b *APIBootstrap) ActivateMCPUser(ctx context.Context, in *Installer, temp string) error {
	user := in.Opts.MCPUser
	c, err := b.client(ctx, in, user, temp)
	if err != nil {
		return err
	}
	if err := c.Login(ctx); err != nil {
		return fmt.Errorf("logging in as %s with the temporary password: %w", user, err)
	}
	newPW := Generate(24, true)
	if err := in.Secrets.Set(in.Host, secrets.MCPPassword, []byte(newPW)); err != nil {
		return fmt.Errorf("storing the %s password: %w", user, err)
	}
	body, _ := json.Marshal(map[string]string{"password": newPW, "cur_password": temp})
	if _, err := c.Do(ctx, http.MethodPut, "/fleet/v1/current/password-reset", nil, body, "application/json"); err != nil {
		return fmt.Errorf("setting the %s password: %w", user, err)
	}
	_ = c.Logout(ctx)
	if ok, detail := b.loginOK(ctx, in, user, newPW); !ok {
		return fmt.Errorf("the new %s password does not work: %s", user, detail)
	}
	return b.writeProfile(in)
}

// AdminExists implements Bootstrapper using the MCP user's login.
func (b *APIBootstrap) AdminExists(ctx context.Context, in *Installer) (bool, error) {
	pw, err := in.Secrets.GetString(in.Host, secrets.MCPPassword)
	if err != nil {
		return false, err
	}
	c, err := b.client(ctx, in, in.Opts.MCPUser, pw)
	if err != nil {
		return false, err
	}
	defer c.Logout(ctx)
	var users []struct {
		Username string `json:"username"`
	}
	if err := c.GetJSON(ctx, "/fleet/v1/users", nil, &users); err != nil {
		return false, err
	}
	for _, u := range users {
		if u.Username == "admin" {
			return true, nil
		}
	}
	return false, nil
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
