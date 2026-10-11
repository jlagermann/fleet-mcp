package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Setting secrets are values for write-only sensor policy settings that a
// new policy needs: a proxy password, an S3 secret key, an exporter token
// ("exporter:<exporter name>:<field>"). The user enters them at a hidden
// prompt (fleet-mcp secret set-setting <name>); a policy creation reads
// them and deletes them once the policy holds them.

var settingName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,200}$`)

func (s *Store) settingPath(name string) (string, error) {
	if !settingName.MatchString(name) || strings.Contains(name, "..") {
		return "", fmt.Errorf("invalid setting name %q", name)
	}
	// ':' is not allowed in Windows file names.
	return filepath.Join(s.dir, "global", "settings", strings.ReplaceAll(name, ":", "~")), nil
}

// SetSetting stores a setting secret.
func (s *Store) SetSetting(name, value string) error {
	p, err := s.settingPath(name)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := restrict(dir); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(value), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// GetSetting returns a setting secret, or an error naming the command that
// stores it.
func (s *Store) GetSetting(name string) (string, error) {
	p, err := s.settingPath(name)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) || (err == nil && strings.TrimSpace(string(b)) == "") {
		return "", fmt.Errorf("%s is not stored; the user runs in a terminal: fleet-mcp secret set-setting %s", name, name)
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// HasSetting reports whether a setting secret is stored.
func (s *Store) HasSetting(name string) bool {
	_, err := s.GetSetting(name)
	return err == nil
}

// DeleteSetting removes a setting secret.
func (s *Store) DeleteSetting(name string) error {
	p, err := s.settingPath(name)
	if err != nil {
		return err
	}
	err = os.Remove(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
