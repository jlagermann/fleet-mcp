// Package secrets stores the credentials and license files fleet-mcp needs
// to install and manage Fleet Manager, in a directory readable only by the
// current user. Values are never returned to MCP clients; tools report only
// whether each secret is present.
package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Scope says whether a secret is shared by all Fleet Managers or belongs to
// one host.
type Scope string

const (
	Global Scope = "global"
	Host   Scope = "host"
)

// Kind says how a secret is provided.
type Kind string

const (
	// Prompt secrets are typed at a hidden prompt: fleet-mcp secret set <name>.
	Prompt Kind = "prompt"
	// File secrets are imported from a file: fm_secret_import_file or
	// fleet-mcp secret import <name> <path>.
	File Kind = "file"
	// Generated secrets are created by fleet-mcp during installation.
	Generated Kind = "generated"
)

// Names of known secrets.
const (
	RepoToken        = "repo-token"
	IdentityCert     = "identity-cert.pem"
	SensorLicense    = "sensor-license.txt"
	RegistryUser     = "registry-user"
	RegistryPassword = "registry-password"
	CommunityString  = "community-string"
	MCPPassword      = "mcp-password"
	SensorPassword   = "sensor-admin-password"
	SensorSSHKey     = "sensor-ssh-key"
)

// Spec describes a known secret.
type Spec struct {
	Name        string `json:"name"`
	Scope       Scope  `json:"scope"`
	Kind        Kind   `json:"kind"`
	Description string `json:"description"`
	UsedFor     string `json:"used_for"`
	// Settable generated secrets may instead be set by the user at a
	// prompt before they are generated.
	Settable bool `json:"user_settable,omitempty"`
	// Showable secrets can be printed in the user's own terminal with
	// fleet-mcp secret show; no MCP tool ever returns a value.
	Showable bool `json:"-"`
}

// Known lists every secret fleet-mcp uses. fleet-mcp never stores a
// Fleet Manager admin password: the admin account's temporary password is
// handed to the user, who must change it at first login.
var Known = []Spec{
	{Name: RepoToken, Scope: Global, Kind: Prompt, Description: "Corelight package repository auth token (Corelight Customer Portal → Downloads → Fleet Manager)", UsedFor: "installing and upgrading Fleet Manager from the Corelight repository"},
	{Name: IdentityCert, Scope: Global, Kind: File, Description: "Fleet Manager product identity certificate (.pem with certificate and key) issued by Corelight; contains the Fleet Manager license", UsedFor: "installing Fleet Manager"},
	{Name: SensorLicense, Scope: Global, Kind: File, Description: "Software Sensor license file", UsedFor: "optional: licensing Software Sensors through Fleet Manager"},
	{Name: RegistryUser, Scope: Global, Kind: Prompt, Description: "Corelight container registry username (Customer Portal → Tokens → Container Registry)", UsedFor: "container installs"},
	{Name: RegistryPassword, Scope: Global, Kind: Prompt, Description: "Corelight container registry password", UsedFor: "container installs"},
	{Name: CommunityString, Scope: Host, Kind: Generated, Description: "pre-shared secret sensors use to connect to this Fleet Manager (messaging.community-string)", UsedFor: "sensor connections", Settable: true, Showable: true},
	{Name: MCPPassword, Scope: Host, Kind: Generated, Description: "password of the local user fleet-mcp logs in as", UsedFor: "the MCP server's API access"},
	{Name: SensorPassword, Scope: Global, Kind: Prompt, Description: "Corelight Sensor admin password; the diag-shell SSH user uses the same password", UsedFor: "moving sensors between Fleet Managers (SSH to the sensor as diag-shell)"},
	{Name: SensorSSHKey, Scope: Global, Kind: Generated, Description: "fleet-mcp's own SSH key for logging in to sensors as diag-shell (public key installed per sensor as security.user.admin.ssh_public_key)", UsedFor: "moving sensors without the admin password"},
}

// Lookup returns the Spec for name.
func Lookup(name string) (Spec, bool) {
	for _, s := range Known {
		if s.Name == name {
			return s, true
		}
	}
	return Spec{}, false
}

// Store is a directory of secrets.
type Store struct {
	dir string
}

var hostName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:_-]*$`)

// Open returns a Store rooted at dir, creating it and restricting access to
// the current user.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("secrets: no directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := restrict(dir); err != nil {
		return nil, fmt.Errorf("secrets: restricting %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Dir is the store's root directory.
func (s *Store) Dir() string { return s.dir }

// HostDir is the directory holding one host's secrets.
func (s *Store) HostDir(host string) (string, error) {
	if !hostName.MatchString(host) {
		return "", fmt.Errorf("secrets: bad host name %q", host)
	}
	return filepath.Join(s.dir, "hosts", strings.ToLower(host)), nil
}

// Path is where a secret is stored. host is ignored for global secrets.
func (s *Store) Path(host, name string) (string, error) {
	spec, ok := Lookup(name)
	if !ok {
		return "", fmt.Errorf("secrets: unknown secret %q", name)
	}
	if spec.Scope == Global {
		return filepath.Join(s.dir, "global", name), nil
	}
	if host == "" {
		return "", fmt.Errorf("secrets: %s needs a host", name)
	}
	d, err := s.HostDir(host)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name), nil
}

// Get returns a secret's value.
func (s *Store) Get(host, name string) ([]byte, error) {
	p, err := s.Path(host, name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("secret %s is not set%s", name, howTo(name))
	}
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("secret %s is empty%s", name, howTo(name))
	}
	return b, nil
}

// GetString returns a secret with surrounding whitespace removed.
func (s *Store) GetString(host, name string) (string, error) {
	b, err := s.Get(host, name)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(strings.TrimPrefix(string(b), string(rune(0xFEFF))))
	if v == "" {
		return "", fmt.Errorf("secret %s is empty%s", name, howTo(name))
	}
	return v, nil
}

// Set stores a secret.
func (s *Store) Set(host, name string, value []byte) error {
	p, err := s.Path(host, name)
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
	if err := os.WriteFile(tmp, value, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Status reports a secret's presence without its value.
type Status struct {
	Spec
	Present bool       `json:"present"`
	SetAt   *time.Time `json:"set_at,omitempty"`
	// Fingerprint is the first 12 hex characters of the value's SHA-256,
	// so a user can tell whether two stores hold the same value.
	Fingerprint string `json:"fingerprint,omitempty"`
	HowToSet    string `json:"how_to_set,omitempty"`
}

// List reports every known secret, for host if given.
func (s *Store) List(host string) []Status {
	var out []Status
	for _, spec := range Known {
		if spec.Scope == Host && host == "" {
			continue
		}
		st := Status{Spec: spec}
		if p, err := s.Path(host, spec.Name); err == nil {
			if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
				st.Present = true
				t := fi.ModTime().UTC()
				st.SetAt = &t
				if b, err := os.ReadFile(p); err == nil {
					sum := sha256.Sum256(b)
					st.Fingerprint = hex.EncodeToString(sum[:])[:12]
				}
			}
		}
		if !st.Present {
			st.HowToSet = strings.TrimPrefix(howTo(spec.Name), "; ")
		}
		out = append(out, st)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out
}

func howTo(name string) string {
	spec, ok := Lookup(name)
	if !ok {
		return ""
	}
	switch spec.Kind {
	case Prompt:
		return fmt.Sprintf("; the user sets it in a terminal with: fleet-mcp secret set %s", name)
	case File:
		return fmt.Sprintf("; import it with fm_secret_import_file (name %q and the file's path) or: fleet-mcp secret import %s <path>", name, name)
	default:
		if name == SensorSSHKey {
			return "; fm_sensor_ssh_key creates it"
		}
		if spec.Settable {
			return fmt.Sprintf("; fm_host_install generates it, or the user sets their own first with: fleet-mcp secret set %s -host <host>", name)
		}
		return "; fm_host_install creates it"
	}
}
