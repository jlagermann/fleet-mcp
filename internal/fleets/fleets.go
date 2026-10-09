// Package fleets keeps the set of Fleet Managers one fleet-mcp server can
// reach, and a logged-in client for each.
//
// Fleet Managers come from three places, in this order of precedence:
//
//  1. the environment (FLEET_MCP_URL or FLEET_MCP_PROFILE), for
//     single-FM setups;
//  2. a fleets.json file, for Fleet Managers fleet-mcp did not install;
//  3. profiles written by fm_host_install, under the secret store.
//
// The registry rescans files when asked, so a Fleet Manager installed
// while the server runs becomes available without a restart.
package fleets

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/spec"
)

// Fleet describes one Fleet Manager.
type Fleet struct {
	Name               string `json:"name"`
	URL                string `json:"url"`
	Username           string `json:"username"`
	PasswordFile       string `json:"password_file"`
	CertSHA256         string `json:"cert_sha256,omitempty"`
	CAFile             string `json:"ca_file,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	// ReadOnly makes the write tools refuse this Fleet Manager.
	ReadOnly bool `json:"read_only,omitempty"`
	// Default marks the Fleet Manager used when a tool names none.
	Default bool `json:"default,omitempty"`
	// Source says where the entry came from (not read from files).
	Source string `json:"source,omitempty"`
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// Validate checks an entry.
func (f *Fleet) Validate() error {
	switch {
	case !namePattern.MatchString(f.Name):
		return fmt.Errorf("fleet name %q: use letters, digits, . _ : -", f.Name)
	case f.URL == "":
		return fmt.Errorf("fleet %s: url is required", f.Name)
	case f.Username == "":
		return fmt.Errorf("fleet %s: username is required", f.Name)
	case f.PasswordFile == "":
		return fmt.Errorf("fleet %s: password_file is required", f.Name)
	}
	if _, err := fleet.ParseBaseURL(f.URL); err != nil {
		return fmt.Errorf("fleet %s: %w", f.Name, err)
	}
	return nil
}

// Conn is a Fleet Manager with its client and API schema store.
type Conn struct {
	Fleet
	Client *fleet.Client
	Specs  *spec.Store
}

// Options configures a Registry.
type Options struct {
	// Env is an entry from the environment, if any.
	Env *Fleet
	// FleetsFile is the path of fleets.json (may not exist).
	FleetsFile string
	// ProfilesDir holds <host>/profile.json files written by installs.
	ProfilesDir string
	// SpecDir is where API schemas are cached, per Fleet Manager version.
	SpecDir string
	// DefaultName overrides which Fleet Manager is the default.
	DefaultName string
	// Timeout and UserAgent for clients.
	Timeout   time.Duration
	UserAgent string
}

// Registry is the set of known Fleet Managers. It is safe for concurrent
// use.
type Registry struct {
	opts Options

	mu     sync.Mutex
	fleets map[string]Fleet
	conns  map[string]*Conn
	warns  []string
}

// New loads the registry.
func New(opts Options) *Registry {
	r := &Registry{opts: opts, conns: map[string]*Conn{}}
	r.Reload()
	return r
}

// NewStatic returns a registry of ready-made connections (for tests).
func NewStatic(conns ...*Conn) *Registry {
	r := &Registry{fleets: map[string]Fleet{}, conns: map[string]*Conn{}}
	for _, c := range conns {
		r.fleets[c.Name] = c.Fleet
		r.conns[c.Name] = c
	}
	return r
}

// Reload rescans the environment, fleets.json and profiles. Existing
// connections are kept when their entry is unchanged.
func (r *Registry) Reload() {
	if r.opts.Env == nil && r.opts.FleetsFile == "" && r.opts.ProfilesDir == "" {
		return // static registry
	}
	found := map[string]Fleet{}
	var warns []string
	add := func(f Fleet) {
		if err := f.Validate(); err != nil {
			warns = append(warns, err.Error())
			return
		}
		if _, dup := found[f.Name]; dup {
			return // an earlier source wins
		}
		found[f.Name] = f
	}
	if r.opts.Env != nil {
		e := *r.opts.Env
		e.Source = "environment"
		add(e)
	}
	if r.opts.FleetsFile != "" {
		list, err := ReadFile(r.opts.FleetsFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			warns = append(warns, err.Error())
		}
		for _, f := range list {
			f.Source = r.opts.FleetsFile
			add(f)
		}
	}
	if r.opts.ProfilesDir != "" {
		paths, _ := filepath.Glob(filepath.Join(r.opts.ProfilesDir, "*", "profile.json"))
		for _, p := range paths {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			var prof struct {
				URL          string `json:"url"`
				Username     string `json:"username"`
				PasswordFile string `json:"password_file"`
				CertSHA256   string `json:"cert_sha256"`
			}
			if err := json.Unmarshal(b, &prof); err != nil {
				warns = append(warns, fmt.Sprintf("%s: %v", p, err))
				continue
			}
			add(Fleet{
				Name: filepath.Base(filepath.Dir(p)), URL: prof.URL, Username: prof.Username,
				PasswordFile: prof.PasswordFile, CertSHA256: prof.CertSHA256, Source: "installed by fleet-mcp",
			})
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for name, c := range r.conns {
		if f, ok := found[name]; !ok || !sameConn(f, c.Fleet) {
			delete(r.conns, name)
		} else {
			c.Fleet = f // pick up read_only/default changes
		}
	}
	r.fleets, r.warns = found, warns
}

func sameConn(a, b Fleet) bool {
	return a.URL == b.URL && a.Username == b.Username && a.PasswordFile == b.PasswordFile &&
		a.CertSHA256 == b.CertSHA256 && a.CAFile == b.CAFile && a.InsecureSkipVerify == b.InsecureSkipVerify
}

// ReadFile reads a fleets.json file: a JSON array of Fleet entries.
func ReadFile(path string) ([]Fleet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []Fleet
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range list {
		list[i].PasswordFile = expandHome(list[i].PasswordFile)
		list[i].CAFile = expandHome(list[i].CAFile)
	}
	return list, nil
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// List returns the known Fleet Managers sorted by name, and load warnings.
func (r *Registry) List() ([]Fleet, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Fleet, 0, len(r.fleets))
	def := r.defaultLocked()
	for _, f := range r.fleets {
		f.Default = f.Name == def
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, append([]string(nil), r.warns...)
}

// Empty reports whether no Fleet Manager is known.
func (r *Registry) Empty() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.fleets) == 0
}

// defaultLocked picks the default: the configured name, the one marked
// default, the environment entry, or the only entry.
func (r *Registry) defaultLocked() string {
	if n := r.opts.DefaultName; n != "" {
		if _, ok := r.fleets[n]; ok {
			return n
		}
	}
	var marked, env []string
	for name, f := range r.fleets {
		if f.Default {
			marked = append(marked, name)
		}
		if f.Source == "environment" {
			env = append(env, name)
		}
	}
	switch {
	case len(marked) == 1:
		return marked[0]
	case len(env) == 1:
		return env[0]
	case len(r.fleets) == 1:
		for name := range r.fleets {
			return name
		}
	}
	return ""
}

// Get returns a connection to the named Fleet Manager, or the default
// when name is empty. Unknown names trigger one rescan.
func (r *Registry) Get(name string) (*Conn, error) {
	if c, err := r.get(name); err == nil || !strings.Contains(err.Error(), "unknown") {
		return c, err
	}
	r.Reload()
	return r.get(name)
}

func (r *Registry) get(name string) (*Conn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name == "" {
		name = r.defaultLocked()
		if name == "" {
			if len(r.fleets) == 0 {
				return nil, errors.New("unknown fleet: no Fleet Manager is configured; install one with fm_host_install or add it to fleets.json (see fm_fleets)")
			}
			return nil, fmt.Errorf("several Fleet Managers are known (%s); pass fleet to choose one", strings.Join(r.namesLocked(), ", "))
		}
	}
	if c, ok := r.conns[name]; ok {
		return c, nil
	}
	f, ok := r.fleets[name]
	if !ok {
		return nil, fmt.Errorf("unknown fleet %q; known: %s", name, strings.Join(r.namesLocked(), ", "))
	}
	client, err := fleet.New(fleet.Options{
		BaseURL: f.URL, Username: f.Username, PasswordFile: f.PasswordFile,
		CAFile: f.CAFile, InsecureSkipVerify: f.InsecureSkipVerify, PinSHA256: f.CertSHA256,
		Timeout: r.opts.Timeout, UserAgent: r.opts.UserAgent,
	})
	if err != nil {
		return nil, fmt.Errorf("fleet %s: %w", name, err)
	}
	c := &Conn{Fleet: f, Client: client, Specs: spec.NewStore(r.opts.SpecDir, client)}
	r.conns[name] = c
	return c, nil
}

func (r *Registry) namesLocked() []string {
	n := make([]string, 0, len(r.fleets))
	for name := range r.fleets {
		n = append(n, name)
	}
	sort.Strings(n)
	if len(n) == 0 {
		return []string{"(none)"}
	}
	return n
}

// Conns returns the connections opened so far (for logout at exit).
func (r *Registry) Conns() []*Conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Conn, 0, len(r.conns))
	for _, c := range r.conns {
		out = append(out, c)
	}
	return out
}
