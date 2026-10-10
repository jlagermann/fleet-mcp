// Package migrate exports a sensor policy and the resources it uses from
// one Fleet Manager into a local package, and imports such a package into
// another Fleet Manager. Fleet Manager itself has no export feature.
//
// A package is a directory holding manifest.json and the files the policy
// needs (bundle, Suricata rule and configuration files, YARA rules, input
// and intel files). Secrets are never exported: exporter tokens, password
// settings, licensed rule-feed URLs and connector credentials are listed in
// the manifest as omissions for the user to re-enter on the target.
package migrate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Format identifies the package layout.
const Format = "fleet-mcp-policy-package/1"

// ManifestFile is the manifest's name inside a package directory.
const ManifestFile = "manifest.json"

// Manifest describes an exported policy.
type Manifest struct {
	Format     string    `json:"format"`
	ExportedAt time.Time `json:"exported_at"`
	Source     Source    `json:"source"`
	Policy     Policy    `json:"policy"`
	Bundle     *Bundle   `json:"bundle,omitempty"`
	Suricata   *Suricata `json:"suricata,omitempty"`
	Yara       *Yara     `json:"yara,omitempty"`
	// Collections maps a collection role (input, intel, resource,
	// ca_bundles) to the collection linked to the policy.
	Collections map[string]*Collection `json:"collections,omitempty"`
	Features    Features               `json:"features"`
	Omitted     []Omission             `json:"omitted,omitempty"`
}

// Source records where a package came from.
type Source struct {
	Fleet    string `json:"fleet"`
	Version  string `json:"version"`
	PolicyID int64  `json:"policy_id"`
}

// Policy is the sensor policy itself.
type Policy struct {
	Name                string          `json:"name"`
	Description         string          `json:"description,omitempty"`
	Configuration       map[string]any  `json:"configuration"`
	PackagesEnabled     map[string]bool `json:"packages_enabled,omitempty"`
	EnableSuricataVLAN  bool            `json:"enable_suricata_vlan,omitempty"`
	FilterConfiguration map[string]any  `json:"filter_configuration,omitempty"`
}

// FileRef is a file stored in the package.
type FileRef struct {
	Path   string `json:"path"` // relative to the package directory
	Name   string `json:"name"` // file name on the source Fleet Manager
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Bundle is the Zeek package bundle.
type Bundle struct {
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	File        FileRef `json:"file"`
}

// Suricata is the linked Suricata policy. The generated rule set is not
// exported; the target Fleet Manager builds its own from the sources.
type Suricata struct {
	Name             string              `json:"name"`
	Description      string              `json:"description,omitempty"`
	Settings         map[string]any      `json:"settings,omitempty"`
	HomeNet          string              `json:"home_net,omitempty"`
	RulesAutomation  bool                `json:"rules_automation"`
	UseModifierFiles bool                `json:"use_modifier_files"`
	Config           map[string]any      `json:"config,omitempty"`
	Sources          []SuricataSource    `json:"sources,omitempty"`
	Files            map[string]*FileRef `json:"files,omitempty"` // yaml, threshold, classification, reference
	ModifierFiles    []ModifierFile      `json:"modifier_files,omitempty"`
}

// SuricataSource is a rule source: an uploaded file or a URL.
type SuricataSource struct {
	Name       string   `json:"name"`
	EntityType string   `json:"entity_type"` // file or url
	URL        string   `json:"url,omitempty"`
	Notes      string   `json:"notes,omitempty"`
	Enabled    bool     `json:"enabled"`
	File       *FileRef `json:"file,omitempty"`
}

// ModifierFile is disable.conf, enable.conf, modify.conf and the like.
type ModifierFile struct {
	Name    string   `json:"name"`
	Enabled bool     `json:"enabled"`
	URL     string   `json:"url,omitempty"`
	File    *FileRef `json:"file,omitempty"`
}

// Yara is the linked YARA ruleset. Its compiled file is not exported.
type Yara struct {
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Sources     []YaraSource `json:"sources,omitempty"`
}

// YaraSource is an uploaded YARA rules file.
type YaraSource struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Namespace   string   `json:"namespace,omitempty"`
	Enabled     bool     `json:"enabled"`
	Interval    *int64   `json:"interval,omitempty"`
	File        *FileRef `json:"file,omitempty"`
}

// Collection is an input, intel, resource or CA bundle collection.
type Collection struct {
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Type        string       `json:"type"` // INPUT, INTEL, RESOURCE, CA_BUNDLES
	Sources     []FileSource `json:"sources,omitempty"`
}

// FileSource is one source of a collection.
type FileSource struct {
	Alias       string   `json:"alias"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Type        string   `json:"type"`
	Enabled     bool     `json:"enabled"`
	Interval    *int64   `json:"interval,omitempty"`
	File        *FileRef `json:"file,omitempty"`
	// Snapshot is set when the source was fed by a connector and the
	// package holds the connector's latest file instead.
	Snapshot  bool       `json:"snapshot,omitempty"`
	Connector *Connector `json:"connector,omitempty"`
}

// Connector names the app connector that fed a source on the source Fleet
// Manager. Its configuration and credentials are not exported.
type Connector struct {
	AppConnectorID string `json:"app_connector_id"`
	Name           string `json:"name"`
}

// Features are what the policy needs from the target Fleet Manager.
type Features struct {
	// Licensed are sensor license names (suricata, yara, smartpcap,
	// asset_classification, ...) whose features the policy enables.
	Licensed []string `json:"licensed,omitempty"`
	// Exporters are the exporter types the policy configures.
	Exporters []string `json:"exporters,omitempty"`
}

// Omission is something the package does not carry.
type Omission struct {
	Part   string `json:"part"`
	Item   string `json:"item"`
	Reason string `json:"reason"`
	Action string `json:"action"`
}

// ReadManifest loads and checks a package's manifest. It returns the
// manifest and the SHA-256 digest of manifest.json, which covers every
// file through their recorded checksums.
func ReadManifest(dir string) (*Manifest, string, error) {
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, "", err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, "", fmt.Errorf("%s: %w", ManifestFile, err)
	}
	if m.Format != Format {
		return nil, "", fmt.Errorf("%s: format %q is not %q", ManifestFile, m.Format, Format)
	}
	sum := sha256.Sum256(b)
	return &m, hex.EncodeToString(sum[:]), nil
}

// VerifyFiles checks every file in the manifest against its checksum.
func VerifyFiles(dir string, m *Manifest) error {
	var errs []error
	for _, f := range m.files() {
		got, n, err := hashFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		switch {
		case err != nil:
			errs = append(errs, err)
		case got != f.SHA256 || n != f.Size:
			errs = append(errs, fmt.Errorf("%s: checksum or size does not match the manifest", f.Path))
		}
	}
	return errors.Join(errs...)
}

// files lists every file reference in the manifest.
func (m *Manifest) files() []*FileRef {
	var out []*FileRef
	if m.Bundle != nil {
		out = append(out, &m.Bundle.File)
	}
	if s := m.Suricata; s != nil {
		for i := range s.Sources {
			if s.Sources[i].File != nil {
				out = append(out, s.Sources[i].File)
			}
		}
		for _, k := range sortedKeys(s.Files) {
			out = append(out, s.Files[k])
		}
		for i := range s.ModifierFiles {
			if s.ModifierFiles[i].File != nil {
				out = append(out, s.ModifierFiles[i].File)
			}
		}
	}
	if m.Yara != nil {
		for i := range m.Yara.Sources {
			if m.Yara.Sources[i].File != nil {
				out = append(out, m.Yara.Sources[i].File)
			}
		}
	}
	for _, k := range sortedKeys(m.Collections) {
		for i := range m.Collections[k].Sources {
			if f := m.Collections[k].Sources[i].File; f != nil {
				out = append(out, f)
			}
		}
	}
	return out
}

// TotalBytes is the size of all files in the package.
func (m *Manifest) TotalBytes() int64 {
	var n int64
	seen := map[string]bool{}
	for _, f := range m.files() {
		if !seen[f.Path] {
			seen[f.Path] = true
			n += f.Size
		}
	}
	return n
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// safeName turns a Fleet Manager name into a file or directory name.
func safeName(s string) string {
	s = strings.Trim(unsafeName.ReplaceAllString(s, "_"), "._")
	if s == "" {
		s = "unnamed"
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// PackageName turns any text into a valid package directory name.
func PackageName(s string) string { return safeName(s) }

// ValidPackageName reports whether name can name a package directory.
func ValidPackageName(name string) bool {
	return name != "" && name == safeName(name)
}
