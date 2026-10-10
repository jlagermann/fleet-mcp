package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jlagermann/fleet-mcp/internal/host"
)

// SecretsFile holds secret setting values (exporter tokens) for a package,
// keyed by setting. Fleet Manager's API never returns them, so they come
// from the source Fleet Manager's database or from the user. The file is
// readable only by its owner, is not covered by the manifest digest, and is
// deleted once nothing in the package needs it.
const SecretsFile = "secrets.json"

// SecretRef is a secret setting a package needs at import.
type SecretRef struct {
	Key   string `json:"key"`
	Label string `json:"label"` // e.g. "Splunk Enterprise (hec) hec_token"
	Part  string `json:"part"`  // exporters or policy
}

// Secrets lists the secret settings the package left out.
func (m *Manifest) Secrets() []SecretRef {
	var out []SecretRef
	for _, o := range m.Omitted {
		key := o.Key
		if key == "" && o.Part == "exporters" {
			key = m.exporterSecretKey(o.Item)
		}
		if key != "" {
			out = append(out, SecretRef{Key: key, Label: o.Item, Part: o.Part})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// exporterSecretKey recovers the setting of an exporter omission recorded
// before omissions carried keys ("<name> (<type>) <field>").
func (m *Manifest) exporterSecretKey(item string) string {
	i := strings.LastIndex(item, ") ")
	j := strings.LastIndex(item[:max(i, 0)], " (")
	if i < 0 || j < 0 {
		return ""
	}
	name, typ, field := item[:j], item[j+2:i], item[i+2:]
	for k, v := range m.Policy.Configuration {
		if inst, f, ok := exporterKey(k); ok && f == "name" && str(v) == name &&
			str(m.Policy.Configuration["bro.exporters."+inst+".type"]) == typ {
			return "bro.exporters." + inst + "." + field
		}
	}
	return ""
}

// ReadSecrets loads a package's secret values (none if there are none).
func ReadSecrets(dir string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, SecretsFile))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s: %w", SecretsFile, err)
	}
	return out, nil
}

// AddSecrets merges values into a package's secrets file.
func AddSecrets(dir string, values map[string]string) error {
	cur, err := ReadSecrets(dir)
	if err != nil {
		return err
	}
	for k, v := range values {
		cur[k] = v
	}
	b, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, SecretsFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, SecretsFile))
}

// RemoveSecrets deletes a package's secrets file.
func RemoveSecrets(dir string) error {
	err := os.Remove(filepath.Join(dir, SecretsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// MissingSecrets lists the package's secrets not yet in its secrets file.
func MissingSecrets(dir string, m *Manifest) ([]SecretRef, error) {
	have, err := ReadSecrets(dir)
	if err != nil {
		return nil, err
	}
	var out []SecretRef
	for _, s := range m.Secrets() {
		if have[s.Key] == "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// DatabasePath is the Fleet Manager database that holds policy settings.
const DatabasePath = "/var/lib/corelight-fleetd/sensor-catalog"

var safeKey = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ReadDatabaseSecrets reads secret setting values of one policy from a
// Fleet Manager's database over SSH, read-only. Fleet Manager stores policy
// settings, exporter tokens included, unencrypted in PolicyConfig.
func ReadDatabaseSecrets(ctx context.Context, r host.Runner, policyID int64, keys []string) (map[string]string, error) {
	if len(keys) == 0 {
		return map[string]string{}, nil
	}
	quoted := make([]string, len(keys))
	for i, k := range keys {
		if !safeKey.MatchString(k) {
			return nil, fmt.Errorf("unexpected setting name %q", k)
		}
		quoted[i] = "'" + k + "'"
	}
	query := fmt.Sprintf("SELECT Key, Value FROM PolicyConfig WHERE ParentID = %d AND Key IN (%s);", policyID, strings.Join(quoted, ","))
	script := "command -v sqlite3 >/dev/null || { echo 'sqlite3 is not installed' >&2; exit 3; }\n" +
		"sqlite3 -json " + host.Quote("file:"+DatabasePath+"?mode=ro") + " " + host.Quote(query) + "\n"
	res, err := r.Run(ctx, script)
	if err != nil {
		return nil, err
	}
	if !res.OK() {
		return nil, fmt.Errorf("reading %s on %s: %s", DatabasePath, r.Name(), strings.TrimSpace(res.Stderr))
	}
	out := map[string]string{}
	if strings.TrimSpace(res.Stdout) == "" {
		return out, nil
	}
	var rows []struct {
		Key   string `json:"Key"`
		Value string `json:"Value"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &rows); err != nil {
		return nil, fmt.Errorf("reading %s on %s: unexpected output", DatabasePath, r.Name())
	}
	for _, row := range rows {
		out[row.Key] = row.Value
	}
	return out, nil
}

// planSecrets adds the secret settings for what is being sent (exporters
// in the configuration, password settings) from the package's secrets
// file. Missing ones become a question (how to supply them) or a blocker.
func (p *Plan) planSecrets(dir string, m *Manifest, opts ImportOptions) error {
	have, err := ReadSecrets(dir)
	if err != nil {
		return err
	}
	p.secretKeys = map[string]bool{}
	var missing []SecretRef
	all := true
	for _, s := range m.Secrets() {
		if opts.Complete && s.Part != "exporters" {
			continue // set by the first import
		}
		if s.Part == "exporters" {
			inst, _, _ := exporterKey(s.Key)
			if _, sending := p.configuration["bro.exporters."+inst+".type"]; !sending {
				all = false
				continue
			}
		}
		v := have[s.Key]
		p.Tokens = append(p.Tokens, TokenStatus{Setting: s.Key, Label: s.Label, Provided: v != ""})
		if v == "" {
			missing = append(missing, s)
			continue
		}
		p.configuration[s.Key] = v
		p.secretKeys[s.Key] = true
	}
	p.sendsAllSecrets = all && len(missing) == 0
	// Secrets that will be sent need no follow-up.
	// Older packages' omissions carry no key; match them by label.
	byLabel := map[string]string{}
	for _, s := range m.Secrets() {
		byLabel[s.Label] = s.Key
	}
	kept := p.FollowUp[:0]
	for _, o := range p.FollowUp {
		key := o.Key
		if key == "" {
			key = byLabel[o.Item]
		}
		if key == "" || !p.secretKeys[key] {
			kept = append(kept, o)
		}
	}
	p.FollowUp = kept
	if len(missing) == 0 {
		return nil
	}
	labels := make([]string, len(missing))
	for i, s := range missing {
		labels[i] = s.Label
	}
	pkg := filepath.Base(dir)
	switch opts.ExporterTokens {
	case "":
		p.Decisions = append(p.Decisions, Decision{
			ID: "exporter_tokens",
			Question: fmt.Sprintf("Fleet Manager's API never returns these %d secrets, so they must be supplied: %s. Copy them from %s's database (read over SSH, read-only), or type each one at a hidden prompt?",
				len(missing), strings.Join(labels, "; "), m.Source.Fleet),
			Resolve: map[string]string{
				"database": `preview again with exporter_tokens "database"`,
				"prompt":   `preview again with exporter_tokens "prompt"; the user runs: fleet-mcp policy tokens ` + pkg,
			},
		})
	case "prompt":
		p.block("%d secrets still need values: run `fleet-mcp policy tokens %s` in a terminal, enter them, then preview again (%s)", len(missing), pkg, strings.Join(labels, "; "))
	case "database":
		p.block("%d secrets were not found in %s's database: %s; use exporter_tokens \"prompt\" for them", len(missing), m.Source.Fleet, strings.Join(labels, "; "))
	}
	return nil
}

// secretSet reports whether a secret setting read back is set: Fleet
// Manager returns true for a stored secret.
func secretSet(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != ""
	}
	return false
}
