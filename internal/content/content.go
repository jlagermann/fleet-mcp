// Package content pushes content files to Fleet Manager as they are: intel
// and input files, YARA rules, Suricata rules and configuration files, and
// Zeek package bundles. It diffs a file against what Fleet Manager has,
// validates what Fleet Manager can validate, optionally links the content
// to a sensor policy, and verifies the result. It never fetches, merges or
// rewrites content; that stays with the user's own tooling.
package content

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
)

// API is the part of *fleet.Client that content uses.
type API interface {
	Do(ctx context.Context, method, path string, query url.Values, body []byte, contentType string) (*fleet.Response, error)
	GetJSON(ctx context.Context, path string, query url.Values, out any) error
	GraphQL(ctx context.Context, query string, variables map[string]any) (*fleet.Response, error)
	GraphQLUpload(ctx context.Context, query string, variables map[string]any, filePath, fileName string, content []byte) (*fleet.Response, error)
	DoMultipart(ctx context.Context, method, path string, fields map[string]string, files ...fleet.FilePart) (*fleet.Response, error)
	Download(ctx context.Context, path string, w io.Writer, limit int64) (int64, error)
}

var _ API = (*fleet.Client)(nil)

// Kind is the type of content pushed.
type Kind string

// Content kinds.
const (
	Intel                  Kind = "intel"
	Input                  Kind = "input"
	Yara                   Kind = "yara"
	SuricataRules          Kind = "suricata_rules"
	SuricataYAML           Kind = "suricata_yaml"
	SuricataThreshold      Kind = "suricata_threshold"
	SuricataClassification Kind = "suricata_classification"
	SuricataReference      Kind = "suricata_reference"
	Bundle                 Kind = "bundle"
)

// suricataConfig maps the Suricata configuration kinds to the Suricata
// policy field and file-manager store they use.
var suricataConfig = map[Kind]struct{ Field, Store, File string }{
	SuricataYAML:           {"suricata-yaml-file-id", "suricata-yaml", "suricata.yaml"},
	SuricataThreshold:      {"suricata-threshold-file-id", "suricata-threshold", "threshold.config"},
	SuricataClassification: {"suricata-classification-file-id", "suricata-classification", "classification.config"},
	SuricataReference:      {"suricata-reference-file-id", "suricata-reference", "reference.config"},
}

// Kinds lists every kind, for argument descriptions.
func Kinds() []string {
	return []string{string(Intel), string(Input), string(Yara), string(SuricataRules), string(SuricataYAML),
		string(SuricataThreshold), string(SuricataClassification), string(SuricataReference), string(Bundle)}
}

// DefaultSource names the source fleet-mcp creates when the user names none
// (intel, YARA, Suricata rules with rules automation).
const DefaultSource = "fleet-mcp"

// DefaultDescription marks objects fleet-mcp creates.
const DefaultDescription = "Created by fleet-mcp"

// MaxFileBytes caps a pushed file and a downloaded current file.
const MaxFileBytes = 512 << 20

// Request is one push.
type Request struct {
	Kind Kind   `json:"kind" jsonschema:"what to push: intel, input, yara, suricata_rules, suricata_yaml, suricata_threshold, suricata_classification, suricata_reference or bundle"`
	File string `json:"file" jsonschema:"path of the local file to push, as it is (fleet-mcp does not merge or rewrite content)"`
	// Source names the object updated in place, or created when none has it.
	Source string `json:"source,omitempty" jsonschema:"intel/input: the file source alias; yara: the YARA source name; suricata_rules on a policy with rules automation: the rule source name. An existing one is updated in place, otherwise one is created. Default: fleet-mcp (input: the file name)"`
	// Name is the file name an input file gets on the sensors.
	Name        string `json:"name,omitempty" jsonschema:"input only: the file name on the sensors, which the Zeek package reading it looks for (default: the local file's name)"`
	Description string `json:"description,omitempty" jsonschema:"description for a new source or bundle (default: Created by fleet-mcp)"`
	// Policy is the sensor policy to link to (bundle: required).
	Policy string `json:"policy,omitempty" jsonschema:"sensor policy id or exact name. bundle: required, the policy whose bundle is replaced. intel/input/yara: optional, adds the source to that policy's collection or YARA ruleset (created if the policy has none). suricata_*: the policy's Suricata policy is used if suricata_policy is not given"`
	// SuricataPolicy is the Suricata policy for suricata_* kinds.
	SuricataPolicy string `json:"suricata_policy,omitempty" jsonschema:"suricata_* only: Suricata policy id or exact name"`
}

// FileInfo describes the local file.
type FileInfo struct {
	Path   string `json:"path"`
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
}

// Target is the Fleet Manager object a push changes.
type Target struct {
	Object        string `json:"object"`
	ID            int64  `json:"id,omitempty"`
	Name          string `json:"name"`
	Exists        bool   `json:"exists"`
	ManagedBy     string `json:"managed_by,omitempty"`
	CurrentSHA256 string `json:"current_sha256,omitempty"`
	CurrentSize   int64  `json:"current_size_bytes,omitempty"`
}

// PolicyRef is the sensor policy a push links to or changes.
type PolicyRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// Plan is what a push will do. Its exported fields are the preview.
type Plan struct {
	Kind       Kind           `json:"kind"`
	File       FileInfo       `json:"file"`
	Target     Target         `json:"target"`
	Unchanged  bool           `json:"unchanged,omitempty"`
	Diff       map[string]any `json:"diff,omitempty"`
	Validation map[string]any `json:"validation,omitempty"`
	Policy     *PolicyRef     `json:"policy,omitempty"`
	Steps      []string       `json:"steps"`
	UsedBy     []string       `json:"used_by_sensor_policies,omitempty"`
	Notes      []string       `json:"notes,omitempty"`
	Warnings   []string       `json:"warnings,omitempty"`
	Blockers   []string       `json:"blockers,omitempty"`

	req     Request
	content []byte
	fileNm  string // the local file's base name
	// state fingerprints what the plan was built from, for the confirm token.
	state []string
	// link holds what linking to the policy needs.
	link linkPlan
	// suricata holds the Suricata policy for suricata_* kinds.
	suricata map[string]any
	// policyBody is the sensor policy as read (bundle and links).
	policyBody map[string]any
	// sameFile is set when Fleet Manager already has the exact file.
	sameFile bool
}

type linkPlan struct {
	needed       bool
	collectionID int64  // existing collection or ruleset to add the source to
	createName   string // a collection or ruleset to create and link
	policyField  string // the policy field to set when one is created
	alreadyIn    bool
}

// Ready reports whether the plan can be applied.
func (p *Plan) Ready() bool { return len(p.Blockers) == 0 && !p.Unchanged }

// State is what the plan was built from; a confirm token covers it, so a
// change on Fleet Manager or in the file between preview and confirm is
// caught.
func (p *Plan) State() []string {
	return append([]string{string(p.Kind), p.File.SHA256, p.Target.CurrentSHA256, strconv.FormatInt(p.Target.ID, 10)}, p.state...)
}

func (p *Plan) block(format string, a ...any) {
	p.Blockers = append(p.Blockers, fmt.Sprintf(format, a...))
}
func (p *Plan) warn(format string, a ...any) {
	p.Warnings = append(p.Warnings, fmt.Sprintf(format, a...))
}
func (p *Plan) note(format string, a ...any) { p.Notes = append(p.Notes, fmt.Sprintf(format, a...)) }
func (p *Plan) step(format string, a ...any) { p.Steps = append(p.Steps, fmt.Sprintf(format, a...)) }

// readLocal reads and hashes the local file.
func readLocal(path string) ([]byte, FileInfo, error) {
	if path == "" {
		return nil, FileInfo{}, errors.New("file is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, FileInfo{}, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, FileInfo{}, err
	}
	if !st.Mode().IsRegular() {
		return nil, FileInfo{}, fmt.Errorf("%s is not a regular file", abs)
	}
	if st.Size() > MaxFileBytes {
		return nil, FileInfo{}, fmt.Errorf("%s is %d bytes, over the %d MB limit", abs, st.Size(), MaxFileBytes>>20)
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return nil, FileInfo{}, err
	}
	sum := sha256.Sum256(b)
	return b, FileInfo{Path: abs, Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])}, nil
}

// managedBy names the tool that manages an object, from the conventions
// Corelight-update and Fleet-client use.
func managedBy(name, description string) string {
	d := strings.ToLower(description)
	switch {
	case strings.Contains(d, "corelight update") || strings.Contains(d, "corelight-update") ||
		strings.HasPrefix(strings.ToLower(name), "corelight-update"):
		return "Corelight-update"
	case strings.Contains(d, "fleet client") || strings.Contains(d, "fleet-client") || strings.EqualFold(name, "fleet-client"):
		return "Fleet-client"
	case strings.Contains(d, "fleet-mcp"):
		return "fleet-mcp"
	}
	return ""
}

// GraphQL and JSON helpers.

type gqlError struct{ msgs []string }

func (e *gqlError) Error() string { return "GraphQL: " + strings.Join(e.msgs, "; ") }

func decodeGraphQL(resp *fleet.Response, err error, out any) error {
	if err != nil {
		return err
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(resp.Body, &env); err != nil {
		return fmt.Errorf("GraphQL response is not JSON: %w", err)
	}
	if len(env.Errors) > 0 {
		ge := &gqlError{}
		for _, e := range env.Errors {
			ge.msgs = append(ge.msgs, e.Message)
		}
		return ge
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

func gql(ctx context.Context, api API, query string, vars map[string]any, out any) error {
	resp, err := api.GraphQL(ctx, query, vars)
	return decodeGraphQL(resp, err, out)
}

func jsonBody(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func idOf(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	}
	return 0
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func listOf(v any) []any {
	l, _ := v.([]any)
	return l
}

func responseID(resp *fleet.Response) (int64, error) {
	var out map[string]any
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return 0, fmt.Errorf("response is not JSON: %w", err)
	}
	if id := idOf(out["id"]); id > 0 {
		return id, nil
	}
	return 0, errors.New("response has no id")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sample returns at most n items, for previews.
func sample(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	return append(append([]string(nil), items[:n]...), fmt.Sprintf("... and %d more", len(items)-n))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
