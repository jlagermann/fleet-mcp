// Package tools defines the fleet-mcp MCP tools.
package tools

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleets"
	"github.com/jlagermann/fleet-mcp/internal/guides"
	"github.com/jlagermann/fleet-mcp/internal/jsonview"
	"github.com/jlagermann/fleet-mcp/internal/redact"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
)

// DefaultMaxBytes caps a tool result when the caller does not set max_bytes.
const DefaultMaxBytes = 60_000

// Deps are shared by all tools.
type Deps struct {
	// Fleets is the set of Fleet Managers the API tools can reach.
	Fleets *fleets.Registry
	// MaxBytes is the default output cap; 0 means DefaultMaxBytes.
	MaxBytes int
	// EnableWrites registers the tools that change Fleet Manager.
	EnableWrites bool
	// Audit records executed changes; nil discards them.
	Audit *audit.Log
	// Secrets holds repository tokens, certificates and generated
	// passwords for host installs; nil disables the host tools.
	Secrets *secrets.Store
	// SSHUser and SSHBinary are defaults for host tools.
	SSHUser, SSHBinary string
	// PackagesDir holds exported policy packages; empty disables the
	// export, import and copy tools.
	PackagesDir string
}

// target selects the Fleet Manager a tool call acts on.
type target struct {
	Fleet string `json:"fleet,omitempty" jsonschema:"name of the Fleet Manager to use (see fm_fleets); omit for the default"`
}

// conn returns the connection for a tool call.
func (d *Deps) conn(name string) (*fleets.Conn, error) {
	if d.Fleets == nil {
		return nil, errors.New("no Fleet Manager registry configured")
	}
	return d.Fleets.Get(name)
}

// writeConn is conn for tools that change Fleet Manager.
func (d *Deps) writeConn(name string) (*fleets.Conn, error) {
	c, err := d.conn(name)
	if err != nil {
		return nil, err
	}
	if c.ReadOnly {
		return nil, fmt.Errorf("fleet %s is read-only (read_only in %s); changes are refused", c.Name, c.Source)
	}
	return c, nil
}

func (d *Deps) maxBytes(requested int) int {
	if requested > 0 {
		return requested
	}
	if d.MaxBytes > 0 {
		return d.MaxBytes
	}
	return DefaultMaxBytes
}

// Instructions returns the text sent to MCP clients at initialization.
// Clients truncate it (Claude Code at 4096 bytes), so it holds only what
// applies to every call, safety rules first; workflows are in the guides
// (fm_guide and the MCP prompts).
func Instructions(writes bool) string {
	var b strings.Builder
	b.WriteString("fleet-mcp installs and manages Corelight Fleet Managers (FM).\n\nRules:\n")
	if writes {
		b.WriteString(writeInstructions)
	} else {
		b.WriteString("- This server is read-only (writes are not enabled).\n")
	}
	b.WriteString(rules)
	b.WriteString("- fleet-mcp may not be on the user's PATH: give every fleet-mcp terminal command with its full path, as tool results do: " + secrets.Command("secret", "set", "<name>") + "\n")
	b.WriteString("\nGuides: before a multi-step task, call fm_guide with its topic and follow it:\n")
	for _, g := range guides.All() {
		b.WriteString("- " + g.Name + ": " + g.When + "\n")
	}
	b.WriteString(usage)
	return b.String()
}

const writeInstructions = `- Changes take two calls. The first returns a preview and a confirm_token and changes nothing. Show the preview to the user and get explicit approval before the second call, which repeats the identical request with confirm_token. Never send it without that approval; preview again if anything in the request changes. Executed changes are audited.
`

const rules = `- Never ask for passwords, tokens or keys in the chat. The user types them at a hidden terminal prompt (fleet-mcp secret set ...) or in the Fleet Manager web interface. Results have secrets replaced with "[REDACTED]".
- One server can reach several Fleet Managers: fm_fleets lists them, and every FM tool takes an optional fleet argument. Always say which Fleet Manager a result came from, and name it in every change you propose. Fleet Managers marked read_only refuse changes.
- Fleet Manager has sensor policies and Suricata policies. When the user asks about "a policy" without saying which, ask which kind first.
`

const usage = `
Tools:
- Named tools (fm_sensors_list, fm_policies_list, ...) return compact summaries; use the matching *_get tool or fm_api_get for full records. Narrow large results with select (a JSON Pointer; keys may contain dots, e.g. "/health.status"), fields, offset/limit and max_bytes.
- fm_api_get reaches any REST GET endpoint and fm_graphql_query any GraphQL query; fm_api_describe finds endpoints, parameters and fields. fm_info shows an FM's version, user and schema availability.
- Fleet Manager's update trigger only pushes policy; it never upgrades sensor software.
`

// viewArgs are the output-shaping arguments shared by many tools.
type viewArgs struct {
	Select   string   `json:"select,omitempty" jsonschema:"JSON Pointer to return only part of the result, e.g. /list/0 or /services.status"`
	Fields   []string `json:"fields,omitempty" jsonschema:"keep only these JSON Pointers within each array item (or within the selected object), e.g. [\"name\", \"health.status\"]"`
	Offset   int      `json:"offset,omitempty" jsonschema:"skip this many items of the selected array"`
	Limit    int      `json:"limit,omitempty" jsonschema:"return at most this many items of the selected array"`
	MaxBytes int      `json:"max_bytes,omitempty" jsonschema:"cap the result size in bytes (default 60000)"`
}

func (d *Deps) view(v any, va viewArgs) (*mcp.CallToolResult, error) {
	res, err := jsonview.View(v, jsonview.Options{
		Select: va.Select, Fields: va.Fields, Offset: va.Offset, Limit: va.Limit,
		MaxBytes: d.maxBytes(va.MaxBytes),
	})
	if err != nil {
		return nil, err
	}
	return textResult(string(res.JSON), res.Notes...), nil
}

// decode parses a JSON body and redacts it.
func decode(body []byte, extraSensitive ...string) (any, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("response is not JSON: %w", err)
	}
	return redact.Value(v, extraSensitive...), nil
}

func textResult(text string, notes ...string) *mcp.CallToolResult {
	if len(notes) > 0 {
		text = "note: " + strings.Join(notes, "\nnote: ") + "\n" + text
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func jsonResult(v any, notes ...string) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return textResult(string(b), notes...), nil
}

func readOnly(title string) *mcp.ToolAnnotations {
	f := false
	return &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &f}
}

// Register adds every tool to s.
func Register(s *mcp.Server, d *Deps) {
	registerGuides(s)
	registerHostDiag(s, d)
	if d.Fleets != nil {
		registerFleets(s, d)
		registerFleetHealth(s, d)
		registerUsers(s, d)
		registerPolicyDiff(s, d)
		registerRead(s, d)
		registerDiagnose(s, d)
		registerGeneric(s, d)
		registerNewPolicy(s, d)
		registerSuricataTest(s, d)
		if d.EnableWrites {
			registerWrite(s, d)
			registerContentWrite(s, d)
			registerSuricataModify(s, d)
			registerPolicyEdit(s, d)
			registerSoftSensorUpgrade(s, d)
			registerUserManage(s, d)
			if d.Secrets != nil {
				registerNewPolicyWrite(s, d)
			}
		}
		if d.PackagesDir != "" {
			registerMigrate(s, d)
			if d.EnableWrites {
				registerMigrateWrite(s, d)
			}
		}
	}
	if d.Secrets != nil {
		registerHost(s, d)
		if d.Fleets != nil {
			registerSensorShell(s, d)
		}
		if d.EnableWrites {
			registerHostWrite(s, d)
			registerHostMaint(s, d)
			if d.Fleets != nil {
				registerSensorWrite(s, d)
				registerSensorKeyWrite(s, d)
				registerSensorAction(s, d)
				registerSupportAccess(s, d)
			}
		}
	}
}
