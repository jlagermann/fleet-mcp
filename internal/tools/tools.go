// Package tools defines the fleet-mcp MCP tools.
package tools

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/jsonview"
	"github.com/jlagermann/fleet-mcp/internal/redact"
	"github.com/jlagermann/fleet-mcp/internal/spec"
)

// DefaultMaxBytes caps a tool result when the caller does not set max_bytes.
const DefaultMaxBytes = 60_000

// Deps are shared by all tools.
type Deps struct {
	Client *fleet.Client
	Specs  *spec.Store
	// MaxBytes is the default output cap; 0 means DefaultMaxBytes.
	MaxBytes int
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

// Instructions are sent to MCP clients at initialization.
const Instructions = `fleet-mcp manages a Corelight Fleet Manager (FM).

All tools in this build are read-only.

- Start with fm_info to see the FM version, the logged-in user and whether the API schemas are available.
- Named tools (fm_sensors_list, fm_groups_list, fm_policies_list, ...) return compact summaries. Use the matching *_get tool or fm_api_get for full records.
- fm_api_get reaches any REST GET endpoint; fm_graphql_query runs GraphQL queries (mutations are rejected). Use fm_api_describe to find endpoints, parameters and GraphQL fields.
- Large results: narrow them with select (a JSON Pointer such as "/list/0"; keys may contain dots, e.g. "/health.status"), fields (pointers kept per item), offset/limit, and max_bytes.
- Secrets (passwords, tokens, keys, license codes in feed URLs) are replaced with "[REDACTED]" before results are returned.`

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
	registerRead(s, d)
	registerGeneric(s, d)
}
