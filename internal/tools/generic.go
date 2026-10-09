package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/redact"
)

// blockedGetPrefixes are GET endpoints with side effects (sessions,
// redirects into login flows) that fm_api_get refuses.
var blockedGetPrefixes = []string{
	"/fleet/v1/login",
	"/fleet/v1/logout",
	"/fleet/v1/oauth2/authorize",
	"/fleet/v1/saml/",
	"/fleet/v1/nginx-auth-provider",
	"/graph/",
}

// apiGetLimit caps what fm_api_get reads; larger responses (backup images,
// sensor update images, bundles) are described, not returned.
const apiGetLimit = 8 << 20

// secretPaths return secret values under plain keys such as "value".
var secretPaths = []string{"/fleet/v1/secret"}

// CheckGetPath validates a path for fm_api_get.
func CheckGetPath(path string) error {
	if err := fleet.ValidatePath(path); err != nil {
		return err
	}
	for _, p := range blockedGetPrefixes {
		if strings.HasPrefix(path, p) {
			return fmt.Errorf("fm_api_get does not call %s (side effects or not a REST endpoint)", path)
		}
	}
	return nil
}

// CheckReadOnlyGraphQL rejects documents that contain anything other than
// queries.
func CheckReadOnlyGraphQL(doc string) error {
	q, err := parser.ParseQuery(&ast.Source{Input: doc})
	if err != nil {
		return fmt.Errorf("invalid GraphQL: %w", err)
	}
	if len(q.Operations) == 0 {
		return errors.New("no GraphQL operation found")
	}
	for _, op := range q.Operations {
		if op.Operation != ast.Query {
			name := op.Name
			if name == "" {
				name = "(anonymous)"
			}
			return fmt.Errorf("fm_graphql_query runs queries only; operation %s is a %s", name, op.Operation)
		}
	}
	return nil
}

func registerGeneric(s *mcp.Server, d *Deps) {
	type apiGetArgs struct {
		target
		Path  string            `json:"path" jsonschema:"REST path starting with /, e.g. /fleet/v1/sensor/tag/list (path parameters filled in)"`
		Query map[string]string `json:"query,omitempty" jsonschema:"query string parameters"`
		viewArgs
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_api_get",
		Description: "GET any Fleet Manager REST endpoint and return the JSON (secrets redacted). Use fm_api_describe to find paths and parameters. Non-JSON downloads are summarized, not returned.",
		Annotations: readOnly("REST GET"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a apiGetArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.conn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		if err := CheckGetPath(a.Path); err != nil {
			return nil, nil, err
		}
		var notes []string
		if idx, _, _ := c.Specs.REST(ctx); idx != nil && idx.Match("GET", a.Path) == nil {
			if ms := idx.PathKnown(a.Path); len(ms) > 0 {
				notes = append(notes, fmt.Sprintf("the REST spec lists %s for this path, not GET", strings.Join(ms, ",")))
			} else {
				notes = append(notes, "this path is not in the REST spec")
			}
		}
		q := url.Values{}
		for k, v := range a.Query {
			q.Set(k, v)
		}
		resp, err := c.Client.GetCapped(ctx, a.Path, q, apiGetLimit)
		if err != nil {
			return nil, nil, err
		}
		if resp.Truncated {
			notes = append(notes, fmt.Sprintf("response not returned: larger than %d MiB (content-type %q, content-length %s); this is probably a file download",
				apiGetLimit>>20, resp.ContentType, resp.Header.Get("Content-Length")))
			return textResult("", notes...), nil, nil
		}
		if !resp.IsJSON() {
			return describeBody(resp, d.maxBytes(a.MaxBytes), notes), nil, nil
		}
		var extra []string
		for _, p := range secretPaths {
			if strings.HasPrefix(a.Path, p) {
				extra = append(extra, "value", "data")
			}
		}
		v, err := decode(resp.Body, extra...)
		if err != nil {
			return nil, nil, err
		}
		r, err := d.view(v, a.viewArgs)
		if r != nil && len(notes) > 0 {
			r = prependNotes(r, notes)
		}
		return r, nil, err
	})

	type gqlArgs struct {
		target
		Query     string         `json:"query" jsonschema:"GraphQL query document (queries only; mutations are rejected)"`
		Variables map[string]any `json:"variables,omitempty" jsonschema:"GraphQL variables"`
		viewArgs
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_graphql_query",
		Description: "Run a read-only GraphQL query against Fleet Manager (/graph/query). GraphQL covers content resources (fileSources, fileCollections for intel/input), YARA sources and rulesets, connectors, staged sensors and sensor reservations. select is applied to the \"data\" object. Use fm_api_describe with api=graphql to find fields.",
		Annotations: readOnly("GraphQL query"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a gqlArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.conn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		if err := CheckReadOnlyGraphQL(a.Query); err != nil {
			return nil, nil, err
		}
		resp, err := c.Client.GraphQL(ctx, a.Query, a.Variables)
		if err != nil {
			return nil, nil, err
		}
		v, err := decode(resp.Body)
		if err != nil {
			return nil, nil, err
		}
		m, _ := v.(map[string]any)
		var notes []string
		if errs, ok := m["errors"].([]any); ok && len(errs) > 0 {
			b, _ := json.Marshal(errs)
			if m["data"] == nil {
				return nil, nil, fmt.Errorf("GraphQL errors: %s", b)
			}
			notes = append(notes, "GraphQL errors (partial data returned): "+string(b))
		}
		r, err := d.view(m["data"], a.viewArgs)
		if r != nil && len(notes) > 0 {
			r = prependNotes(r, notes)
		}
		return r, nil, err
	})

	type describeArgs struct {
		target
		Search      string `json:"search,omitempty" jsonschema:"words that must all appear in the path, summary, tags or field name, e.g. \"backup restore\""`
		API         string `json:"api,omitempty" jsonschema:"rest, graphql or both (default both)"`
		Method      string `json:"method,omitempty" jsonschema:"with path: show one REST operation in full"`
		Path        string `json:"path,omitempty" jsonschema:"with method: a REST path, template (/fleet/v1/sensor/policy/{id}) or concrete (/fleet/v1/sensor/policy/17)"`
		GraphQLType string `json:"graphql_type,omitempty" jsonschema:"return the full definition of this GraphQL type (fields, input fields, enum values)"`
		Limit       int    `json:"limit,omitempty" jsonschema:"maximum matches per API (default 40)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_api_describe",
		Description: "Search the Fleet Manager REST spec and GraphQL schema: find endpoints by keyword, show one REST operation's parameters, or show a GraphQL type. Works only when a schema is available (see fm_info); production Fleet Managers usually do not expose them.",
		Annotations: readOnly("Describe API"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a describeArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.conn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		api := strings.ToLower(a.API)
		if api == "" {
			api = "both"
		}
		limit := a.Limit
		if limit <= 0 {
			limit = 40
		}
		out := map[string]any{}

		if a.GraphQLType != "" {
			g, src, err := c.Specs.GraphQL(ctx)
			if g == nil {
				return nil, nil, fmt.Errorf("GraphQL schema unavailable: %v", err)
			}
			raw, ok := g.Types[a.GraphQLType]
			if !ok {
				return nil, nil, fmt.Errorf("no GraphQL type %q; similar: %s", a.GraphQLType, strings.Join(g.TypeNames(a.GraphQLType), ", "))
			}
			var t any
			_ = json.Unmarshal(raw, &t)
			out["source"], out["type"] = src, t
			r, err := jsonResult(out)
			return r, nil, err
		}

		if a.Path != "" {
			idx, src, err := c.Specs.REST(ctx)
			if idx == nil {
				return nil, nil, fmt.Errorf("REST spec unavailable: %v", err)
			}
			method := a.Method
			if method == "" {
				method = "GET"
			}
			op := idx.Match(method, a.Path)
			if op == nil {
				for _, o := range idx.Ops {
					if o.Path == a.Path && strings.EqualFold(o.Method, method) {
						op = o
					}
				}
			}
			if op == nil {
				return nil, nil, fmt.Errorf("no %s %s in the REST spec; methods for this path: %v", strings.ToUpper(method), a.Path, idx.PathKnown(a.Path))
			}
			out["source"], out["operation"] = src, op
			r, err := jsonResult(out)
			return r, nil, err
		}

		if api == "rest" || api == "both" {
			if idx, src, err := c.Specs.REST(ctx); idx != nil {
				rows := []any{}
				for _, o := range idx.Search(a.Search, limit) {
					rows = append(rows, map[string]any{"method": o.Method, "path": o.Path, "summary": o.Summary, "tags": o.Tags})
				}
				out["rest"] = map[string]any{"source": src, "matches": rows}
			} else {
				out["rest"] = map[string]any{"unavailable": err.Error()}
			}
		}
		if api == "graphql" || api == "both" {
			if g, src, err := c.Specs.GraphQL(ctx); g != nil {
				out["graphql"] = map[string]any{"source": src, "matches": g.Search(a.Search, limit)}
			} else {
				out["graphql"] = map[string]any{"unavailable": err.Error()}
			}
		}
		r, err := jsonResult(out)
		return r, nil, err
	})
}

func describeBody(resp *fleet.Response, maxBytes int, notes []string) *mcp.CallToolResult {
	ct := resp.ContentType
	if strings.HasPrefix(ct, "text/") {
		text := redact.String(string(resp.Body))
		if len(text) > maxBytes {
			notes = append(notes, fmt.Sprintf("text truncated to %d of %d bytes", maxBytes, len(text)))
			text = text[:maxBytes]
		}
		return textResult(text, notes...)
	}
	notes = append(notes, fmt.Sprintf("binary response not returned: content-type %q, %d bytes", ct, len(resp.Body)))
	return textResult("", notes...)
}

func prependNotes(r *mcp.CallToolResult, notes []string) *mcp.CallToolResult {
	if len(r.Content) == 0 {
		return textResult("", notes...)
	}
	if tc, ok := r.Content[0].(*mcp.TextContent); ok {
		tc.Text = "note: " + strings.Join(notes, "\nnote: ") + "\n" + tc.Text
	}
	return r
}
