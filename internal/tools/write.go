package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/jsonview"
	"github.com/jlagermann/fleet-mcp/internal/redact"
)

const diffLimit = 200

var writeMethods = map[string]bool{
	http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
}

// blockedWritePrefixes are endpoints fm_api_write refuses: session and
// credential endpoints for the MCP's own user, and GraphQL (which has its
// own tool).
var blockedWritePrefixes = []string{
	"/fleet/v1/login",
	"/fleet/v1/logout",
	"/fleet/v1/oauth2/token",
	"/fleet/v1/oauth2/authorize",
	"/fleet/v1/current/",
	"/fleet/v1/saml/",
	"/graph/",
}

type impact struct {
	method string // "" matches any write method
	prefix string
	note   string
}

// highImpact endpoints get an explicit warning in the preview.
var highImpact = []impact{
	{http.MethodPost, "/fleet/v1/server/backup/restore", "restores Fleet Manager from a backup image, replacing its current configuration"},
	{http.MethodPost, "/fleet/v1/server/backup/clone", "clones Fleet Manager configuration from a backup"},
	{http.MethodDelete, "/fleet/v1/server/backup", "deletes the current backup image"},
	{http.MethodDelete, "/fleet/v1/token/global_key", "rotates the global sensor token key and revokes ALL sensor tokens"},
	{http.MethodDelete, "/fleet/v1/token/", "revokes a sensor token"},
	{http.MethodDelete, "/fleet/v1/sensor/catalog/", "removes a sensor (or its exceptions) from Fleet Manager"},
	{"", "/fleet/v1/sensor/catalog/", "changes a sensor's Fleet Manager record; apply-changes pushes configuration to the sensor"},
	{"", "/fleet/v1/sensor/instance/", "sends a change directly to a sensor"},
	{"", "/fleet/v1/sensor-update/", "affects sensor software updates"},
	{"", "/fleet/v1/sensor/policy", "changes a sensor policy; sensors in its groups receive the change"},
	{"", "/fleet/v1/suricata", "changes Suricata policy or rules deployed to sensors"},
	{"", "/fleet/v1/users", "changes Fleet Manager users; can lock out users, including this server's own"},
	{"", "/fleet/v1/roles", "changes roles and permissions; can remove this server's own access"},
	{"", "/fleet/v1/auth/", "changes authentication providers or session settings"},
	{"", "/fleet/v1/tenants", "changes organizations (tenants)"},
	{"", "/fleet/v1/secret", "changes stored secrets"},
	{"", "/fleet/v1/settings", "changes Fleet Manager settings"},
}

// CheckWritePath validates a path and method for fm_api_write.
func CheckWritePath(method, path string) error {
	if !writeMethods[method] {
		return fmt.Errorf("method must be POST, PUT, PATCH or DELETE, got %q (use fm_api_get to read)", method)
	}
	if err := fleet.ValidatePath(path); err != nil {
		return err
	}
	for _, p := range blockedWritePrefixes {
		if strings.HasPrefix(path, p) {
			if p == "/graph/" {
				return errors.New("use fm_graphql_mutate for GraphQL")
			}
			return fmt.Errorf("fm_api_write does not call %s (session or credential endpoint for the server's own user)", path)
		}
	}
	return nil
}

func impactNotes(method, path string) []string {
	var out []string
	if method == http.MethodDelete {
		out = append(out, "DELETE: this removes data and cannot be undone through the API")
	}
	for _, h := range highImpact {
		if (h.method == "" || h.method == method) && strings.HasPrefix(path, h.prefix) {
			out = append(out, h.note)
			if h.method != "" {
				break
			}
		}
	}
	return out
}

// ConfirmToken binds a confirmation to one exact request on one Fleet
// Manager.
func ConfirmToken(host, tool string, parts ...any) string {
	h := sha256.New()
	b, _ := json.Marshal(append([]any{host, tool}, parts...))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func sortedQuery(q map[string]string) string {
	v := url.Values{}
	for k, val := range q {
		v.Set(k, val)
	}
	return v.Encode() // Encode sorts by key
}

func registerWrite(s *mcp.Server, d *Deps) {
	t := true
	f := false
	writeAnn := func(title string) *mcp.ToolAnnotations {
		return &mcp.ToolAnnotations{Title: title, DestructiveHint: &t, OpenWorldHint: &f}
	}

	type apiWriteArgs struct {
		Method       string            `json:"method" jsonschema:"POST, PUT, PATCH or DELETE"`
		Path         string            `json:"path" jsonschema:"REST path starting with /, path parameters filled in"`
		Query        map[string]string `json:"query,omitempty" jsonschema:"query string parameters"`
		Body         any               `json:"body,omitempty" jsonschema:"JSON request body"`
		ConfirmToken string            `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this request's preview; when it matches, the change is executed"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_api_write",
		Description: "Change Fleet Manager through the REST API (POST, PUT, PATCH, DELETE with a JSON body). " +
			"Two steps: call without confirm_token to get a preview (request, matching spec operation, impact warnings, and for PUT/PATCH a diff against the current object) and a confirm_token; " +
			"show the preview to the user, and only after they approve, call again with the identical request plus confirm_token to execute. " +
			"Any change to the request needs a new preview. Executed changes are written to the audit log. File uploads (multipart) are not supported here.",
		Annotations: writeAnn("REST write"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a apiWriteArgs) (*mcp.CallToolResult, any, error) {
		method := strings.ToUpper(strings.TrimSpace(a.Method))
		if err := CheckWritePath(method, a.Path); err != nil {
			return nil, nil, err
		}
		var body []byte
		if a.Body != nil {
			var err error
			if body, err = json.Marshal(a.Body); err != nil {
				return nil, nil, fmt.Errorf("body: %w", err)
			}
		}
		q := sortedQuery(a.Query)
		token := ConfirmToken(d.Client.Host(), "fm_api_write", method, a.Path, q, a.Body)

		if a.ConfirmToken == "" {
			return d.previewREST(ctx, method, a.Path, a.Query, a.Body, token)
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match this request; the request changed since the preview (or the token is from another request). Preview again")
		}

		qv, _ := url.ParseQuery(q)
		resp, err := d.Client.Do(ctx, method, a.Path, qv, body, "application/json")
		rec := audit.Record{Fleet: d.Client.Host(), User: d.User, Tool: "fm_api_write", Method: method, Path: a.Path, Query: q,
			Body: redact.Value(a.Body), Token: token}
		if resp != nil {
			rec.Status = resp.Status
			rec.Response = excerptRedacted(resp.Body)
		}
		if err != nil {
			rec.Error = err.Error()
		}
		auditErr := d.Audit.Write(rec)
		if err != nil {
			return nil, nil, err
		}
		out := map[string]any{"executed": true, "status": resp.Status}
		if v, derr := decode(resp.Body); derr == nil && v != nil {
			out["response"] = v
		} else if len(resp.Body) > 0 {
			out["response"] = excerptRedacted(resp.Body)
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			out["location"] = loc
		}
		var notes []string
		if auditErr != nil {
			notes = append(notes, "WARNING: the change was made but the audit log write failed: "+auditErr.Error())
		}
		r, err := jsonResult(out, notes...)
		return r, nil, err
	})

	type gqlMutateArgs struct {
		Query        string         `json:"query" jsonschema:"GraphQL document containing one or more mutations"`
		Variables    map[string]any `json:"variables,omitempty" jsonschema:"GraphQL variables"`
		ConfirmToken string         `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this mutation's preview; when it matches, the mutation is executed"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_graphql_mutate",
		Description: "Run a GraphQL mutation against Fleet Manager (content resources, YARA, connectors, staged sensors). " +
			"Two steps: call without confirm_token for a preview listing each mutation field and its arguments plus a confirm_token; " +
			"after the user approves, call again with the identical query and variables plus confirm_token. Executed mutations are written to the audit log.",
		Annotations: writeAnn("GraphQL mutation"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a gqlMutateArgs) (*mcp.CallToolResult, any, error) {
		fields, err := mutationFields(a.Query)
		if err != nil {
			return nil, nil, err
		}
		token := ConfirmToken(d.Client.Host(), "fm_graphql_mutate", a.Query, a.Variables)
		if a.ConfirmToken == "" {
			var warnings []string
			for _, fld := range fields {
				if strings.HasPrefix(strings.ToLower(fld), "delete") {
					warnings = append(warnings, fld+" deletes data")
				}
			}
			r, err := jsonResult(map[string]any{
				"preview":       true,
				"mutations":     fields,
				"variables":     redact.Value(anyMap(a.Variables)),
				"warnings":      warnings,
				"confirm_token": token,
				"next":          "Show this preview to the user. After they approve, call fm_graphql_mutate again with the same query and variables plus confirm_token.",
			})
			return r, nil, err
		}
		if a.ConfirmToken != token {
			return nil, nil, errors.New("confirm_token does not match this mutation; preview again")
		}
		resp, err := d.Client.GraphQL(ctx, a.Query, a.Variables)
		rec := audit.Record{Fleet: d.Client.Host(), User: d.User, Tool: "fm_graphql_mutate", Path: "/graph/query",
			Body: map[string]any{"query": a.Query, "variables": redact.Value(anyMap(a.Variables))}, Token: token}
		if resp != nil {
			rec.Status = resp.Status
			rec.Response = excerptRedacted(resp.Body)
		}
		if err != nil {
			rec.Error = err.Error()
		}
		auditErr := d.Audit.Write(rec)
		if err != nil {
			return nil, nil, err
		}
		v, err := decode(resp.Body)
		if err != nil {
			return nil, nil, err
		}
		notes := []string{}
		if m, ok := v.(map[string]any); ok {
			if errs, ok := m["errors"].([]any); ok && len(errs) > 0 {
				b, _ := json.Marshal(errs)
				notes = append(notes, "GraphQL errors: "+string(b))
			}
		}
		if auditErr != nil {
			notes = append(notes, "WARNING: the mutation ran but the audit log write failed: "+auditErr.Error())
		}
		r, err := jsonResult(map[string]any{"executed": true, "result": v}, notes...)
		return r, nil, err
	})
}

func anyMap(m map[string]any) any {
	if m == nil {
		return nil
	}
	return m
}

// mutationFields parses doc and returns the root fields of its mutations.
// The document must contain at least one mutation and no subscriptions.
func mutationFields(doc string) ([]string, error) {
	q, err := parser.ParseQuery(&ast.Source{Input: doc})
	if err != nil {
		return nil, fmt.Errorf("invalid GraphQL: %w", err)
	}
	var fields []string
	for _, op := range q.Operations {
		switch op.Operation {
		case ast.Subscription:
			return nil, errors.New("subscriptions are not supported")
		case ast.Mutation:
			for _, sel := range op.SelectionSet {
				if f, ok := sel.(*ast.Field); ok {
					fields = append(fields, f.Name)
				}
			}
		}
	}
	if len(fields) == 0 {
		return nil, errors.New("no mutation found; use fm_graphql_query for queries")
	}
	return fields, nil
}

// previewREST builds the preview for fm_api_write.
func (d *Deps) previewREST(ctx context.Context, method, path string, query map[string]string, body any, token string) (*mcp.CallToolResult, any, error) {
	out := map[string]any{
		"preview": true,
		"request": map[string]any{"method": method, "path": path, "query": query, "body": redact.Value(body)},
	}
	warnings := impactNotes(method, path)
	if idx, _, _ := d.Specs.REST(ctx); idx != nil {
		if op := idx.Match(method, path); op != nil {
			out["operation"] = map[string]any{"path": op.Path, "summary": op.Summary, "params": op.Params}
		} else {
			warnings = append(warnings, fmt.Sprintf("%s %s is not in the REST spec (methods for this path: %v)", method, path, idx.PathKnown(path)))
		}
	}
	if method == http.MethodPut || method == http.MethodPatch {
		if diff, note := d.diffAgainstCurrent(ctx, path, body); diff != nil || note != "" {
			if diff != nil {
				out["diff"] = diff
			}
			if note != "" {
				out["diff_note"] = note
			}
		}
	}
	if len(warnings) > 0 {
		out["warnings"] = warnings
	}
	out["confirm_token"] = token
	out["next"] = "Show this preview to the user. After they approve, call fm_api_write again with the identical method, path, query and body plus confirm_token."
	r, err := jsonResult(out)
	return r, nil, err
}

// diffAgainstCurrent GETs path and compares the keys present in body with
// their current values.
func (d *Deps) diffAgainstCurrent(ctx context.Context, path string, body any) (any, string) {
	resp, err := d.Client.GetCapped(ctx, path, nil, apiGetLimit)
	if err != nil || resp.Truncated || !resp.IsJSON() {
		return nil, "no diff: the current object could not be read with GET " + path
	}
	var cur any
	if err := json.Unmarshal(resp.Body, &cur); err != nil {
		return nil, "no diff: current object is not JSON"
	}
	bm, bok := body.(map[string]any)
	cm, cok := cur.(map[string]any)
	if !bok || !cok {
		changes, trunc := jsonview.Diff(redact.Value(cur), redact.Value(body), diffLimit)
		return changes, truncNote(trunc)
	}
	subset := map[string]any{}
	var omitted []string
	for k := range cm {
		if _, ok := bm[k]; ok {
			subset[k] = cm[k]
		} else {
			omitted = append(omitted, k)
		}
	}
	changes, trunc := jsonview.Diff(redact.Value(subset), redact.Value(bm), diffLimit)
	note := truncNote(trunc)
	if len(omitted) > 0 {
		sort.Strings(omitted)
		if len(omitted) > 30 {
			omitted = append(omitted[:30], "…")
		}
		note = strings.TrimSpace(note + fmt.Sprintf(" The body omits %d current top-level keys (%s); a PUT may reset them, a PATCH leaves them unchanged.", len(omitted), strings.Join(omitted, ", ")))
	}
	if len(changes) == 0 {
		note = strings.TrimSpace("No differences in the keys this body sets. " + note)
	}
	return changes, note
}

func truncNote(t bool) string {
	if t {
		return fmt.Sprintf("Diff shows the first %d differences only.", diffLimit)
	}
	return ""
}

func excerptRedacted(b []byte) string {
	var v any
	if json.Unmarshal(b, &v) == nil {
		out, _ := json.Marshal(redact.Value(v))
		b = out
	} else {
		b = []byte(redact.String(string(b)))
	}
	const n = 1000
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}
