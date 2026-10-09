// Package spec indexes the Fleet Manager REST (Swagger 2.0) and GraphQL
// (introspection) schemas for search and request checking.
//
// The schemas are not shipped with fleet-mcp. They are loaded from a local
// directory, or downloaded from a Fleet Manager that exposes them
// ("expose-swagger": true in corelight-fleetd.conf; GraphQL introspection).
// Every caller must work without them.
package spec

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var methods = []string{"get", "put", "post", "delete", "patch", "head", "options"}

// Param is one REST operation parameter.
type Param struct {
	Name        string `json:"name"`
	In          string `json:"in"`
	Type        string `json:"type,omitempty"`
	Ref         string `json:"schema,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Description string `json:"description,omitempty"`
}

// Operation is one REST method on one path.
type Operation struct {
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Summary     string   `json:"summary,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Params      []Param  `json:"params,omitempty"`

	pattern *regexp.Regexp
}

// REST is an index of REST operations.
type REST struct {
	Ops []*Operation
}

// ParseREST indexes a Swagger 2.0 document.
func ParseREST(b []byte) (*REST, error) {
	var doc struct {
		Swagger string                                `json:"swagger"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("spec: parsing REST spec: %w", err)
	}
	if len(doc.Paths) == 0 {
		return nil, fmt.Errorf("spec: REST spec has no paths")
	}
	idx := &REST{}
	for path, item := range doc.Paths {
		for _, m := range methods {
			raw, ok := item[m]
			if !ok {
				continue
			}
			var op struct {
				Summary     string   `json:"summary"`
				Description string   `json:"description"`
				Tags        []string `json:"tags"`
				Parameters  []struct {
					Name        string `json:"name"`
					In          string `json:"in"`
					Type        string `json:"type"`
					Required    bool   `json:"required"`
					Description string `json:"description"`
					Schema      struct {
						Ref string `json:"$ref"`
					} `json:"schema"`
				} `json:"parameters"`
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				return nil, fmt.Errorf("spec: %s %s: %w", m, path, err)
			}
			o := &Operation{
				Method:      strings.ToUpper(m),
				Path:        path,
				Summary:     op.Summary,
				Description: op.Description,
				Tags:        op.Tags,
				pattern:     pathPattern(path),
			}
			for _, p := range op.Parameters {
				o.Params = append(o.Params, Param{
					Name: p.Name, In: p.In, Type: p.Type, Required: p.Required,
					Description: p.Description, Ref: strings.TrimPrefix(p.Schema.Ref, "#/definitions/"),
				})
			}
			idx.Ops = append(idx.Ops, o)
		}
	}
	sort.Slice(idx.Ops, func(i, j int) bool {
		if idx.Ops[i].Path != idx.Ops[j].Path {
			return idx.Ops[i].Path < idx.Ops[j].Path
		}
		return idx.Ops[i].Method < idx.Ops[j].Method
	})
	return idx, nil
}

var templateVar = regexp.MustCompile(`\\\{[^/]+?\\\}`)

func pathPattern(p string) *regexp.Regexp {
	return regexp.MustCompile("^" + templateVar.ReplaceAllString(regexp.QuoteMeta(p), `[^/]+`) + "/?$")
}

// Search returns operations whose method, path, summary, description or
// tags contain every whitespace-separated term (case-insensitive).
func (r *REST) Search(query string, limit int) []*Operation {
	terms := strings.Fields(strings.ToLower(query))
	out := []*Operation{}
	for _, o := range r.Ops {
		hay := strings.ToLower(strings.Join(append([]string{o.Method, o.Path, o.Summary, o.Description}, o.Tags...), " "))
		if containsAll(hay, terms) {
			out = append(out, o)
			if limit > 0 && len(out) == limit {
				break
			}
		}
	}
	return out
}

// Match finds the operation for a concrete request path, such as
// GET /fleet/v1/sensor/policy/17. Exact template matches win over
// parameterized ones.
func (r *REST) Match(method, path string) *Operation {
	method = strings.ToUpper(method)
	var best *Operation
	for _, o := range r.Ops {
		if o.Method != method || !o.pattern.MatchString(path) {
			continue
		}
		if best == nil || strings.Count(o.Path, "{") < strings.Count(best.Path, "{") {
			best = o
		}
	}
	return best
}

// PathKnown reports whether any method exists for path.
func (r *REST) PathKnown(path string) []string {
	var ms []string
	for _, o := range r.Ops {
		if o.pattern.MatchString(path) {
			ms = append(ms, o.Method)
		}
	}
	return ms
}

// Field is a GraphQL root field (a query or a mutation).
type Field struct {
	Kind        string   `json:"kind"` // "query" or "mutation"
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Args        []string `json:"args,omitempty"` // "name: Type"
	Returns     string   `json:"returns"`
}

// GraphQL is an index of GraphQL root fields and types.
type GraphQL struct {
	Fields []*Field
	Types  map[string]json.RawMessage
}

type typeRef struct {
	Kind   string   `json:"kind"`
	Name   string   `json:"name"`
	OfType *typeRef `json:"ofType"`
}

func (t *typeRef) String() string {
	if t == nil {
		return ""
	}
	switch t.Kind {
	case "NON_NULL":
		return t.OfType.String() + "!"
	case "LIST":
		return "[" + t.OfType.String() + "]"
	}
	return t.Name
}

// ParseGraphQL indexes an introspection result ({"data":{"__schema":...}}).
func ParseGraphQL(b []byte) (*GraphQL, error) {
	var doc struct {
		Data struct {
			Schema struct {
				QueryType    *struct{ Name string } `json:"queryType"`
				MutationType *struct{ Name string } `json:"mutationType"`
				Types        []json.RawMessage      `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("spec: parsing GraphQL schema: %w", err)
	}
	s := doc.Data.Schema
	if len(s.Types) == 0 {
		return nil, fmt.Errorf("spec: GraphQL schema has no types")
	}
	roots := map[string]string{}
	if s.QueryType != nil {
		roots[s.QueryType.Name] = "query"
	}
	if s.MutationType != nil {
		roots[s.MutationType.Name] = "mutation"
	}
	idx := &GraphQL{Types: map[string]json.RawMessage{}}
	for _, raw := range s.Types {
		var t struct {
			Name   string `json:"name"`
			Fields []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				Args        []struct {
					Name string   `json:"name"`
					Type *typeRef `json:"type"`
				} `json:"args"`
				Type *typeRef `json:"type"`
			} `json:"fields"`
		}
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("spec: GraphQL type: %w", err)
		}
		if strings.HasPrefix(t.Name, "__") {
			continue
		}
		idx.Types[t.Name] = raw
		kind, ok := roots[t.Name]
		if !ok {
			continue
		}
		for _, f := range t.Fields {
			fld := &Field{Kind: kind, Name: f.Name, Description: f.Description, Returns: f.Type.String()}
			for _, a := range f.Args {
				fld.Args = append(fld.Args, a.Name+": "+a.Type.String())
			}
			idx.Fields = append(idx.Fields, fld)
		}
	}
	sort.Slice(idx.Fields, func(i, j int) bool {
		if idx.Fields[i].Kind != idx.Fields[j].Kind {
			return idx.Fields[i].Kind < idx.Fields[j].Kind
		}
		return idx.Fields[i].Name < idx.Fields[j].Name
	})
	return idx, nil
}

// Search returns root fields matching every term.
func (g *GraphQL) Search(query string, limit int) []*Field {
	terms := strings.Fields(strings.ToLower(query))
	out := []*Field{}
	for _, f := range g.Fields {
		hay := strings.ToLower(f.Kind + " " + f.Name + " " + f.Description + " " + strings.Join(f.Args, " ") + " " + f.Returns)
		if containsAll(hay, terms) {
			out = append(out, f)
			if limit > 0 && len(out) == limit {
				break
			}
		}
	}
	return out
}

// TypeNames returns type names containing every term.
func (g *GraphQL) TypeNames(query string) []string {
	terms := strings.Fields(strings.ToLower(query))
	out := []string{}
	for name := range g.Types {
		if containsAll(strings.ToLower(name), terms) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func containsAll(hay string, terms []string) bool {
	for _, t := range terms {
		if !strings.Contains(hay, t) {
			return false
		}
	}
	return true
}
