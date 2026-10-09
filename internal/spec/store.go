package spec

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
	"sync"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
)

const (
	restDocPath = "/fleet/v1/swagger/doc.json"
	infoPath    = "/fleet/v1/info"
)

// IntrospectionQuery is the standard GraphQL introspection query.
const IntrospectionQuery = `query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name }
  types { ...FullType } directives { name description locations args { ...InputValue } } } }
fragment FullType on __Type { kind name description
  fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason }
  inputFields { ...InputValue } interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } }
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }`

// Store loads schemas for the connected Fleet Manager once, on first use.
type Store struct {
	dir    string
	client *fleet.Client

	mu      sync.Mutex
	loaded  bool
	version string
	rest    *REST
	restSrc string
	restErr error
	gql     *GraphQL
	gqlSrc  string
	gqlErr  error
}

// NewStore returns a Store that reads from and caches into dir. dir may be
// empty, in which case only live downloads are tried and nothing is saved.
func NewStore(dir string, c *fleet.Client) *Store {
	return &Store{dir: dir, client: c}
}

// Status describes what the store found.
type Status struct {
	FleetVersion string `json:"fleet_version"`
	REST         string `json:"rest_spec"`
	GraphQL      string `json:"graphql_schema"`
}

// Status loads (if needed) and reports where each schema came from.
func (s *Store) Status(ctx context.Context) Status {
	s.load(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{FleetVersion: s.version, REST: s.restSrc, GraphQL: s.gqlSrc}
	if s.rest == nil {
		st.REST = "unavailable: " + errString(s.restErr)
	}
	if s.gql == nil {
		st.GraphQL = "unavailable: " + errString(s.gqlErr)
	}
	return st
}

// REST returns the REST index and where it came from.
func (s *Store) REST(ctx context.Context) (*REST, string, error) {
	s.load(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rest, s.restSrc, s.restErr
}

// GraphQL returns the GraphQL index and where it came from.
func (s *Store) GraphQL(ctx context.Context) (*GraphQL, string, error) {
	s.load(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gql, s.gqlSrc, s.gqlErr
}

// load runs once Fleet Manager has answered; until then each call retries,
// so a transient outage at startup is not cached.
func (s *Store) load(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded {
		return
	}
	version, err := Version(ctx, s.client)
	if err != nil {
		s.restErr = fmt.Errorf("cannot reach Fleet Manager: %w", err)
		s.gqlErr = s.restErr
		return
	}
	s.loaded = true
	s.version = version
	{

		if b, src, err := s.fromDir("rest"); err == nil {
			s.rest, s.restErr = ParseREST(b)
			s.restSrc = src
		} else if b, err := FetchREST(ctx, s.client); err == nil {
			s.rest, s.restErr = ParseREST(b)
			s.restSrc = "downloaded from Fleet Manager"
			s.save("rest", b)
		} else {
			s.restErr = err
		}

		if b, src, err := s.fromDir("graphql"); err == nil {
			s.gql, s.gqlErr = ParseGraphQL(b)
			s.gqlSrc = src
		} else if b, err := FetchGraphQL(ctx, s.client); err == nil {
			s.gql, s.gqlErr = ParseGraphQL(b)
			s.gqlSrc = "introspected from Fleet Manager"
			s.save("graphql", b)
		} else {
			s.gqlErr = err
		}
	}
}

// fromDir prefers <kind>-<version>.json, then the newest <kind>-*.json.
func (s *Store) fromDir(kind string) ([]byte, string, error) {
	if s.dir == "" {
		return nil, "", errors.New("no spec directory")
	}
	if s.version != "" {
		p := filepath.Join(s.dir, FileName(kind, s.version))
		if b, err := os.ReadFile(p); err == nil {
			return b, "file " + p, nil
		}
	}
	matches, _ := filepath.Glob(filepath.Join(s.dir, kind+"-*.json"))
	if len(matches) == 0 {
		return nil, "", fmt.Errorf("no %s spec in %s", kind, s.dir)
	}
	sort.Slice(matches, func(i, j int) bool {
		fi, _ := os.Stat(matches[i])
		fj, _ := os.Stat(matches[j])
		return fi != nil && fj != nil && fi.ModTime().After(fj.ModTime())
	})
	b, err := os.ReadFile(matches[0])
	if err != nil {
		return nil, "", err
	}
	src := "file " + matches[0]
	if s.version != "" {
		src += " (does not match Fleet Manager " + s.version + ")"
	}
	return b, src, nil
}

func (s *Store) save(kind string, b []byte) {
	if s.dir == "" || s.version == "" {
		return
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(s.dir, FileName(kind, s.version)), b, 0o600)
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// FileName is the cache file name for a schema kind and Fleet version.
func FileName(kind, version string) string {
	return kind + "-" + unsafeChars.ReplaceAllString(version, "_") + ".json"
}

// Version returns Fleet Manager's server_version.
func Version(ctx context.Context, c *fleet.Client) (string, error) {
	var info struct {
		ServerVersion string `json:"server_version"`
	}
	if err := c.GetJSON(ctx, infoPath, nil, &info); err != nil {
		return "", err
	}
	return info.ServerVersion, nil
}

// FetchREST downloads the Swagger document. It fails unless Fleet Manager
// has "expose-swagger": true.
func FetchREST(ctx context.Context, c *fleet.Client) ([]byte, error) {
	resp, err := c.Get(ctx, restDocPath, nil)
	if err != nil {
		var apiErr *fleet.APIError
		if errors.As(err, &apiErr) && (apiErr.Status == 404 || apiErr.Status == 403) {
			return nil, fmt.Errorf("this Fleet Manager does not expose its REST spec (HTTP %d); set \"expose-swagger\": true in /etc/corelight-fleetd.conf and restart corelight-fleetd, or put a saved spec in the spec directory", apiErr.Status)
		}
		return nil, err
	}
	return resp.Body, nil
}

// FetchGraphQL runs an introspection query.
func FetchGraphQL(ctx context.Context, c *fleet.Client) ([]byte, error) {
	resp, err := c.GraphQL(ctx, IntrospectionQuery, nil)
	if err != nil {
		return nil, err
	}
	var probe struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(resp.Body, &probe); err != nil {
		return nil, fmt.Errorf("GraphQL introspection: %w", err)
	}
	if len(probe.Errors) > 0 || len(probe.Data) == 0 || string(probe.Data) == "null" {
		msgs := make([]string, 0, len(probe.Errors))
		for _, e := range probe.Errors {
			msgs = append(msgs, e.Message)
		}
		return nil, fmt.Errorf("GraphQL introspection refused: %s", strings.Join(msgs, "; "))
	}
	return resp.Body, nil
}

// Pull downloads both schemas into dir and returns the files written.
func Pull(ctx context.Context, c *fleet.Client, dir string) ([]string, error) {
	version, err := Version(ctx, c)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var written []string
	var errs []error
	if b, err := FetchREST(ctx, c); err != nil {
		errs = append(errs, fmt.Errorf("REST: %w", err))
	} else {
		p := filepath.Join(dir, FileName("rest", version))
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return written, err
		}
		written = append(written, p)
	}
	if b, err := FetchGraphQL(ctx, c); err != nil {
		errs = append(errs, fmt.Errorf("GraphQL: %w", err))
	} else {
		p := filepath.Join(dir, FileName("graphql", version))
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return written, err
		}
		written = append(written, p)
	}
	return written, errors.Join(errs...)
}

func errString(err error) string {
	if err == nil {
		return "not loaded"
	}
	return err.Error()
}
