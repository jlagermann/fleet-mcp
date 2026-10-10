package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
)

// API is the part of *fleet.Client that migrate uses.
type API interface {
	Do(ctx context.Context, method, path string, query url.Values, body []byte, contentType string) (*fleet.Response, error)
	GetJSON(ctx context.Context, path string, query url.Values, out any) error
	GraphQL(ctx context.Context, query string, variables map[string]any) (*fleet.Response, error)
	GraphQLUpload(ctx context.Context, query string, variables map[string]any, filePath, fileName string, content []byte) (*fleet.Response, error)
	DoMultipart(ctx context.Context, method, path string, fields map[string]string, files ...fleet.FilePart) (*fleet.Response, error)
	Download(ctx context.Context, path string, w io.Writer, limit int64) (int64, error)
}

var _ API = (*fleet.Client)(nil)

// Fleet Manager endpoints.
const (
	pathInfo           = "/fleet/v1/info"
	pathPolicyList     = "/fleet/v1/sensor/policy/list"
	pathPolicy         = "/fleet/v1/sensor/policy"
	pathPolicyMetadata = "/fleet/v1/sensor/policy/metadata"
	pathBundle         = "/fleet/v1/sensor/bundle"
	pathSuricata       = "/fleet/v1/suricata"
	pathSuricataList   = "/fleet/v1/suricata/policies"
	pathSuricataMeta   = "/fleet/v1/suricata/metadata"
	pathSuricataDefs   = "/fleet/v1/suricata/defaults"
	pathCatalog        = "/fleet/v1/sensor/catalog"
	pathFiles          = "/fleet/v1/filemgr/files/"
	pathStores         = "/fleet/v1/filemgr/stores/"
)

// gqlError is a GraphQL error response.
type gqlError struct{ msgs []string }

func (e *gqlError) Error() string { return "GraphQL: " + strings.Join(e.msgs, "; ") }

// decodeGraphQL decodes a GraphQL response's data into out, failing on
// any GraphQL error.
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

// jsonBody marshals v for a REST request.
func jsonBody(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// idOf reads a numeric or string ID.
func idOf(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case json.Number:
		n, _ := t.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(t, 10, 64)
		return n
	}
	return 0
}

// truthy interprets Fleet Manager boolean settings, which arrive as JSON
// booleans, "true"/"1" strings or numbers.
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(t))
		return err == nil && b
	case float64:
		return t != 0
	}
	return false
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// majorMinor returns "29.2" for "29.2.2-16847904621".
func majorMinor(version string) (string, error) {
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return "", fmt.Errorf("cannot read version %q", version)
	}
	for _, p := range parts[:2] {
		if _, err := strconv.Atoi(p); err != nil {
			return "", fmt.Errorf("cannot read version %q", version)
		}
	}
	return parts[0] + "." + parts[1], nil
}

func serverVersion(ctx context.Context, api API) (string, error) {
	var info struct {
		ServerVersion string `json:"server_version"`
	}
	if err := api.GetJSON(ctx, pathInfo, nil, &info); err != nil {
		return "", err
	}
	if info.ServerVersion == "" {
		return "", errors.New("no server_version in the Fleet Manager info")
	}
	return info.ServerVersion, nil
}

// listOf accepts a bare array or an object with a "list" array.
func listOf(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case map[string]any:
		if l, ok := t["list"].([]any); ok {
			return l
		}
	}
	return nil
}
