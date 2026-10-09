// Package redact removes secrets from Fleet Manager API output before it is
// returned to an MCP client.
package redact

import (
	"net/url"
	"regexp"
	"strings"
)

// Mask replaces a redacted value.
const Mask = "[REDACTED]"

// sensitiveKey matches object keys whose values are secrets, for example
// a sensor's "doc-password" or "tethering_token".
var sensitiveKey = regexp.MustCompile(`(?i)(pass(word|wd|phrase)|secret|token|credential|private[-_.]?key|api[-_.]?key|access[-_.]?key|oinkcode|license[-_.]?key|passcode|(^|[-_.])otp($|[-_.])|recovery[-_.]?code|^key$|^cookie$|^authorization$|^headers$)`)

// sensitiveParam matches URL query parameter names that carry secrets.
var sensitiveParam = regexp.MustCompile(`(?i)(pass|secret|token|key|code|auth|sig|credential)`)

var urlPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

// licensedPathHosts are rule-feed hosts that put a license code in the
// first path segment, for example https://rules.emergingthreatspro.com/<code>/...
var licensedPathHosts = []string{"emergingthreatspro.com", "rules.corelight.io"}

// SensitiveKey reports whether an object key names a secret.
func SensitiveKey(k string) bool { return sensitiveKey.MatchString(k) }

// Value returns a copy of a decoded JSON value with secrets masked. Keys in
// extra are also treated as sensitive (compared case-insensitively).
func Value(v any, extra ...string) any {
	return walk(v, extra)
}

func walk(v any, extra []string) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if isSensitive(k, extra) && !harmless(val) {
				out[k] = Mask
				continue
			}
			out[k] = walk(val, extra)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = walk(val, extra)
		}
		return out
	case string:
		return String(t)
	default:
		return v
	}
}

func isSensitive(k string, extra []string) bool {
	if SensitiveKey(k) {
		return true
	}
	for _, e := range extra {
		if strings.EqualFold(k, e) {
			return true
		}
	}
	return false
}

// harmless values carry no secret even under a sensitive key: null,
// booleans (e.g. "has-token": true), numbers and empty strings.
func harmless(v any) bool {
	switch t := v.(type) {
	case nil, bool, float64, int, int64:
		return true
	case string:
		return t == ""
	}
	return false
}

// String masks credentials embedded in any URLs inside s.
func String(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	return urlPattern.ReplaceAllStringFunc(s, scrubURL)
}

func scrubURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	changed := false
	if u.User != nil {
		u.User = url.User(Mask)
		changed = true
	}
	if u.RawQuery != "" {
		q := u.Query()
		for k := range q {
			if sensitiveParam.MatchString(k) {
				q.Set(k, Mask)
				changed = true
			}
		}
		if changed {
			u.RawQuery = q.Encode()
		}
	}
	for _, h := range licensedPathHosts {
		if u.Hostname() == h || strings.HasSuffix(u.Hostname(), "."+h) {
			parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2)
			if len(parts) == 2 && parts[0] != "" && !strings.Contains(parts[0], ".") {
				u.Path = "/" + Mask + "/" + parts[1]
				changed = true
			}
		}
	}
	if !changed {
		return raw
	}
	// Keep the mask readable instead of percent-encoded.
	r := u.String()
	r = strings.ReplaceAll(r, url.QueryEscape(Mask), Mask)
	r = strings.ReplaceAll(r, url.PathEscape(Mask), Mask)
	return r
}
