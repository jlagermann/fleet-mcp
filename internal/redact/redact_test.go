package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValue(t *testing.T) {
	in := map[string]any{
		"name": "sensor1",
		"extendedinformation.status": map[string]any{
			"doc-password": "abc-123",
			"doc-username": "admin",
			"os.version":   "29.2.2",
		},
		"tethering_token":     "eyJhbGciOi",
		"empty_token":         "",
		"has-token":           true,
		"token_count":         float64(3),
		"client_secret":       map[string]any{"v": "x"},
		"permission_actions":  "list_secrets,revoke_tokens",
		"sources":             []any{map[string]any{"url": "https://rules.emergingthreatspro.com/1234567890abcdef/suricata-7.0.3/etpro.rules.tar.gz"}},
		"Authorization":       "Bearer x",
		"key":                 "abc",
		"monkey":              "fine",
		"private_key":         "-----BEGIN",
		"api-key":             "k",
		"suricata-yaml-file-id": float64(73093),
		"headers":             `{"Authorization":["Bearer etpro-secret"]}`,
		"etpro":               "https://ppp.rules.corelight.io/CodeXYZ123/suricata-7.0.3/etpro.rules.tar.gz",
	}
	out := Value(in).(map[string]any)
	b, _ := json.Marshal(out)
	s := string(b)
	for _, leaked := range []string{"abc-123", "eyJhbGciOi", `"x"`, "1234567890abcdef", "Bearer x", `"abc"`, "BEGIN", `"k"`, "etpro-secret", "CodeXYZ123"} {
		if strings.Contains(s, leaked) {
			t.Errorf("leaked %s in %s", leaked, s)
		}
	}
	for _, kept := range []string{"sensor1", "29.2.2", `"doc-username":"admin"`, `"has-token":true`, `"token_count":3`, `"empty_token":""`, "list_secrets,revoke_tokens", `"monkey":"fine"`, "73093", "suricata-7.0.3/etpro.rules.tar.gz"} {
		if !strings.Contains(s, kept) {
			t.Errorf("lost %s in %s", kept, s)
		}
	}
	if in["tethering_token"] != "eyJhbGciOi" {
		t.Error("input was modified")
	}
}

func TestValueExtraKeys(t *testing.T) {
	out := Value(map[string]any{"name": "a", "value": "hunter2"}, "value").(map[string]any)
	if out["value"] != Mask || out["name"] != "a" {
		t.Fatalf("got %v", out)
	}
}

func TestString(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":                                     "plain text",
		"https://feed.corelight.com/corelight.rules":     "https://feed.corelight.com/corelight.rules",
		"see https://user:pw@host.example/x for details": "see https://" + Mask + "@host.example/x for details",
		"https://example.com/rules?oinkcode=abc&v=2":     "https://example.com/rules?oinkcode=" + Mask + "&v=2",
		"https://rules.emergingthreatspro.com/abc123/suricata/etpro.rules.tar.gz": "https://rules.emergingthreatspro.com/" + Mask + "/suricata/etpro.rules.tar.gz",
		"https://ppp.rules.corelight.io/Abc123XYZ/suricata-7.0.3/etpro.rules.tar.gz": "https://ppp.rules.corelight.io/" + Mask + "/suricata-7.0.3/etpro.rules.tar.gz",
	} {
		if got := String(in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
}
