package content

import "testing"

func TestSnippetVars(t *testing.T) {
	y := "%YAML 1.1\n---\nvars:\n  \"address-groups\":\n    SCANNERS: \"[192.0.2.1,198.51.100.0/24]\"\n    \"DMZ\": '[203.0.113.0/24]' # dmz\n  port-groups:\n    WEB_PORTS: 8080 # comment\n  # comment\nother:\n  SCANNERS: nope\n"
	got := snippetVars(y)
	want := map[string]string{"address-groups.SCANNERS": "[192.0.2.1,198.51.100.0/24]", "address-groups.DMZ": "[203.0.113.0/24]", "port-groups.WEB_PORTS": "8080"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}
