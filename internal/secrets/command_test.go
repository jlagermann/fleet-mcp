package secrets

import (
	"runtime"
	"testing"
)

func TestCommand(t *testing.T) {
	// A test binary is not fleet-mcp, so the bare name is used.
	got := Command("secret", "set-setting", "exporter:Splunk HEC:hec_token")
	want := "fleet-mcp secret set-setting 'exporter:Splunk HEC:hec_token'"
	if runtime.GOOS == "windows" {
		want = `fleet-mcp secret set-setting "exporter:Splunk HEC:hec_token"`
	}
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
