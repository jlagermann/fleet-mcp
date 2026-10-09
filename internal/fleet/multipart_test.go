package fleet_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/fleettest"
)

func TestDoMultipart(t *testing.T) {
	fm := fleettest.New(t)
	fm.Route("PUT /fleet/v1/sensor/bundle", map[string]any{"id": 7})
	c := newClient(t, fm)
	resp, err := c.DoMultipart(context.Background(), http.MethodPut, "/fleet/v1/sensor/bundle",
		map[string]string{"name": "b1"}, fleet.FilePart{Field: "file", FileName: "b1.bundle", Content: []byte("BUNDLE-BYTES")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp.Body), `"id":7`) {
		t.Fatalf("body %s", resp.Body)
	}
	log := fm.BodyLog()
	if len(log) != 1 {
		t.Fatalf("bodies %v", log)
	}
	for _, want := range []string{`name="name"`, "b1", `name="file"; filename="b1.bundle"`, "BUNDLE-BYTES"} {
		if !strings.Contains(log[0], want) {
			t.Errorf("multipart body lacks %q:\n%s", want, log[0])
		}
	}
}
