package tools_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleets"
	"github.com/jlagermann/fleet-mcp/internal/fleettest"
	"github.com/jlagermann/fleet-mcp/internal/guides"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
	"github.com/jlagermann/fleet-mcp/internal/tools"
)

// Claude Code cuts server instructions at 4096 bytes; keep a margin for
// the full binary path. It passed a 2.5 KB tool description whole, so the
// tool limit is only a budget that keeps descriptions compact.
const (
	maxInstructions    = 3500
	maxToolDescription = 4096
)

func TestInstructionsFitAndKeepTheRules(t *testing.T) {
	for _, writes := range []bool{true, false} {
		s := tools.Instructions(writes)
		if len(s) > maxInstructions {
			t.Errorf("writes=%v: instructions are %d bytes, over %d; move workflow detail into a guide", writes, len(s), maxInstructions)
		}
		for _, want := range append([]string{"Never ask for passwords", "fm_guide", "read_only"}, guides.Names()...) {
			if !strings.Contains(s, want) {
				t.Errorf("writes=%v: instructions lack %q", writes, want)
			}
		}
		if writes != strings.Contains(s, "confirm_token") {
			t.Errorf("writes=%v: approval rule present = %v", writes, !writes)
		}
	}
	// The approval rule comes before anything a client could cut.
	if s := tools.Instructions(true); strings.Index(s, "confirm_token") > 600 {
		t.Error("the approval rule should be near the top")
	}
}

// fullSession registers every tool, with writes, secrets and packages on.
func fullSession(t *testing.T) *mcp.ClientSession {
	t.Helper()
	store, err := secrets.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log, _ := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	deps := &tools.Deps{Fleets: fleets.NewStatic(conn(t, "lab", fleettest.New(t), false)), EnableWrites: true,
		Audit: log, Secrets: store, PackagesDir: t.TempDir()}
	s := mcp.NewServer(&mcp.Implementation{Name: "fleet-mcp", Version: "test"}, &mcp.ServerOptions{Instructions: tools.Instructions(true)})
	tools.Register(s, deps)
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := s.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func TestToolDescriptionsFit(t *testing.T) {
	cs := fullSession(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) < 35 {
		t.Errorf("only %d tools registered", len(res.Tools))
	}
	for _, tl := range res.Tools {
		if n := len(tl.Description); n > maxToolDescription {
			t.Errorf("%s: description is %d bytes, over %d", tl.Name, n, maxToolDescription)
		}
	}
}

func TestGuideToolAndPrompts(t *testing.T) {
	cs := fullSession(t)
	out, isErr := call(t, cs, "fm_guide", nil)
	if isErr || !strings.Contains(out, `"name":"install-fleet-manager"`) || !strings.Contains(out, `"when":"before fm_policy_create"`) {
		t.Fatalf("list: %s", out)
	}
	out, isErr = call(t, cs, "fm_guide", map[string]any{"topic": "install-fleet-manager"})
	if isErr || !strings.HasPrefix(out, "# Install Fleet Manager") || !strings.Contains(out, "secret set repo-token") {
		t.Fatalf("guide: %s", out)
	}
	if out, isErr = call(t, cs, "fm_guide", map[string]any{"topic": "nope"}); !isErr || !strings.Contains(out, "move-sensor") {
		t.Fatalf("unknown topic: %v %s", isErr, out)
	}

	ctx := context.Background()
	pl, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Prompts) != len(guides.Names()) {
		t.Fatalf("%d prompts for %d guides", len(pl.Prompts), len(guides.Names()))
	}
	p, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: "troubleshoot-sensor", Arguments: map[string]string{"request": "Lab-Sensor3 is red"}})
	if err != nil {
		t.Fatal(err)
	}
	text := p.Messages[0].Content.(*mcp.TextContent).Text
	if !strings.Contains(text, "fm_sensor_diagnose") || !strings.HasSuffix(text, "My request: Lab-Sensor3 is red\n") {
		t.Fatalf("prompt: %s", text)
	}
}
