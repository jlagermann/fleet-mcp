package metrics

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestFooter(t *testing.T) {
	ctx, rec := With(context.Background())
	done := Step(ctx, "SSH step %d", 1)
	time.Sleep(5 * time.Millisecond)
	done()
	API(ctx, 20*time.Millisecond)
	API(ctx, 30*time.Millisecond)
	f := rec.Footer("fm_test", 400)
	for _, want := range []string{"fm_test took", "about 100 tokens", "2 calls, 50ms", "SSH step 1"} {
		if !strings.Contains(f, want) {
			t.Errorf("footer lacks %q:\n%s", want, f)
		}
	}
	// No recorder: no-ops.
	Step(context.Background(), "x")()
	API(context.Background(), time.Second)
}
