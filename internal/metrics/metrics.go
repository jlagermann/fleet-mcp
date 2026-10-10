// Package metrics times what a tool call spends its time on, for demos:
// named phases (an SSH step, waiting for a sensor to apply a change) and
// Fleet Manager API calls. It is off unless FLEET_MCP_DEMO_METRICS is set;
// without a Recorder in the context every function is a no-op.
package metrics

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

type key struct{}

// Phase is one named span of a tool call.
type Phase struct {
	Label      string
	Start, End time.Duration // since the call started
}

// Recorder collects one tool call's phases.
type Recorder struct {
	start time.Time
	mu    sync.Mutex
	// phases in start order.
	phases []Phase
	// API calls to Fleet Manager: count and total time.
	apiCalls int
	apiTime  time.Duration
}

// With returns a context that records into a new Recorder.
func With(ctx context.Context) (context.Context, *Recorder) {
	r := &Recorder{start: time.Now()}
	return context.WithValue(ctx, key{}, r), r
}

func from(ctx context.Context) *Recorder {
	r, _ := ctx.Value(key{}).(*Recorder)
	return r
}

// Step starts a named phase; call the returned function when it ends.
func Step(ctx context.Context, format string, a ...any) func() {
	r := from(ctx)
	if r == nil {
		return func() {}
	}
	label := fmt.Sprintf(format, a...)
	begin := time.Since(r.start)
	return func() {
		end := time.Since(r.start)
		r.mu.Lock()
		r.phases = append(r.phases, Phase{Label: label, Start: begin, End: end})
		r.mu.Unlock()
	}
}

// API records one Fleet Manager API call.
func API(ctx context.Context, d time.Duration) {
	if r := from(ctx); r != nil {
		r.mu.Lock()
		r.apiCalls++
		r.apiTime += d
		r.mu.Unlock()
	}
}

// Footer describes the call for a demo: total time, an estimate of the
// tokens the result adds to the AI's context, and the timeline.
func (r *Recorder) Footer(tool string, resultBytes int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := time.Since(r.start)
	var b strings.Builder
	fmt.Fprintf(&b, "--- fleet-mcp demo metrics ---\n%s took %s. Its result is about %d tokens of AI context (%d bytes).\n",
		tool, round(total), (resultBytes+3)/4, resultBytes)
	if r.apiCalls > 0 {
		fmt.Fprintf(&b, "Fleet Manager API: %d calls, %s in total.\n", r.apiCalls, round(r.apiTime))
	}
	if len(r.phases) > 0 {
		sorted := append([]Phase(nil), r.phases...)
		for i := 1; i < len(sorted); i++ {
			for j := i; j > 0 && sorted[j].Start < sorted[j-1].Start; j-- {
				sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
			}
		}
		b.WriteString("Timeline:\n")
		for _, p := range sorted {
			fmt.Fprintf(&b, "  %7s - %7s  %s (%s)\n", round(p.Start), round(p.End), p.Label, round(p.End-p.Start))
		}
	}
	return b.String()
}

func round(d time.Duration) string {
	switch {
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	case d < time.Minute:
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}
