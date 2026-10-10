package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// reportCmd summarizes the fleet-mcp tool calls of a Claude Code session
// transcript (~/.claude/projects/<project>/<session>.jsonl): per call its
// duration, the model tokens of the turn that made it, and the size of its
// result; with -timeline also the server's demo-metrics timeline.
func reportCmd(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	since := fs.String("since", "", "only calls at or after this time (RFC 3339, e.g. 2026-10-10T15:00:00Z)")
	prefix := fs.String("prefix", "mcp__fleet-mcp__", "tool name prefix to report")
	timeline := fs.Bool("timeline", false, "print each call's demo-metrics timeline (FLEET_MCP_DEMO_METRICS)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: fleet-mcp report [-since time] [-timeline] <session.jsonl>")
	}
	var from time.Time
	if *since != "" {
		t, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("-since: %w", err)
		}
		from = t
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	calls, err := readCalls(f, *prefix)
	if err != nil {
		return err
	}
	var kept []*toolCall
	for _, c := range calls {
		if c.At.Before(from) {
			continue
		}
		kept = append(kept, c)
	}
	printReport(os.Stdout, kept, *prefix, *timeline)
	return nil
}

type tokenUsage struct {
	Input       int `json:"input_tokens"`
	CacheCreate int `json:"cache_creation_input_tokens"`
	CacheRead   int `json:"cache_read_input_tokens"`
	Output      int `json:"output_tokens"`
}

type toolCall struct {
	ID       string
	Name     string
	Input    string
	At, Done time.Time
	Usage    tokenUsage
	// Calls is how many tool calls the model made in the same turn; the
	// turn's tokens are shared between them.
	Calls       int
	ResultBytes int
	IsError     bool
	Footer      string
}

// transcript line, the parts the report needs.
type line struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Message   struct {
		ID      string          `json:"id"`
		Usage   *tokenUsage     `json:"usage"`
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

type block struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
}

const footerMark = "--- fleet-mcp demo metrics ---"

func readCalls(r io.Reader, prefix string) ([]*toolCall, error) {
	byID := map[string]*toolCall{}
	perMessage := map[string][]*toolCall{}
	var order []*toolCall
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var l line
		if json.Unmarshal(sc.Bytes(), &l) != nil {
			continue
		}
		var blocks []block
		if json.Unmarshal(l.Message.Content, &blocks) != nil {
			continue
		}
		for _, b := range blocks {
			switch {
			case l.Type == "assistant" && b.Type == "tool_use" && strings.HasPrefix(b.Name, prefix):
				c := &toolCall{ID: b.ID, Name: strings.TrimPrefix(b.Name, prefix), Input: shortInput(b.Input), At: l.Timestamp}
				if l.Message.Usage != nil {
					c.Usage = *l.Message.Usage
				}
				byID[c.ID] = c
				order = append(order, c)
				perMessage[l.Message.ID] = append(perMessage[l.Message.ID], c)
			case l.Type == "user" && b.Type == "tool_result":
				c := byID[b.ToolUseID]
				if c == nil {
					continue
				}
				c.Done, c.IsError = l.Timestamp, b.IsError
				text := resultText(b.Content)
				if i := strings.Index(text, footerMark); i >= 0 {
					c.Footer = strings.TrimSpace(text[i+len(footerMark):])
					text = text[:i]
				}
				c.ResultBytes = len(text)
			}
		}
	}
	for _, cs := range perMessage {
		for _, c := range cs {
			c.Calls = len(cs)
		}
	}
	return order, sc.Err()
}

// resultText flattens a tool_result's content (a string or text blocks).
func resultText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	_ = json.Unmarshal(raw, &parts)
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p.Text)
	}
	return b.String()
}

// shortInput shows a call's arguments without long values or tokens.
func shortInput(raw json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		v := fmt.Sprint(m[k])
		if k == "confirm_token" {
			v = "…"
		}
		if len(v) > 40 {
			v = v[:37] + "..."
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

func printReport(w io.Writer, calls []*toolCall, prefix string, timeline bool) {
	if len(calls) == 0 {
		fmt.Fprintf(w, "No %s* tool calls in this transcript.\n", prefix)
		return
	}
	fmt.Fprintln(w, "| # | Time (UTC) | Tool | Wall time | Model output | Model input (fresh / cache write / cache read) | Result |")
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|")
	var tot tokenUsage
	var totDur time.Duration
	var totResult int
	for i, c := range calls {
		dur := "?"
		if !c.Done.IsZero() {
			d := c.Done.Sub(c.At)
			totDur += d
			dur = d.Round(100 * time.Millisecond).String()
		}
		shared := ""
		if c.Calls > 1 {
			shared = fmt.Sprintf(" (turn shared by %d calls)", c.Calls)
		}
		name := c.Name
		if c.IsError {
			name += " (error)"
		}
		fmt.Fprintf(w, "| %d | %s | %s %s | %s | %d%s | %d / %d / %d | ≈%d tokens |\n",
			i+1, c.At.UTC().Format("15:04:05"), name, c.Input, dur,
			c.Usage.Output, shared, c.Usage.Input, c.Usage.CacheCreate, c.Usage.CacheRead, (c.ResultBytes+3)/4)
		tot.Output += c.Usage.Output
		tot.Input += c.Usage.Input
		tot.CacheCreate += c.Usage.CacheCreate
		tot.CacheRead += c.Usage.CacheRead
		totResult += (c.ResultBytes + 3) / 4
	}
	fmt.Fprintf(w, "\n%d calls, %s in tools. Model tokens of the turns that made them: %d output; input %d fresh, %d cache write, %d cache read. Results added ≈%d tokens of context.\n",
		len(calls), totDur.Round(time.Second), tot.Output, tot.Input, tot.CacheCreate, tot.CacheRead, totResult)
	fmt.Fprintln(w, "Wall time runs from the call to its result, so it includes any time spent on a permission prompt; with FLEET_MCP_DEMO_METRICS the -timeline footer shows the tool's own time.")
	fmt.Fprintln(w, "Model input is the whole conversation context the model read for that turn (mostly cache reads, which are billed at a fraction of fresh input).")
	if !timeline {
		return
	}
	for i, c := range calls {
		if c.Footer != "" {
			fmt.Fprintf(w, "\n#%d %s\n%s\n", i+1, c.Name, c.Footer)
		}
	}
}
