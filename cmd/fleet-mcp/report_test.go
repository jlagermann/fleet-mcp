package main

import (
	"bytes"
	"strings"
	"testing"
)

const transcript = `{"type":"assistant","timestamp":"2026-10-10T15:00:00Z","message":{"id":"m1","usage":{"input_tokens":2,"cache_creation_input_tokens":100,"cache_read_input_tokens":5000,"output_tokens":150},"content":[{"type":"tool_use","id":"t1","name":"mcp__fleet-mcp__fm_info","input":{"fleet":"lab","confirm_token":"secret-ish"}}]}}
{"type":"user","timestamp":"2026-10-10T15:00:02.5Z","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"{\"ok\":true}"},{"type":"text","text":"--- fleet-mcp demo metrics ---\nfm_info took 2.4s."}]}]}}
{"type":"assistant","timestamp":"2026-10-10T15:01:00Z","message":{"id":"m2","usage":{"output_tokens":9},"content":[{"type":"tool_use","id":"t2","name":"Bash","input":{}}]}}
`

func TestReport(t *testing.T) {
	calls, err := readCalls(strings.NewReader(transcript), "mcp__fleet-mcp__")
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls %+v", calls)
	}
	c := calls[0]
	if c.Name != "fm_info" || c.Usage.Output != 150 || c.Usage.CacheRead != 5000 || c.ResultBytes != len(`{"ok":true}`) || !strings.Contains(c.Footer, "2.4s") {
		t.Fatalf("call %+v", c)
	}
	var b bytes.Buffer
	printReport(&b, calls, "mcp__fleet-mcp__", true)
	out := b.String()
	for _, want := range []string{"fm_info", "2.5s", "| 150 |", "2 / 100 / 5000", "fm_info took 2.4s"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "secret-ish") {
		t.Error("confirm_token shown")
	}
}
