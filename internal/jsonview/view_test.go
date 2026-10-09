package jsonview

import (
	"encoding/json"
	"strings"
	"testing"
)

func doc(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestGet(t *testing.T) {
	v := doc(t, `{"list":[{"name":"a","health.status":"ok","x/y":1,"st":{"os.version":"29"}}]}`)
	for ptr, want := range map[string]string{
		"/list/0/name":          `"a"`,
		"list/0/health.status":  `"ok"`,
		"/list/0/x~1y":          `1`,
		"/list/0/st/os.version": `"29"`,
		"":                      `{"list":[{"health.status":"ok","name":"a","st":{"os.version":"29"},"x/y":1}]}`,
	} {
		got, err := Get(v, ptr)
		if err != nil {
			t.Fatalf("Get(%q): %v", ptr, err)
		}
		b, _ := json.Marshal(got)
		if string(b) != want {
			t.Errorf("Get(%q) = %s, want %s", ptr, b, want)
		}
	}
	for _, bad := range []string{"/nope", "/list/5", "/list/x", "/list/0/name/deeper"} {
		if _, err := Get(v, bad); err == nil {
			t.Errorf("Get(%q) succeeded", bad)
		}
	}
}

func TestViewPagingAndFields(t *testing.T) {
	v := doc(t, `{"list":[{"n":0,"k":"a"},{"n":1,"k":"b"},{"n":2,"k":"c"},{"n":3,"k":"d"}]}`)
	res, err := View(v, Options{Select: "/list", Fields: []string{"k"}, Offset: 1, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.JSON) != `[{"k":"b"},{"k":"c"}]` {
		t.Fatalf("got %s", res.JSON)
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "1-2 of 4") {
		t.Fatalf("notes = %v", res.Notes)
	}
}

func TestViewMaxBytesArray(t *testing.T) {
	var items []any
	for i := 0; i < 100; i++ {
		items = append(items, map[string]any{"i": float64(i), "pad": strings.Repeat("x", 50)})
	}
	res, err := View(items, Options{MaxBytes: 500})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.JSON) > 500 {
		t.Fatalf("len = %d", len(res.JSON))
	}
	var back []any
	if err := json.Unmarshal(res.JSON, &back); err != nil {
		t.Fatalf("capped array is not valid JSON: %v", err)
	}
	if len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "of 100 items") {
		t.Fatalf("notes = %v", res.Notes)
	}
}

func TestViewMaxBytesObject(t *testing.T) {
	res, err := View(map[string]any{"a": strings.Repeat("y", 1000)}, Options{MaxBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.JSON) != 100 || len(res.Notes) == 0 {
		t.Fatalf("len=%d notes=%v", len(res.JSON), res.Notes)
	}
}

func TestProjectNested(t *testing.T) {
	v := doc(t, `{"name":"s1","extendedinformation.status":{"os.version":"29.2"},"big":[1,2,3]}`)
	got, _ := json.Marshal(Project(v, []string{"name", "extendedinformation.status/os.version", "missing"}))
	if string(got) != `{"extendedinformation.status/os.version":"29.2","name":"s1"}` {
		t.Fatalf("got %s", got)
	}
}
