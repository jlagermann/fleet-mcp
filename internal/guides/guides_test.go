package guides

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEveryGuideHasAFile(t *testing.T) {
	for _, g := range All() {
		_, text, ok := Get(g.Name)
		if !ok || !strings.HasPrefix(text, "# ") {
			t.Errorf("%s: missing or has no title", g.Name)
		}
		if g.Title == "" || g.Description == "" || g.When == "" {
			t.Errorf("%s: incomplete metadata", g.Name)
		}
	}
}

func TestEveryFileIsAGuide(t *testing.T) {
	names := map[string]bool{}
	for _, n := range Names() {
		names[n+".md"] = true
	}
	md, _ := fs.Glob(files, "*.md")
	for _, f := range md {
		if !names[f] {
			t.Errorf("%s is embedded but not listed", f)
		}
	}
}

func TestGetUnknown(t *testing.T) {
	if _, _, ok := Get("nope"); ok {
		t.Fatal("unknown guide found")
	}
	if _, _, ok := Get(" Move-Sensor "); !ok {
		t.Fatal("name should be trimmed and case-insensitive")
	}
}
