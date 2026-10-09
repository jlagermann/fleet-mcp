package fleets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func setupDirs(t *testing.T) (fleetsFile, profilesDir string) {
	dir := t.TempDir()
	fleetsFile = filepath.Join(dir, "fleets.json")
	profilesDir = filepath.Join(dir, "hosts")
	writeFile(t, fleetsFile, `[
	  {"name": "prod", "url": "https://fm.example.com", "username": "claude", "password_file": "/pw/prod", "read_only": true},
	  {"name": "lab", "url": "https://lab.example.com", "username": "claude", "password_file": "/pw/lab", "default": true},
	  {"name": "bad name!", "url": "https://x", "username": "u", "password_file": "/p"}
	]`)
	writeFile(t, filepath.Join(profilesDir, "10.0.0.5", "profile.json"),
		`{"url":"https://10.0.0.5","username":"claude","password_file":"/pw/a","cert_sha256":"`+pin+`"}`)
	return fleetsFile, profilesDir
}

func TestLoadSourcesAndDefault(t *testing.T) {
	ff, pd := setupDirs(t)
	r := New(Options{FleetsFile: ff, ProfilesDir: pd})
	list, warns := r.List()
	if len(list) != 3 {
		t.Fatalf("fleets = %+v", list)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "bad name") {
		t.Fatalf("warnings = %v", warns)
	}
	byName := map[string]Fleet{}
	for _, f := range list {
		byName[f.Name] = f
	}
	if !byName["lab"].Default || byName["prod"].Default || !byName["prod"].ReadOnly {
		t.Fatalf("flags: %+v", byName)
	}
	if p := byName["10.0.0.5"]; p.Source != "installed by fleet-mcp" || p.CertSHA256 != pin {
		t.Fatalf("profile entry: %+v", p)
	}
	c, err := r.Get("")
	if err != nil || c.Name != "lab" {
		t.Fatalf("default = %v, %v", c, err)
	}
	c2, _ := r.Get("lab")
	if c2 != c {
		t.Fatal("connection not reused")
	}
}

func TestEnvWinsAndDefaultName(t *testing.T) {
	ff, pd := setupDirs(t)
	env := &Fleet{Name: "lab", URL: "https://env.example.com", Username: "u", PasswordFile: "/p"}
	r := New(Options{Env: env, FleetsFile: ff, ProfilesDir: pd, DefaultName: "prod"})
	list, _ := r.List()
	for _, f := range list {
		if f.Name == "lab" && f.URL != "https://env.example.com" {
			t.Fatalf("environment did not win: %+v", f)
		}
	}
	if c, err := r.Get(""); err != nil || c.Name != "prod" {
		t.Fatalf("DefaultName ignored: %v %v", c, err)
	}
}

func TestNoDefaultWithSeveral(t *testing.T) {
	dir := t.TempDir()
	ff := filepath.Join(dir, "fleets.json")
	writeFile(t, ff, `[{"name":"a","url":"https://a","username":"u","password_file":"/p"},{"name":"b","url":"https://b","username":"u","password_file":"/p"}]`)
	r := New(Options{FleetsFile: ff})
	if _, err := r.Get(""); err == nil || !strings.Contains(err.Error(), "a, b") {
		t.Fatalf("err = %v", err)
	}
	if _, err := r.Get("zzz"); err == nil || !strings.Contains(err.Error(), "unknown fleet") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewProfilePickedUp(t *testing.T) {
	dir := t.TempDir()
	pd := filepath.Join(dir, "hosts")
	r := New(Options{ProfilesDir: pd, FleetsFile: filepath.Join(dir, "none.json")})
	if !r.Empty() {
		t.Fatal("expected empty")
	}
	if _, err := r.Get(""); err == nil || !strings.Contains(err.Error(), "no Fleet Manager is configured") {
		t.Fatalf("err = %v", err)
	}
	writeFile(t, filepath.Join(pd, "fm-new", "profile.json"), `{"url":"https://fm-new","username":"claude","password_file":"/p","cert_sha256":"`+pin+`"}`)
	c, err := r.Get("fm-new")
	if err != nil || c.Name != "fm-new" {
		t.Fatalf("new profile not picked up: %v", err)
	}
}

func TestReloadKeepsUnchangedConns(t *testing.T) {
	ff, pd := setupDirs(t)
	r := New(Options{FleetsFile: ff, ProfilesDir: pd})
	c1, err := r.Get("lab")
	if err != nil {
		t.Fatal(err)
	}
	r.Reload()
	c2, _ := r.Get("lab")
	if c1 != c2 {
		t.Fatal("unchanged connection was dropped on reload")
	}
	writeFile(t, ff, `[{"name": "lab", "url": "https://moved.example.com", "username": "claude", "password_file": "/pw/lab"}]`)
	r.Reload()
	c3, _ := r.Get("lab")
	if c3 == c1 || c3.URL != "https://moved.example.com" {
		t.Fatal("changed entry kept the old connection")
	}
}
