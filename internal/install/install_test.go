package install

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"unicode"

	"github.com/jlagermann/fleet-mcp/internal/host"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
)

func TestGrade(t *testing.T) {
	facts := map[string]string{
		"os_id": "ubuntu", "os_version": "22.04", "os_name": "Ubuntu 22.04.5 LTS", "arch": "x86_64",
		"cpus": "4", "mem_mb": "7900", "var_free_gb": "21", "tmp_free_gb": "21", "var_fs": "/", "tmp_fs": "/",
		"port_443": "free", "port_1443": "nginx", "repo_http": "401", "fleet_pkg": "",
	}
	rep := Grade(facts)
	levels := map[string]Level{}
	for _, f := range rep.Findings {
		levels[f.Check] = f.Level
	}
	want := map[string]Level{"os": Pass, "arch": Pass, "cpus": Pass, "memory": Pass, "var_space": Warn, "tmp_space": Pass,
		"shared_space": Warn, "port_443": Pass, "port_1443": Fail, "repository": Pass}
	for k, v := range want {
		if levels[k] != v {
			t.Errorf("%s = %s, want %s", k, levels[k], v)
		}
	}
	if rep.Ready {
		t.Error("port conflict should make the host not ready")
	}
	facts["port_1443"] = "free"
	facts["mem_mb"] = "4000"
	facts["os_version"] = "20.04"
	rep = Grade(facts)
	if rep.Ready {
		t.Error("Ubuntu 20.04 should fail")
	}
}

func TestParseTempPassword(t *testing.T) {
	out := "User \"admin\" successfully created.\n\nUser info:\n   ID:          19a3312c\n   Password:    alm2iepoa19(.\n   FleetAdmin:  true\n"
	if pw, ok := ParseTempPassword(out); !ok || pw != "alm2iepoa19(." {
		t.Fatalf("got %q %v", pw, ok)
	}
	if _, ok := ParseTempPassword("error: user exists"); ok {
		t.Fatal("parsed a password from an error")
	}
}

func TestGenerate(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p := Generate(24, true)
		if len(p) != 24 || seen[p] || strings.ContainsAny(p, " '\"\\`$") {
			t.Fatalf("bad password %q", p)
		}
		seen[p] = true
		var lo, up, di, sy bool
		for _, r := range p {
			switch {
			case unicode.IsLower(r):
				lo = true
			case unicode.IsUpper(r):
				up = true
			case unicode.IsDigit(r):
				di = true
			default:
				sy = true
			}
		}
		if !lo || !up || !di || !sy {
			t.Fatalf("missing a character class: %q", p)
		}
	}
	if strings.ContainsAny(Generate(40, false), "!@#%^*-_=+") {
		t.Fatal("symbols in a no-symbol string")
	}
}

func TestDesiredConfKeepsUnknownKeys(t *testing.T) {
	var conf map[string]any
	_ = json.Unmarshal([]byte(`{"log-level":"DEBUG","tacacs-plus":{"enable":false},"messaging":{"community-string":"","http-options":{"bind-address":":2443"}}}`), &conf)
	yes := true
	in := &Installer{Opts: Options{ExposeSwagger: &yes}}
	got := in.desiredConf(conf, "abc")
	b, _ := json.Marshal(got)
	s := string(b)
	for _, want := range []string{`"log-level":"DEBUG"`, `"tacacs-plus":{"enable":false}`, `"community-string":"abc"`, `"bind-address":":2443"`, `"expose-swagger":true`, `"ssl-key-path":"/etc/corelight-fleetd.pem"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	if communityFrom(conf) != "" {
		t.Error("input was modified")
	}
	no := false
	in.Opts.ExposeSwagger = &no
	conf["expose-swagger"] = true
	if _, ok := in.desiredConf(conf, "abc")["expose-swagger"]; ok {
		t.Error("expose-swagger not removed")
	}
}

// fakeRunner answers scripts by substring.
type fakeRunner struct {
	answers map[string]string // substring -> stdout
	scripts []string
}

func (f *fakeRunner) Name() string { return "fake" }
func (f *fakeRunner) Run(_ context.Context, script string, secretVals ...string) (*host.Result, error) {
	f.scripts = append(f.scripts, script)
	for k, v := range f.answers {
		if strings.Contains(script, k) {
			return &host.Result{Stdout: host.Mask(v, secretVals...)}, nil
		}
	}
	return &host.Result{}, nil
}

func TestPlanBlocksWithoutSecrets(t *testing.T) {
	st, err := secrets.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{answers: map[string]string{
		`echo "os_id=`: goodFacts,
		"dpkg-query -W -f='${Status}\\n' curl": "0\n",
	}}
	in := &Installer{R: r, Secrets: st, Host: "test-host", Opts: Options{}}
	plan, err := in.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]State{}
	for _, s := range plan {
		states[s.Step] = s.State
	}
	if states["readiness"] != Done || states["prerequisites"] != Pending || states["repo_key"] != Blocked || states["agent_user"] != Pending {
		t.Fatalf("plan = %+v", plan)
	}
	if !strings.Contains(plan[2].Detail, "fleet-mcp secret set repo-token") {
		t.Fatalf("blocked detail = %q", plan[2].Detail)
	}
	// Planning must not change the host.
	for _, s := range r.scripts {
		if strings.Contains(s, "apt-get install") || strings.Contains(s, "install -m") {
			t.Fatalf("plan ran a change: %s", s)
		}
	}
}

const goodFacts = "os_id=ubuntu\nos_version=22.04\nos_name=Ubuntu 22.04.5 LTS\narch=x86_64\ncpus=4\nmem_mb=16000\n" +
	"var_free_gb=120\ntmp_free_gb=120\nvar_fs=/\ntmp_fs=/\nport_443=free\nport_1443=free\nrepo_http=401\nntp_synced=no\n"

func readinessOf(t *testing.T, facts string) StepStatus {
	t.Helper()
	st, _ := secrets.Open(t.TempDir())
	in := &Installer{R: &fakeRunner{answers: map[string]string{`echo "os_id=`: facts}}, Secrets: st, Host: "h"}
	plan, err := in.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return plan[0]
}

func TestReadinessBlocksOnResourceWarnings(t *testing.T) {
	if s := readinessOf(t, goodFacts); s.State != Done || !strings.Contains(s.Detail, "advisory: time_sync") {
		t.Fatalf("good host: %+v", s)
	}
	for name, facts := range map[string]string{
		"low disk":    strings.Replace(goodFacts, "var_free_gb=120", "var_free_gb=21", 1),
		"low memory":  strings.Replace(goodFacts, "mem_mb=16000", "mem_mb=4000", 1),
		"one cpu":     strings.Replace(goodFacts, "cpus=4", "cpus=1", 1),
		"rhel":        strings.Replace(goodFacts, "os_id=ubuntu\nos_version=22.04", "os_id=rhel\nos_version=9.4", 1),
		"old ubuntu":  strings.Replace(goodFacts, "os_version=22.04", "os_version=20.04", 1),
		"port in use": strings.Replace(goodFacts, "port_443=free", "port_443=nginx", 1),
	} {
		if s := readinessOf(t, facts); s.State != Blocked {
			t.Errorf("%s: %+v", name, s)
		}
	}
}

type fakeBootstrap struct {
	activated   string
	adminExists bool
}

func (f *fakeBootstrap) MCPUserReady(context.Context, *Installer) (bool, string) { return false, "" }
func (f *fakeBootstrap) ActivateMCPUser(_ context.Context, _ *Installer, temp string) error {
	f.activated = temp
	return nil
}
func (f *fakeBootstrap) AdminExists(context.Context, *Installer) (bool, error) { return f.adminExists, nil }

const created = "User \"%s\" successfully created.\n\nUser info:\n   ID:          19a3\n   Password:    %s\n   FleetAdmin:  true\n"

func TestAdminTemporaryPasswordReturned(t *testing.T) {
	r := &fakeRunner{answers: map[string]string{"create-user -a 'admin'": strings.ReplaceAll(strings.Replace(created, "%s", "admin", 1), "%s", "Tmp-pw.1")}}
	in := &Installer{R: r, Host: "h", Opts: Options{MCPUser: "fleet-mcp"}, Bootstrap: &fakeBootstrap{}}
	detail, err := in.applyAdmin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if in.AdminTempPassword != "Tmp-pw.1" || !strings.Contains(detail, "Tmp-pw.1") || !strings.Contains(detail, "require a new password") {
		t.Fatalf("detail %q, temp %q", detail, in.AdminTempPassword)
	}
	for _, s := range r.scripts {
		if strings.Contains(s, "reset-password") {
			t.Fatal("admin password reset attempted")
		}
	}
}

func TestExistingAdminUntouched(t *testing.T) {
	r := &fakeRunner{answers: map[string]string{"create-user -a 'admin'": "error: user admin already exists\n"}}
	in := &Installer{R: r, Host: "h", Opts: Options{MCPUser: "fleet-mcp"}, Bootstrap: &fakeBootstrap{}}
	detail, err := in.applyAdmin(context.Background())
	if err != nil || in.AdminTempPassword != "" || !strings.Contains(detail, "left untouched") {
		t.Fatalf("%q %v", detail, err)
	}
	for _, s := range r.scripts {
		if strings.Contains(s, "reset-password") {
			t.Fatal("existing admin was reset")
		}
	}
}

func TestMCPUserResetWhenExisting(t *testing.T) {
	r := &fakeRunner{answers: map[string]string{
		"create-user -a 'fleet-mcp'":    "error: user fleet-mcp already exists\n",
		"reset-password 'fleet-mcp'":    "   Password:    Reset-1x\n",
	}}
	fb := &fakeBootstrap{}
	in := &Installer{R: r, Host: "h", Opts: Options{MCPUser: "fleet-mcp"}, Bootstrap: fb}
	detail, err := in.applyMCPUser(context.Background())
	if err != nil || fb.activated != "Reset-1x" || !strings.Contains(detail, "reset") || strings.Contains(detail, "Reset-1x") {
		t.Fatalf("%q %v activated=%q", detail, err, fb.activated)
	}
}

func TestOptionsValidate(t *testing.T) {
	for _, o := range []Options{{Version: "29.2; rm -rf /"}, {MCPUser: "admin"}, {MCPUser: "a b"}} {
		if err := o.Validate(); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
	o := Options{Version: "29.2.2"}
	if err := o.Validate(); err != nil || o.MCPUser != DefaultAgentUser || o.ExposeSwagger == nil || !*o.ExposeSwagger {
		t.Fatalf("defaults: %+v %v", o, err)
	}
	off := false
	o = Options{ExposeSwagger: &off}
	if err := o.Validate(); err != nil || *o.ExposeSwagger {
		t.Fatalf("explicit false was overridden: %+v", o)
	}
}

func TestTokenScriptKeepsTokenOffCommandLines(t *testing.T) {
	s := tokenScript("abc123TOKEN")
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "abc123TOKEN") && strings.Contains(line, "curl") {
			t.Fatalf("token on a curl command line: %s", line)
		}
	}
	if !strings.Contains(s, "<<'FLEET_MCP_EOF'") {
		t.Fatal("token not in a quoted heredoc")
	}
}

func TestChecklist(t *testing.T) {
	st, _ := secrets.Open(t.TempDir())
	items, err := Checklist(context.Background(), st, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ChecklistReady(items) {
		t.Fatal("ready without a token or certificate")
	}
	md := RenderChecklist(items)
	for _, want := range []string{"[ ] MISSING Package repository auth token", "fleet-mcp secret set repo-token", "[?] not checked", "temporary password", "Resolve the MISSING"} {
		if !strings.Contains(md, want) {
			t.Errorf("checklist lacks %q:\n%s", want, md)
		}
	}
	_ = st.Set("", secrets.RepoToken, []byte("abcdef0123456789abcdef"))
	r := &fakeRunner{answers: map[string]string{`echo "os_id=`: strings.Replace(goodFacts, "ntp_synced=no", "ntp_synced=yes", 1)}}
	items, _ = Checklist(context.Background(), st, "h", r)
	for _, it := range items {
		if it.Section == "Host" && it.Status != Ready {
			t.Errorf("host item %q = %s (%s)", it.Item, it.Status, it.Detail)
		}
	}
	if ChecklistReady(items) {
		t.Fatal("ready without the identity certificate")
	}
}

// TestTokenScriptInBash runs the generated fragment in a real shell: the
// heredoc must terminate and $TOKEN and the netrc must hold the token.
func TestTokenScriptInBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	tok := "abcDEF0123456789xyz"
	script := tokenScript(tok) + "printf 'T=%s\n' \"$TOKEN\"; cat \"$NETRC\"\n"
	out, err := exec.Command(bash, "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	s := string(out)
	if strings.Contains(s, "here-document") || !strings.Contains(s, "T="+tok+"\n") ||
		!strings.Contains(s, "machine pkgrepos.corelight.cloud login "+tok+" password irrelevant") {
		t.Fatalf("output:\n%s", s)
	}
}

// TestWriteFileScriptInBash writes a file with the generated script in a
// real shell and checks the content arrives intact.
func TestWriteFileScriptInBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum not available")
	}
	who, err := exec.Command(bash, "-c", "printf %s:%s \"$(id -un)\" \"$(id -gn)\"").Output()
	if err != nil {
		t.Skip("id not available")
	}
	path := t.TempDir() + "/out.conf"
	content := "line one with FLEET_MCP_EOF in it\n{\"json\": true}\n"
	script := "set -e\n" + writeFileScript(path, content, "0640", string(who)) + "echo DONE\n"
	out, err := exec.Command(bash, "-c", script).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "DONE") || strings.Contains(string(out), "here-document") {
		t.Fatalf("%v: %s", err, out)
	}
	got, err := exec.Command("cat", path).Output()
	if err != nil || string(got) != content {
		t.Fatalf("file = %q, %v", got, err)
	}
}
