package softsensor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jlagermann/fleet-mcp/internal/host"
)

// fakeRunner answers scripts by the first matching rule, in order.
type fakeRunner struct {
	rules   [][2]string
	scripts []string
}

func (f *fakeRunner) Name() string { return "james@198.51.100.9" }
func (f *fakeRunner) Run(_ context.Context, script string, _ ...string) (*host.Result, error) {
	f.scripts = append(f.scripts, script)
	for _, r := range f.rules {
		if strings.Contains(script, r[0]) {
			return &host.Result{Stdout: r[1]}, nil
		}
	}
	return &host.Result{}, nil
}

const sampleFacts = `os=ubuntu 24.04|Ubuntu 24.04.3 LTS
apt=yes
pkg=corelight-sensor|ii |29.0.6-1
pkg=corelightctl|ii |29.0.6-1
pkg=corelight-sensor-images-base|ii |29.0.6-1
pkg=corelight-sensor-rke2-images|un |
newrepo=yes
yaml=600
free=%FREE%
deployreq=21.86
firewalld=inactive
unit=inactive
aptupdate=ok
available=29.2.3-1
available=29.2.2-1
available=29.2.1-1
available=29.0.6-1
`

const sampleURIs = `'https://pkgrepos.example/corelightctl_29.2.2-1_amd64.deb' corelightctl_29.2.2-1_amd64.deb 228782184 SHA256:aa
'https://pkgrepos.example/corelight-sensor-images-base_29.2.2-1_amd64.deb' corelight-sensor-images-base_29.2.2-1_amd64.deb 4536392930 SHA256:bb
'https://pkgrepos.example/corelight-sensor_29.2.2-1_amd64.deb' corelight-sensor_29.2.2-1_amd64.deb 3492 SHA256:cc
`

func planner(free string) (*Planner, *fakeRunner) {
	f := &fakeRunner{rules: [][2]string{
		{"dpkg-query -W -f='pkg=", strings.ReplaceAll(sampleFacts, "%FREE%", free)},
		{"--print-uris", sampleURIs},
		{"apt-cache show", "481128\n4430067\n0\n"},
		{"--compare-versions", "1\n"},
	}}
	return &Planner{R: f}, f
}

func TestPlanPicksNewestAllowedByFleetManager(t *testing.T) {
	p, _ := planner("60000")
	plan, err := p.Plan(context.Background(), Options{MaxVersion: "29.2.2-16847904621"}, "29.0.6")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Target != "29.2.2-1" {
		t.Fatalf("target %q, want 29.2.2-1 (29.2.3 is newer than the Fleet Manager)", plan.Target)
	}
	if !plan.Ready() || len(plan.Blockers) != 0 {
		t.Fatalf("not ready: %v", plan.Blockers)
	}
	// 228782184+4536392930+3492 bytes = 4544 MB; largest 4430067 KiB = 4326 MB
	if plan.DownloadMB != 4544 {
		t.Errorf("download %d MB", plan.DownloadMB)
	}
	if want := 22385 + marginMB; plan.NeededMB != want { // deploy check wins over 4544+4326
		t.Errorf("needed %d MB, want %d", plan.NeededMB, want)
	}
	if !strings.Contains(strings.Join(plan.Steps, "\n"), "corelightctl=29.2.2-1 corelight-sensor=29.2.2-1") {
		t.Errorf("steps: %v", plan.Steps)
	}
}

func TestPlanBlocksNewerThanFleetManagerAndLowDisk(t *testing.T) {
	p, _ := planner("12000")
	plan, err := p.Plan(context.Background(), Options{Version: "29.2.3", MaxVersion: "29.2.2-16847904621"}, "29.0.6")
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(plan.Blockers, "\n")
	for _, want := range []string{"newer than its Fleet Manager", "only 12000 MB free"} {
		if !strings.Contains(all, want) {
			t.Errorf("no blocker %q in:\n%s", want, all)
		}
	}
	if plan.Ready() {
		t.Error("ready despite blockers")
	}
}

func TestPlanDeployOnlyAfterInstall(t *testing.T) {
	p, f := planner("60000")
	f.rules[0][1] = strings.ReplaceAll(strings.ReplaceAll(sampleFacts, "%FREE%", "60000"), "corelight-sensor|ii |29.0.6-1", "corelight-sensor|ii |29.2.2-1")
	plan, err := p.Plan(context.Background(), Options{MaxVersion: "29.2.2"}, "29.0.6")
	if err != nil {
		t.Fatal(err)
	}
	if !plan.DeployOnly || !plan.Ready() {
		t.Fatalf("deploy_only=%v ready=%v blockers=%v", plan.DeployOnly, plan.Ready(), plan.Blockers)
	}
	if strings.Contains(strings.Join(plan.Steps, "\n"), "apt-get install") {
		t.Errorf("deploy-only plan installs packages: %v", plan.Steps)
	}
	// Already running the target: nothing to do.
	plan, err = p.Plan(context.Background(), Options{MaxVersion: "29.2.2"}, "29.2.2")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Ready() {
		t.Error("ready although the target is installed and running")
	}
}

func TestPlanWarnsAndBlocksOnHost(t *testing.T) {
	p, f := planner("60000")
	facts := strings.ReplaceAll(sampleFacts, "%FREE%", "60000")
	facts = strings.ReplaceAll(facts, "os=ubuntu 24.04|Ubuntu 24.04.3 LTS", "os=ubuntu 26.04|Ubuntu 26.04 LTS")
	facts = strings.ReplaceAll(facts, "yaml=600", "yaml=644")
	facts += "oldrepo=yes\n"
	f.rules[0][1] = facts
	plan, err := p.Plan(context.Background(), Options{MaxVersion: "29.2.2"}, "29.0.6")
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(plan.Warnings, "\n")
	for _, want := range []string{"not a documented Software Sensor platform", "mode 644"} {
		if !strings.Contains(w, want) {
			t.Errorf("no warning %q in:\n%s", want, w)
		}
	}
	if !strings.Contains(strings.Join(plan.Blockers, "\n"), "corelight_corelightctl.list") {
		t.Errorf("no retired-repository blocker: %v", plan.Blockers)
	}
	if strings.Contains(w, "synchronous 4 KiB write") {
		t.Errorf("slow-storage warning without a measurement:\n%s", w)
	}
}

// TestStateChangesWithBootAndRun checks that the plan state behind the
// confirm token changes after a reboot (or VM snapshot revert) and after
// another upgrade run, although the versions are the same.
func TestStateChangesWithBootAndRun(t *testing.T) {
	state := func(extra string) string {
		p, f := planner("60000")
		f.rules[0][1] = strings.ReplaceAll(sampleFacts, "%FREE%", "60000") + extra
		plan, err := p.Plan(context.Background(), Options{MaxVersion: "29.2.2"}, "29.0.6")
		if err != nil {
			t.Fatal(err)
		}
		return plan.State()
	}
	a := state("bootid=aaaa\nlastrun=\n")
	if a != state("bootid=aaaa\nlastrun=\n") {
		t.Error("state differs for the same host facts")
	}
	if a == state("bootid=bbbb\nlastrun=\n") {
		t.Error("state unchanged after a reboot")
	}
	if a == state("bootid=aaaa\nlastrun=2026-10-27T15:03:05Z queued\n") {
		t.Error("state unchanged after an upgrade run")
	}
}

func TestPlanWarnsOnSlowStorage(t *testing.T) {
	for _, c := range []struct {
		syncus string
		ms     float64
		warn   bool
	}{{"23450", 23.45, true}, {"10000", 10, true}, {"870", 0.87, false}} {
		p, f := planner("60000")
		f.rules[0][1] = strings.ReplaceAll(sampleFacts, "%FREE%", "60000") + "syncus=" + c.syncus + "\n"
		plan, err := p.Plan(context.Background(), Options{MaxVersion: "29.2.2"}, "29.0.6")
		if err != nil {
			t.Fatal(err)
		}
		if plan.SyncWriteMs != c.ms {
			t.Errorf("syncus=%s: sync_write_ms %v, want %v", c.syncus, plan.SyncWriteMs, c.ms)
		}
		w := strings.Join(plan.Warnings, "\n")
		if c.warn && !strings.Contains(w, "check for snapshots") {
			t.Errorf("syncus=%s: slow-storage warning lacks the snapshot advice:\n%s", c.syncus, w)
		}
		if got := strings.Contains(w, "synchronous 4 KiB write"); got != c.warn {
			t.Errorf("syncus=%s: slow-storage warning %v, want %v", c.syncus, got, c.warn)
		}
	}
}

// TestFactsLatencyRuns runs the latency lines of the facts script with
// bash, its file moved to a temporary directory.
func TestFactsLatencyRuns(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	var lines []string
	for _, l := range strings.Split(facts, "\n") {
		if strings.Contains(l, "lat") || strings.HasPrefix(l, "t0=") {
			lines = append(lines, l)
		}
	}
	dir := t.TempDir()
	s := strings.ReplaceAll(strings.Join(lines, "\n"), "/var/lib/", dir+"/")
	out, err := exec.Command(bash, "-c", s).CombinedOutput()
	if err != nil {
		t.Fatalf("latency lines failed: %v\n%s", err, out)
	}
	k, v, _ := strings.Cut(strings.TrimSpace(string(out)), "=")
	if n, err := strconv.Atoi(v); k != "syncus" || err != nil || n < 0 {
		t.Errorf("output %q, want syncus=<microseconds>", out)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("latency file left behind: %v", left)
	}
}

func TestStartScript(t *testing.T) {
	p, f := planner("60000")
	plan, err := p.Plan(context.Background(), Options{MaxVersion: "29.2.2"}, "29.0.6")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	s := f.scripts[len(f.scripts)-1]
	for _, want := range []string{"systemd-run --unit=" + unit, "corelightctl='29.2.2-1' corelight-sensor='29.2.2-1'", "sensor prepare", "sensor deploy -v", "apt-get clean"} {
		if !strings.Contains(s, want) {
			t.Errorf("start script lacks %q", want)
		}
	}
	if strings.Contains(s, "{{") {
		t.Error("unreplaced placeholder in start script")
	}
	plan.Blockers = []string{"x"}
	if err := p.Start(context.Background(), plan); err == nil {
		t.Error("started a blocked plan")
	}
}

// TestStartScriptRuns runs the start script with bash, its paths moved to
// a temporary directory and systemd stubbed out, and checks the script it
// writes (a redirect after a heredoc once left it empty).
func TestStartScriptRuns(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	s := startScript(&Plan{Target: "29.2.2-1"})
	s = strings.NewReplacer(
		"/var/lib/fleet-mcp", dir,
		logFile, filepath.Join(dir, "upgrade.log"),
		"systemctl ", "true ",
		"systemd-run ", "echo started ",
	).Replace(s)
	out, err := exec.Command(bash, "-c", s).CombinedOutput()
	if err != nil {
		t.Fatalf("start script failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "started --unit="+unit) {
		t.Errorf("unit not started: %s", out)
	}
	written, err := os.ReadFile(filepath.Join(dir, "softsensor-upgrade.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"corelightctl='29.2.2-1' corelight-sensor='29.2.2-1'", "if [ no = no ]", "sensor deploy -v", "stage done"} {
		if !strings.Contains(string(written), want) {
			t.Errorf("written script lacks %q:\n%s", want, written)
		}
	}
	if out, err := exec.Command(bash, "-n", filepath.Join(dir, "softsensor-upgrade.sh")).CombinedOutput(); err != nil {
		t.Errorf("written script does not parse: %v %s", err, out)
	}
	state, _ := os.ReadFile(filepath.Join(dir, "softsensor-upgrade.state"))
	if !strings.HasSuffix(strings.TrimSpace(string(state)), "queued") {
		t.Errorf("state %q, want queued", state)
	}
}

func TestStatus(t *testing.T) {
	cases := []struct {
		out, result, err string
	}{
		{"unit=active\nstage=2026-10-26T20:00:00Z start '29.2.2-1'\nstage=2026-10-26T20:00:01Z install\n", ResultRunning, ""},
		{"unit=inactive\nstage=t start x\nstage=t deploy\nstage=t done 0\n", ResultDone, ""},
		{"unit=inactive\nstage=t prepare\nstage=t reboot-required prepare\n", ResultRebootRequired, ""},
		{"unit=inactive\nstage=t deploy\nstage=t failed deploy 6\nerr=ERROR preflight\n", ResultFailed, "failed during deploy (exit 6): deployment failed; the rollback completed"},
		{"unit=inactive\nstage=t install\n", ResultFailed, "stopped during install"},
		{"unit=inactive\nstage=t queued\n", ResultFailed, "stopped during queued"},
		{"unit=active\nstage=t queued\n", ResultRunning, ""},
		{"unit=inactive\n", "", ""},
	}
	for _, c := range cases {
		p := &Planner{R: &fakeRunner{rules: [][2]string{{"systemctl is-active", c.out}}}}
		st, err := p.Status(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if st.Result != c.result || !strings.Contains(st.Error, c.err) {
			t.Errorf("%q: result %q error %q, want %q / %q", c.out, st.Result, st.Error, c.result, c.err)
		}
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"29.2.3", "29.2.2", true}, {"29.2.2", "29.2.2", false}, {"29.10.0", "29.9.9", true}, {"29.2", "29.2.1", false}} {
		if got := newer(c.a, c.b); got != c.want {
			t.Errorf("newer(%s, %s) = %v", c.a, c.b, got)
		}
	}
	if base("29.2.2-16847904621") != "29.2.2" {
		t.Error("base")
	}
}
