package install

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jlagermann/fleet-mcp/internal/host"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
)

// ruleRunner answers scripts by the first matching rule, in order.
type ruleRunner struct {
	rules   []rule
	scripts []string
}

type rule struct {
	match  string
	stdout string
	code   int
}

func (f *ruleRunner) Name() string { return "198.51.100.7" }
func (f *ruleRunner) Run(_ context.Context, script string, secretVals ...string) (*host.Result, error) {
	f.scripts = append(f.scripts, script)
	for _, r := range f.rules {
		if strings.Contains(script, r.match) {
			res := &host.Result{Stdout: host.Mask(r.stdout, secretVals...), ExitCode: r.code}
			if r.code != 0 {
				res.Stderr = "the web API did not come up within 120s"
			}
			return res, nil
		}
	}
	return &host.Result{}, nil
}

const sampleConf = `{
   "data-path": "/var/lib/corelight-fleetd",
   "log-level": "INFO",
   "messaging": {"community-string": "OldCommunity123", "http-options": {"bind-address": ":1443"}},
   "ssl-certificate-path": "/etc/corelight-fleetd.pem",
   "ssl-key-path": "/etc/corelight-fleetd.pem"
}`

func newStore(t *testing.T) *secrets.Store {
	t.Helper()
	st, err := secrets.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func selfSigned(t *testing.T, cn string, names []string, ips []net.IP) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		DNSNames: names, IPAddresses: ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})...)
}

func TestPlanConfigureSettings(t *testing.T) {
	r := &ruleRunner{rules: []rule{{match: "cat " + confPath, stdout: sampleConf}}}
	m := &Maintainer{R: r, Secrets: newStore(t), Host: "198.51.100.7"}
	p, err := m.PlanConfigure(context.Background(), ConfigureOptions{Settings: map[string]any{
		"log-level":                           "debug",
		"messaging.community-string":          "x",
		"data-path":                           "/srv",
		"expose-swagger":                      "yes",
		"messaging/http-options/bind-address": ":1443", // unchanged
		"brand-new-key":                       true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes) != 2 || p.Changes[1].Item != "log-level" || p.Changes[1].To != `"DEBUG"` || p.Changes[1].From != `"INFO"` {
		t.Fatalf("changes = %+v", p.Changes)
	}
	if len(p.Blockers) != 3 || p.Ready() {
		t.Fatalf("blockers = %v", p.Blockers)
	}
	if !strings.Contains(strings.Join(p.Warnings, " "), "brand-new-key") {
		t.Fatalf("warnings = %v", p.Warnings)
	}
	for _, s := range r.scripts {
		if strings.Contains(s, "install -m") || strings.Contains(s, "systemctl restart") {
			t.Fatalf("plan changed the host: %s", s)
		}
	}
}

func TestPlanConfigureCommunityStringNeverShown(t *testing.T) {
	st := newStore(t)
	if err := st.Set("198.51.100.7", secrets.CommunityString, []byte("NewCommunity456")); err != nil {
		t.Fatal(err)
	}
	r := &ruleRunner{rules: []rule{{match: "cat " + confPath, stdout: sampleConf}, {match: "systemctl restart", stdout: "api up after 3x2s\n"}}}
	m := &Maintainer{R: r, Secrets: st, Host: "198.51.100.7"}
	p, err := m.PlanConfigure(context.Background(), ConfigureOptions{CommunityString: true})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	if !p.Ready() || strings.Contains(string(b), "NewCommunity456") || strings.Contains(string(b), "OldCommunity123") {
		t.Fatalf("plan = %s", b)
	}
	res, err := m.ApplyConfigure(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(res)
	if strings.Contains(string(b), "NewCommunity456") || len(res.Backups) != 1 {
		t.Fatalf("result = %s", b)
	}
}

func TestApplyConfigureRollsBack(t *testing.T) {
	r := &ruleRunner{rules: []rule{
		{match: "cat " + confPath, stdout: sampleConf},
		{match: "stat -c", stdout: "644 root:corelight-fleetd\n"},
		{match: "install -m", code: 1},
	}}
	m := &Maintainer{R: r, Secrets: newStore(t), Host: "198.51.100.7"}
	p, err := m.PlanConfigure(context.Background(), ConfigureOptions{Settings: map[string]any{"log-level": "WARN"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.ApplyConfigure(context.Background(), p)
	if err == nil || res == nil || !res.RolledBack || !strings.Contains(err.Error(), "backups were restored") {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	apply, rollback := r.scripts[len(r.scripts)-2], r.scripts[len(r.scripts)-1]
	// The configuration is rewritten without world access, and backed up
	// root-only.
	if !strings.Contains(apply, "install -m 0640 -o root -g corelight-fleetd") || !strings.Contains(apply, "chmod 600") {
		t.Fatalf("apply script:\n%s", apply)
	}
	if !strings.Contains(rollback, "cp '"+confPath+".bak-") || !strings.Contains(rollback, "systemctl restart") {
		t.Fatalf("rollback script:\n%s", rollback)
	}
}

func TestPlanConfigureTLSCert(t *testing.T) {
	st := newStore(t)
	pemData := selfSigned(t, "fm.example.net", []string{"fm.example.net"}, nil)
	if _, err := secrets.Validate(secrets.TLSCert, pemData); err != nil {
		t.Fatal(err)
	}
	if err := st.Set("198.51.100.7", secrets.TLSCert, pemData); err != nil {
		t.Fatal(err)
	}
	r := &ruleRunner{rules: []rule{
		{match: "cat " + confPath, stdout: sampleConf},
		{match: "openssl x509 -noout -subject", stdout: "abc123\nsubject=CN = Corelight FM 1234\nnotAfter=Feb 27 12:00:00 2027 GMT\n"},
	}}
	m := &Maintainer{R: r, Secrets: st, Host: "198.51.100.7"}
	p, err := m.PlanConfigure(context.Background(), ConfigureOptions{TLSCert: true})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Ready() || !p.repin || len(p.files) != 1 || p.files[0].path != tlsPath {
		t.Fatalf("plan = %+v", p)
	}
	if v, _ := getPath(p.conf, "ssl-key-path"); v != tlsPath {
		t.Fatalf("ssl-key-path = %v", v)
	}
	if p.Changes[0].From != "Corelight FM 1234, expires 2027-02-27" {
		t.Fatalf("from = %q", p.Changes[0].From)
	}
	w := strings.Join(p.Warnings, " ")
	if !strings.Contains(w, "do not include 198.51.100.7") || !strings.Contains(w, "identity certificate stays") {
		t.Fatalf("warnings = %v", p.Warnings)
	}
}

func TestPlanConfigureMissingSecrets(t *testing.T) {
	r := &ruleRunner{rules: []rule{{match: "cat " + confPath, stdout: sampleConf}}}
	m := &Maintainer{R: r, Secrets: newStore(t), Host: "198.51.100.7"}
	p, err := m.PlanConfigure(context.Background(), ConfigureOptions{IdentityCert: true, TLSCert: true, License: true, CommunityString: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Blockers) != 4 || !strings.Contains(strings.Join(p.Blockers, " "), "-host <host>") {
		t.Fatalf("blockers = %v", p.Blockers)
	}
}

func TestCNOf(t *testing.T) {
	for in, want := range map[string]string{
		"CN=fm.example.net,O=Example": "fm.example.net",
		"CN = Corelight FM, O = X":    "Corelight FM",
		"O=No Common Name":            "O=No Common Name",
	} {
		if got := cnOf(in); got != want {
			t.Errorf("cnOf(%q) = %q", in, got)
		}
	}
}

const upgradeOut = `installed=install ok installed|29.2.1-16524281181
datapath=/var/lib/corelight-fleetd
free=/ 40000
free=/var/lib/corelight-fleetd 40000
active=active
aptupdate=ok
available=29.2.2-16847904621
available=29.2.1-16524281181
available=29.2.0-16269045676
`

func TestUpgradePlan(t *testing.T) {
	cmp := func(out string) rule { return rule{match: "dpkg --compare-versions", stdout: out} }
	r := &ruleRunner{rules: []rule{{match: "apt-cache madison", stdout: upgradeOut}, cmp("1\n")}}
	u := &Upgrader{R: r, StartBackup: func(context.Context) error { return nil }}
	p, err := u.Plan(context.Background(), UpgradeOptions{Backup: true})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Ready() || p.Target != "29.2.2-16847904621" || p.Downgrade || len(p.Steps) != 4 {
		t.Fatalf("plan = %+v", p)
	}

	r.rules[1] = cmp("-1\n")
	p, _ = u.Plan(context.Background(), UpgradeOptions{Version: "29.2.0", Backup: true})
	if p.Ready() || !p.Downgrade || p.Target != "29.2.0-16269045676" {
		t.Fatalf("downgrade plan = %+v", p)
	}
	p, _ = u.Plan(context.Background(), UpgradeOptions{Version: "29.2.0", AllowDowngrade: true, Backup: true})
	if !p.Ready() {
		t.Fatalf("allowed downgrade = %+v", p)
	}

	p, _ = u.Plan(context.Background(), UpgradeOptions{Version: "29.2.1"})
	if p.Ready() || len(p.Blockers) != 0 {
		t.Fatalf("same version = %+v", p)
	}
	p, _ = u.Plan(context.Background(), UpgradeOptions{Version: "30"})
	if p.Ready() || len(p.Blockers) != 1 {
		t.Fatalf("missing version = %+v", p)
	}

	r.rules[0].stdout = strings.Replace(strings.Replace(upgradeOut, "free=/ 40000", "free=/ 900", 1), "aptupdate=ok", "aptupdate=failed: E: 401 Unauthorized", 1)
	r.rules[1] = cmp("1\n")
	u.StartBackup = nil
	p, _ = u.Plan(context.Background(), UpgradeOptions{Backup: true})
	if len(p.Blockers) != 3 {
		t.Fatalf("blockers = %v", p.Blockers)
	}
}

func TestPickVersion(t *testing.T) {
	avail := []string{"29.2.20-1", "29.2.2-16847904621", "29.1.5-1"}
	for want, got := range map[string]string{"": "29.2.20-1", "29.2.2": "29.2.2-16847904621", "29.1": "29.1.5-1", "29.2.2-16847904621": "29.2.2-16847904621", "28": ""} {
		if v := pickVersion(avail, want); v != got {
			t.Errorf("pickVersion(%q) = %q, want %q", want, v, got)
		}
	}
}

func TestUpgradeApply(t *testing.T) {
	r := &ruleRunner{rules: []rule{
		{match: "date +%s", stdout: "1760000000\n"},
		{match: "fleet_backup_", stdout: "/var/lib/corelight-fleetd/backup/fleet_backup_fm_2026.zip 5242880\n"},
		{match: "apt-get install", stdout: "api up after 5x2s\n"},
		{match: "dpkg-query", stdout: "install ok installed|29.2.2-16847904621"},
	}}
	started := false
	u := &Upgrader{R: r, StartBackup: func(context.Context) error { started = true; return nil }}
	p := &UpgradePlan{Installed: "29.2.1-16524281181", Target: "29.2.2-16847904621", Backup: true, DataPath: "/var/lib/corelight-fleetd"}
	res, err := u.Apply(context.Background(), p)
	if err != nil || !started || res.Version != p.Target || !strings.Contains(res.Backup, "(5 MB)") {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if s := r.scripts[2]; !strings.Contains(s, "--force-confold") || strings.Contains(s, "--allow-downgrades") {
		t.Fatalf("install script:\n%s", s)
	}
}

func TestFailReason(t *testing.T) {
	stderr := "the web API did not come up within 120s\n× corelight-fleetd.service\n" +
		"Oct 16 14:04:22 fm corelight-fleetd[1]: {\"level\":\"ERROR\",\"message\":\"PROCESS IS EXITING\"}\n" +
		"Oct 16 14:04:22 fm corelight-fleetd[1]: ERROR: /etc/corelight-fleetd.conf: unable to read file /etc/x.pem\n" +
		"Oct 16 14:04:22 fm systemd[1]: corelight-fleetd.service: Failed with result 'exit-code'.\n"
	if got := failReason(stderr); got != "/etc/corelight-fleetd.conf: unable to read file /etc/x.pem" {
		t.Fatalf("failReason = %q", got)
	}
	if got := failReason("plain\nmore"); got != "plain" {
		t.Fatalf("failReason = %q", got)
	}
}

func TestPlanConfigureMissingPath(t *testing.T) {
	r := &ruleRunner{rules: []rule{{match: "cat " + confPath, stdout: sampleConf}, {match: "test -e '/etc/there.pem'", stdout: "yes\n"}}}
	m := &Maintainer{R: r, Secrets: newStore(t), Host: "198.51.100.7"}
	p, err := m.PlanConfigure(context.Background(), ConfigureOptions{Settings: map[string]any{"ssl-key-path": "/etc/missing.pem", "ssl-certificate-path": "/etc/there.pem"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Blockers) != 1 || !strings.Contains(p.Blockers[0], "/etc/missing.pem does not exist") || len(p.Changes) != 1 {
		t.Fatalf("plan = %+v", p)
	}
}
