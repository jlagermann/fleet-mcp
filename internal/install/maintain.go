package install

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/host"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
)

// Paths on an installed Fleet Manager host.
const (
	// licensePath is where corelight-fleetd looks for a Software Sensor
	// license by default; it is read at start.
	licensePath = "/etc/corelight-fleet-license.txt"
	// tlsPath holds a web certificate installed by fleet-mcp.
	tlsPath = "/etc/corelight-fleetd-tls.pem"
)

// ConfigureOptions are changes to an installed Fleet Manager host. Files and
// secrets come from fleet-mcp's secret store, never from the chat.
type ConfigureOptions struct {
	Settings        map[string]any `json:"settings,omitempty"`
	CommunityString bool           `json:"community_string,omitempty"`
	IdentityCert    bool           `json:"identity_cert,omitempty"`
	TLSCert         bool           `json:"tls_cert,omitempty"`
	License         bool           `json:"license,omitempty"`
}

// Change is one line of a preview.
type Change struct {
	Item string `json:"item"`
	From string `json:"from"`
	To   string `json:"to"`
	Note string `json:"note,omitempty"`
}

// ConfigurePlan is what a configure will do; its exported fields are the
// preview.
type ConfigurePlan struct {
	Host     string   `json:"host"`
	Changes  []Change `json:"changes"`
	Steps    []string `json:"steps,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Blockers []string `json:"blockers,omitempty"`

	conf    map[string]any
	confChg bool
	files   []fileWrite
	repin   bool
	secrets []string
	state   string
}

type fileWrite struct {
	path, content, mode, owner, what string
}

// Ready reports whether there is a change and nothing blocks it.
func (p *ConfigurePlan) Ready() bool { return len(p.Blockers) == 0 && len(p.Changes) > 0 }

// State identifies what the plan was built from (the configuration and
// the files it replaces), so a confirm token goes stale when they change.
func (p *ConfigurePlan) State() string { return p.state }

// Maintainer changes an installed Fleet Manager host.
type Maintainer struct {
	R       host.Runner
	Secrets *secrets.Store
	// Host is the name the host's secrets and profile are stored under.
	Host string
}

// knownSettings are corelight-fleetd.conf paths and their value types.
var knownSettings = map[string]string{
	"log-level": "string", "expose-swagger": "bool", "development-mode": "bool",
	"auth/skip-role-restrictions": "bool", "auth/plugins/ldap/config-file-path": "string",
	"messaging/http-options/bind-address": "string", "messaging/http-options/certificate-path": "string",
	"messaging/http-options/key-path": "string", "ssl-certificate-path": "string", "ssl-key-path": "string",
	"tacacs-plus/enable": "bool", "tacacs-plus/server": "string",
}

// secretSettings are never set from tool arguments.
var secretSettings = map[string]bool{"messaging/community-string": true, "tacacs-plus/shared-secret": true}

var logLevels = map[string]bool{"DEBUG": true, "INFO": true, "WARN": true, "WARNING": true, "ERROR": true}

func getPath(conf map[string]any, path string) (any, bool) {
	cur := any(conf)
	for _, k := range strings.Split(path, "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[k]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// setPath sets a value, creating parent objects; nil deletes the key.
func setPath(conf map[string]any, path string, v any) {
	parts := strings.Split(path, "/")
	m := conf
	for _, k := range parts[:len(parts)-1] {
		next, ok := m[k].(map[string]any)
		if !ok {
			if v == nil {
				return
			}
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
	if v == nil {
		delete(m, parts[len(parts)-1])
		return
	}
	m[parts[len(parts)-1]] = v
}

func showVal(v any, ok bool) string {
	if !ok || v == nil {
		return "(not set)"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// PlanConfigure builds the plan. It reads the host and the secret store
// and changes nothing.
func (m *Maintainer) PlanConfigure(ctx context.Context, o ConfigureOptions) (*ConfigurePlan, error) {
	res, err := m.R.Run(ctx, "cat "+confPath)
	if err != nil {
		return nil, err
	}
	if !res.OK() {
		return nil, fmt.Errorf("reading %s: %s (is Fleet Manager installed?)", confPath, strings.TrimSpace(res.Stderr))
	}
	var conf map[string]any
	if err := json.Unmarshal([]byte(res.Stdout), &conf); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", confPath, err)
	}
	p := &ConfigurePlan{Host: m.R.Name(), conf: conf}
	state := []string{sha(res.Stdout)}
	block := func(f string, a ...any) { p.Blockers = append(p.Blockers, fmt.Sprintf(f, a...)) }
	warn := func(f string, a ...any) { p.Warnings = append(p.Warnings, fmt.Sprintf(f, a...)) }

	keys := make([]string, 0, len(o.Settings))
	for k := range o.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		path := strings.Trim(strings.ReplaceAll(k, ".", "/"), "/")
		v := o.Settings[k]
		if path == "" {
			block("empty setting name")
			continue
		}
		if secretSettings[path] {
			block("%s is a secret and is not set from the chat; for the community string use community_string with the value stored by: %s", path, secrets.Command("secret", "set", secrets.CommunityString, "-host", m.Host))
			continue
		}
		if path == "data-path" {
			block("data-path is where Fleet Manager keeps all its data; moving it means moving the data by hand with the service stopped, which fleet-mcp does not do")
			continue
		}
		if _, isObj := v.(map[string]any); isObj {
			block("%s: give each value by its full path (e.g. messaging/http-options/bind-address), not an object", path)
			continue
		}
		typ, known := knownSettings[path]
		if !known {
			p.Warnings = append(p.Warnings, path+" is not a setting fleet-mcp knows; if Fleet Manager does not start with it, the change is rolled back")
		}
		if v != nil {
			switch typ {
			case "bool":
				if _, ok := v.(bool); !ok {
					block("%s takes true or false", path)
					continue
				}
			case "string":
				s, ok := v.(string)
				if !ok {
					block("%s takes a string", path)
					continue
				}
				if path == "log-level" {
					if !logLevels[strings.ToUpper(s)] {
						block("log-level must be DEBUG, INFO, WARN or ERROR")
						continue
					}
					v = strings.ToUpper(s)
				}
			}
		}
		if s, isStr := v.(string); isStr && strings.HasSuffix(path, "-path") {
			res, err := m.R.Run(ctx, "test -e "+host.Quote(s)+" && echo yes || echo no")
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(res.Stdout) != "yes" {
				block("%s: %s does not exist on the host", path, s)
				continue
			}
		}
		cur, ok := getPath(conf, path)
		if (v == nil && !ok) || (ok && v != nil && showVal(cur, true) == showVal(v, true)) {
			continue
		}
		note := ""
		switch path {
		case "development-mode":
			note = "meant for testing Fleet Manager itself, not for production"
		case "expose-swagger":
			note = "serves the REST API description (login required); fleet-mcp's fm_api_describe uses it"
		case "messaging/http-options/bind-address":
			note = "the address and port sensors connect to; sensors set up for the old port lose their connection"
		case "log-level":
			note = "DEBUG logs a lot; set it back when done"
		}
		if path == "ssl-certificate-path" || path == "ssl-key-path" {
			p.repin = true
		}
		setPath(conf, path, v)
		p.confChg = true
		p.Changes = append(p.Changes, Change{Item: path, From: showVal(cur, ok), To: showVal(v, v != nil), Note: note})
	}

	if o.CommunityString {
		cs, err := m.Secrets.GetString(m.Host, secrets.CommunityString)
		if err == nil {
			err = secrets.ValidateCommunityString(cs)
		}
		switch cur, _ := getPath(conf, "messaging/community-string"); {
		case err != nil:
			block("community string: %v", err)
		case cur == cs:
			warn("the stored community string is already in use")
		default:
			setPath(conf, "messaging/community-string", cs)
			p.confChg = true
			p.secrets = append(p.secrets, cs)
			p.Changes = append(p.Changes, Change{Item: "messaging/community-string", From: "(current value)", To: "(the value stored for this host)",
				Note: "sensors keep the old one and cannot connect until each is given the new one (fm_sensor_fleet attach on this same Fleet Manager)"})
			warn("changing the community string disconnects every sensor of this Fleet Manager until each is given the new one")
		}
	}

	certPath := valueOr(conf, "messaging/http-options/certificate-path", identityPath)
	tlsCur := valueOr(conf, "ssl-certificate-path", identityPath)

	if o.IdentityCert {
		b, err := m.Secrets.Get("", secrets.IdentityCert)
		var sum *secrets.CertSummary
		if err == nil {
			sum, err = secrets.ValidateIdentityCert(b)
		}
		if err != nil {
			block("identity certificate: %v", err)
		} else {
			cur, err := m.certSummary(ctx, certPath)
			if err != nil {
				return nil, err
			}
			state = append(state, cur.sha)
			if cur.sha == sha(string(b)) {
				warn("the stored identity certificate is already installed at %s", certPath)
			} else {
				newCN := cnOf(sum.Subject)
				if cur.cn != "" && cur.cn != newCN {
					warn("the new identity certificate is for %s, the installed one for %s: sensors check this name when they connect, so make sure it is the right certificate", newCN, cur.cn)
				}
				if sum.DaysLeft < 30 {
					warn("the stored identity certificate expires on %s", sum.NotAfter.Format("2006-01-02"))
				}
				p.files = append(p.files, fileWrite{path: certPath, content: string(b), mode: "0400", owner: "corelight-fleetd:corelight-fleetd", what: "product identity certificate"})
				p.Changes = append(p.Changes, Change{Item: "product identity certificate " + certPath, From: cur.describe(),
					To: fmt.Sprintf("%s, expires %s", newCN, sum.NotAfter.Format("2006-01-02")), Note: "carries the Fleet Manager license; read at start"})
				if tlsCur == certPath && !o.TLSCert {
					p.repin = true
					warn("this host also serves the identity certificate on its web interface: browsers and API clients will see the new one")
				}
			}
		}
	}

	if o.TLSCert {
		b, err := m.Secrets.Get(m.Host, secrets.TLSCert)
		var sum *secrets.CertSummary
		if err == nil {
			sum, err = secrets.ValidateTLSCert(b)
		}
		if err != nil {
			block("TLS certificate: %v", err)
		} else {
			cur, err := m.certSummary(ctx, tlsCur)
			if err != nil {
				return nil, err
			}
			state = append(state, cur.sha)
			if cur.sha == sha(string(b)) {
				warn("the stored TLS certificate is already installed at %s", tlsCur)
			} else {
				p.files = append(p.files, fileWrite{path: tlsPath, content: string(b), mode: "0400", owner: "corelight-fleetd:corelight-fleetd", what: "web certificate and key"})
				for _, k := range []string{"ssl-certificate-path", "ssl-key-path"} {
					if v, _ := getPath(conf, k); v != tlsPath {
						setPath(conf, k, tlsPath)
						p.confChg = true
					}
				}
				names := append(append([]string{}, sum.DNSNames...), sum.IPAddresses...)
				p.Changes = append(p.Changes, Change{Item: "web interface and API certificate (" + tlsPath + ")", From: cur.describe(),
					To:   fmt.Sprintf("%s (names: %s), issued by %s, expires %s", cnOf(sum.Subject), strings.Join(names, ", "), cnOf(sum.Issuer), sum.NotAfter.Format("2006-01-02")),
					Note: "sensors are not affected: they connect on port 1443 with the identity certificate"})
				// Keep sensor connections (port 1443) on the identity
				// certificate: name it explicitly so it never follows the
				// web certificate.
				for _, k := range []string{"messaging/http-options/certificate-path", "messaging/http-options/key-path"} {
					if _, ok := getPath(conf, k); !ok {
						setPath(conf, k, certPath)
						p.Changes = append(p.Changes, Change{Item: k, From: "(not set)", To: showVal(certPath, true), Note: "keeps sensor connections on the identity certificate"})
					}
				}
				p.repin = true
				if !containsFold(names, m.Host) {
					warn("the certificate's names (%s) do not include %s, the name fleet-mcp connects to", strings.Join(names, ", "), m.Host)
				}
				if tlsCur == certPath {
					warn("the web interface used the identity certificate until now; afterwards it uses this one, and the identity certificate stays for sensor connections")
				}
			}
		}
	}

	if o.License {
		b, err := m.Secrets.Get("", secrets.SensorLicense)
		if err == nil && strings.TrimSpace(string(b)) == "" {
			err = fmt.Errorf("the stored license file is empty")
		}
		if err != nil {
			block("license: %v", err)
		} else {
			res, err := m.R.Run(ctx, "test -f "+licensePath+" && sha256sum "+licensePath+" | cut -d' ' -f1 || true")
			if err != nil {
				return nil, err
			}
			got := strings.TrimSpace(res.Stdout)
			state = append(state, got)
			if got == sha(string(b)) {
				warn("the stored license is already installed")
			} else {
				from := "none"
				if got != "" {
					from = "a different license"
				}
				p.files = append(p.files, fileWrite{path: licensePath, content: string(b), mode: "0640", owner: "root:corelight-fleetd", what: "Software Sensor license"})
				p.Changes = append(p.Changes, Change{Item: "Software Sensor license " + licensePath, From: from, To: "the stored license", Note: "read at start"})
			}
		}
	}

	if len(p.Changes) > 0 {
		for _, f := range p.files {
			p.Steps = append(p.Steps, fmt.Sprintf("back up %s (root-only copy) and install the %s", f.path, f.what))
		}
		if p.confChg {
			p.Steps = append(p.Steps, "back up "+confPath+" (root-only copy) and write the new configuration")
		}
		p.Steps = append(p.Steps, "restart corelight-fleetd and wait up to 2 minutes for its API; the web interface is down meanwhile and sensors reconnect on their own",
			"if it does not come up: restore the backups and restart again")
		if p.repin {
			p.Steps = append(p.Steps, "update the certificate fleet-mcp pins for this Fleet Manager (only for Fleet Managers fleet-mcp installed)")
		}
	}
	p.state = sha(strings.Join(state, "|"))
	return p, nil
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func valueOr(conf map[string]any, path, def string) string {
	v, _ := getPath(conf, path)
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

var cnPattern = regexp.MustCompile(`CN\s*=\s*([^,/]+)`)

// cnOf returns the common name of an X.509 subject in Go or openssl form.
func cnOf(subject string) string {
	if m := cnPattern.FindStringSubmatch(subject); m != nil {
		return strings.TrimSpace(m[1])
	}
	return subject
}

type certInfo struct {
	sha, cn, notAfter string
}

func (c certInfo) describe() string {
	if c.sha == "" {
		return "none"
	}
	if c.cn == "" {
		return "a file that is not a readable certificate"
	}
	return fmt.Sprintf("%s, expires %s", c.cn, c.notAfter)
}

// certSummary describes a certificate file on the host without copying
// it here (the file holds a private key).
func (m *Maintainer) certSummary(ctx context.Context, path string) (certInfo, error) {
	q := host.Quote(path)
	res, err := m.R.Run(ctx, "test -f "+q+" || exit 0\nsha256sum "+q+" | cut -d' ' -f1\nopenssl x509 -noout -subject -enddate -in "+q+" 2>/dev/null || true")
	if err != nil {
		return certInfo{}, err
	}
	return parseCertSummary(res.Stdout), nil
}

func parseCertSummary(out string) certInfo {
	var c certInfo
	for i, l := range strings.Split(strings.TrimSpace(out), "\n") {
		switch {
		case i == 0:
			c.sha = strings.TrimSpace(l)
		case strings.HasPrefix(l, "subject="):
			c.cn = cnOf(strings.TrimPrefix(l, "subject="))
		case strings.HasPrefix(l, "notAfter="):
			if t, err := time.Parse("Jan _2 15:04:05 2006 MST", strings.TrimSpace(strings.TrimPrefix(l, "notAfter="))); err == nil {
				c.notAfter = t.Format("2006-01-02")
			}
		}
	}
	return c
}

// ConfigureResult is what a configure did.
type ConfigureResult struct {
	Done       []string `json:"done"`
	Backups    []string `json:"backups,omitempty"`
	RolledBack bool     `json:"rolled_back,omitempty"`
	Pin        string   `json:"new_pinned_certificate,omitempty"`
}

// ApplyConfigure backs up, writes, restarts and waits; when the service does
// not come back it restores the backups and restarts again.
func (m *Maintainer) ApplyConfigure(ctx context.Context, p *ConfigurePlan) (*ConfigureResult, error) {
	if !p.Ready() {
		return nil, fmt.Errorf("nothing to change, or blocked: %s", strings.Join(p.Blockers, "; "))
	}
	out := &ConfigureResult{}
	stamp := time.Now().UTC().Format("20060102-150405")
	type pair struct{ orig, bak string }
	var backups []pair
	var b strings.Builder
	backup := func(path string) {
		bk := path + ".bak-" + stamp
		backups = append(backups, pair{path, bk})
		out.Backups = append(out.Backups, bk)
		q, qb := host.Quote(path), host.Quote(bk)
		fmt.Fprintf(&b, "if [ -f %s ]; then cp -p %s %s && chown root:root %s && chmod 600 %s; fi\n", q, q, qb, qb, qb)
	}
	for _, f := range p.files {
		backup(f.path)
		b.WriteString(writeFileScript(f.path, f.content, f.mode, f.owner))
	}
	if p.confChg {
		mode, owner := m.fileMode(ctx, confPath)
		data, _ := json.MarshalIndent(p.conf, "", "   ")
		backup(confPath)
		b.WriteString(writeFileScript(confPath, string(data)+"\n", mode, owner))
	}
	b.WriteString("systemctl restart " + serviceName + "\n")
	res, err := m.R.Run(ctx, "set -e\n"+b.String()+waitScript, p.secrets...)
	if err == nil && res.OK() {
		out.Done = append(out.Done, "installed the changes and restarted corelight-fleetd ("+lastLine(res.Stdout)+")")
	} else {
		reason := ""
		if err != nil {
			reason = err.Error()
		} else {
			reason = failReason(res.Stderr)
		}
		// Roll back: copy each backup over the new file (cp onto an
		// existing file keeps that file's owner and mode); a file that did
		// not exist before is removed.
		var rb strings.Builder
		for _, bk := range backups {
			q, qb := host.Quote(bk.orig), host.Quote(bk.bak)
			fmt.Fprintf(&rb, "if [ -f %s ]; then cp %s %s; else rm -f %s; fi\n", qb, qb, q, q)
		}
		rb.WriteString("systemctl restart " + serviceName + "\n" + waitScript)
		rbRes, rbErr := m.R.Run(context.WithoutCancel(ctx), rb.String())
		out.RolledBack = true
		if rbErr != nil || !rbRes.OK() {
			return out, fmt.Errorf("corelight-fleetd did not come up with the change (%s), and not after restoring the backups either: check the host now (backups end in .bak-%s)", reason, stamp)
		}
		return out, fmt.Errorf("corelight-fleetd did not come up with the change (%s); the backups were restored and Fleet Manager is running again", reason)
	}
	if p.repin {
		pin, err := m.repin(ctx)
		switch {
		case err != nil:
			out.Done = append(out.Done, "could not update the pinned certificate: "+err.Error())
		case pin != "":
			out.Pin = pin
			out.Done = append(out.Done, "fleet-mcp now pins the new certificate for this Fleet Manager")
		}
	}
	return out, nil
}

// fileMode returns a file's mode and owner:group for rewriting it, never
// readable by every user; the default is the installer's 0640
// root:corelight-fleetd.
func (m *Maintainer) fileMode(ctx context.Context, path string) (string, string) {
	res, err := m.R.Run(ctx, "stat -c '%a %U:%G' "+host.Quote(path)+" 2>/dev/null || true")
	if err == nil {
		if f := strings.Fields(res.Stdout); len(f) == 2 && len(f[0]) == 3 {
			return "0" + f[0][:2] + "0", f[1]
		}
	}
	return "0640", "root:corelight-fleetd"
}

// failReason picks corelight-fleetd's own error from the journal lines the
// wait script prints, else the first line.
func failReason(stderr string) string {
	lines := strings.Split(stderr, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if _, msg, ok := strings.Cut(lines[i], "]: ERROR: "); ok {
			return strings.TrimSpace(msg)
		}
	}
	return firstLine(stderr)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// repin updates the certificate pinned in the host's fleet-mcp profile.
// Only Fleet Managers fleet-mcp installed have a profile; others are
// trusted however fleets.json says, and are left alone.
func (m *Maintainer) repin(ctx context.Context) (string, error) {
	prof, err := ReadProfile(m.Secrets, m.Host)
	if err != nil {
		return "", nil
	}
	res, err := m.R.Run(ctx, "echo | openssl s_client -connect 127.0.0.1:443 2>/dev/null | openssl x509 -noout -fingerprint -sha256")
	if err != nil {
		return "", err
	}
	pin, err := fleet.NormalizeFingerprint(res.Stdout)
	if err != nil {
		return "", err
	}
	if pin == prof.CertSHA256 {
		return "", nil
	}
	prof.CertSHA256, prof.Written = pin, time.Now().UTC()
	dir, err := m.Secrets.HostDir(m.Host)
	if err != nil {
		return "", err
	}
	data, _ := json.MarshalIndent(prof, "", "  ")
	return pin, os.WriteFile(filepath.Join(dir, "profile.json"), data, 0o600)
}
