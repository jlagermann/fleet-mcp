package install

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/jlagermann/fleet-mcp/internal/host"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
)

// Paths and names from the Fleet Manager installation guide.
const (
	keyringPath  = "/etc/apt/keyrings/corelight_fleet-stable-archive-keyring.gpg"
	sourcesPath  = "/etc/apt/sources.list.d/corelight_fleet-stable.list"
	authConfPath = "/etc/apt/auth.conf.d/corelight_fleet-stable.conf"
	repoBase     = "https://pkgrepos.corelight.cloud/corelight/fleet-stable/any/"
	repoKeyURL   = "https://pkgrepos.corelight.cloud/corelight/fleet-stable/gpgkey"
	confPath     = "/etc/corelight-fleetd.conf"
	identityPath = "/etc/corelight-fleetd.pem"
	serviceName  = "corelight-fleetd"
	fleetdBin    = "/usr/bin/corelight-fleetd"
	pkgName      = "corelight-fleet"
)

var sourcesList = fmt.Sprintf("deb [signed-by=%s] %s any main\n\ndeb-src [signed-by=%s] %s any main\n", keyringPath, repoBase, keyringPath, repoBase)

// Options for an installation.
type Options struct {
	// Version pins corelight-fleet, e.g. "29.2.2" (prefix match); empty
	// installs the newest.
	Version string `json:"version,omitempty"`
	// ExposeSwagger sets "expose-swagger" in corelight-fleetd.conf. It
	// defaults to true: without it Fleet Manager serves no REST API spec
	// (GraphQL introspection works either way), and fleet-mcp uses the
	// spec to describe and check API calls.
	ExposeSwagger *bool `json:"expose_swagger,omitempty"`
	// MCPUser is the local Fleet Manager user created for fleet-mcp.
	MCPUser string `json:"agent_user"`
	// URL Fleet Manager is reached at from this machine; default
	// https://<host>.
	URL string `json:"url,omitempty"`
}

// DefaultAgentUser is the Fleet Manager user created for the agent.
const DefaultAgentUser = "claude"

var versionPattern = regexp.MustCompile(`^[0-9][0-9A-Za-z.+~-]*$`)
var userPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$`)

// Validate checks the options.
func (o *Options) Validate() error {
	if o.Version != "" && !versionPattern.MatchString(o.Version) {
		return fmt.Errorf("bad version %q", o.Version)
	}
	if o.ExposeSwagger == nil {
		yes := true
		o.ExposeSwagger = &yes
	}
	if o.MCPUser == "" {
		o.MCPUser = DefaultAgentUser
	}
	if !userPattern.MatchString(o.MCPUser) || strings.EqualFold(o.MCPUser, "admin") {
		return fmt.Errorf("bad agent_user %q (letters, digits, . _ -, not \"admin\")", o.MCPUser)
	}
	return nil
}

// State of a step.
type State string

const (
	Done    State = "done"
	Pending State = "pending"
	Blocked State = "blocked"
	Failed  State = "failed"
	Skipped State = "skipped"
)

// StepStatus is a step's state in a plan or run.
type StepStatus struct {
	Step   string `json:"step"`
	What   string `json:"what"`
	State  State  `json:"state"`
	Detail string `json:"detail,omitempty"`
}

type step struct {
	name, what string
	check      func(ctx context.Context) (State, string, error)
	apply      func(ctx context.Context) (string, error)
}

// Installer installs Fleet Manager on one host.
type Installer struct {
	R       host.Runner
	Secrets *secrets.Store
	Host    string // secrets key and default URL host
	Opts    Options
	// Bootstrap performs the API part (admin password, MCP user). It is
	// supplied by the caller so this package stays free of HTTP details.
	Bootstrap Bootstrapper

	// AdminTempPassword is set when Execute creates the admin user. It is
	// temporary: Fleet Manager requires a change at first login.
	AdminTempPassword string

	restartNeeded bool
	steps         []step
}

// Bootstrapper finishes setup through the Fleet Manager API.
type Bootstrapper interface {
	// MCPUserReady reports whether the stored MCP user password logs in.
	MCPUserReady(ctx context.Context, in *Installer) (bool, string)
	// ActivateMCPUser replaces the MCP user's temporary password with a
	// generated one and stores it.
	ActivateMCPUser(ctx context.Context, in *Installer, tempPassword string) error
	// AdminExists reports, using the MCP user, whether the admin user exists.
	AdminExists(ctx context.Context, in *Installer) (bool, error)
}

// URL returns the Fleet Manager web URL.
func (in *Installer) URL() string {
	if in.Opts.URL != "" {
		return strings.TrimRight(in.Opts.URL, "/")
	}
	return "https://" + in.Host
}

func (in *Installer) run(ctx context.Context, script string, secretVals ...string) (*host.Result, error) {
	return in.R.Run(ctx, "set -e\n"+script, secretVals...)
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// remoteSHA returns the sha256 of a remote file, or "" if it is missing.
func (in *Installer) remoteSHA(ctx context.Context, path string) (string, error) {
	res, err := in.R.Run(ctx, "test -f "+host.Quote(path)+" && sha256sum "+host.Quote(path)+" | cut -d' ' -f1 || true")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(res.Stdout), nil
}

// writeFile installs content at path with mode and owner. content is sent
// base64-encoded inside the script.
func writeFileScript(path, content, mode, owner string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(content))
	// Wrap the base64 so lines stay short.
	var b strings.Builder
	for i := 0; i < len(enc); i += 76 {
		end := min(i+76, len(enc))
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	// The pipe belongs on the heredoc's first line; the end marker must
	// stay alone on its own line.
	h := host.Heredoc(b.String())
	nl := strings.IndexByte(h, '\n')
	h = h[:nl] + ` | base64 -d > "$tmp"` + h[nl:]
	user, group, _ := strings.Cut(owner, ":")
	return fmt.Sprintf("tmp=$(mktemp)\n%sinstall -m %s -o %s -g %s \"$tmp\" %s\nrm -f \"$tmp\"\necho %s | sha256sum -c --quiet || { echo 'written file does not match' >&2; exit 1; }\n",
		h, mode, user, group, host.Quote(path), host.Quote(sha(content)+"  "+path))
}

// Generate returns a random password: letters, digits and a few symbols,
// with at least one of each class and no spaces or quotes.
func Generate(n int, symbols bool) string {
	const lower, upper, digits, syms = "abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#%^*-_=+"
	classes := []string{lower, upper, digits}
	if symbols {
		classes = append(classes, syms)
	}
	all := strings.Join(classes, "")
	pick := func(set string) byte {
		i, _ := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		return set[i.Int64()]
	}
	out := make([]byte, 0, n)
	for _, c := range classes {
		out = append(out, pick(c))
	}
	for len(out) < n {
		out = append(out, pick(all))
	}
	// Shuffle so the class characters are not always first.
	for i := len(out) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}
	return string(out)
}

func (in *Installer) build() {
	in.steps = []step{
		{"readiness", "check the host meets Fleet Manager's requirements (supported OS, CPUs, memory, disk, free ports, repository access); any failure or resource warning stops the install", in.checkReadiness, nil},
		{"prerequisites", "install curl, gnupg and apt-transport-https", in.checkPrereqs, in.applyPrereqs},
		{"repo_key", "download the Corelight Fleet repository signing key to " + keyringPath, in.checkKey, in.applyKey},
		{"repo_source", "write " + sourcesPath, in.checkSources, in.applySources},
		{"repo_auth", "write the repository token to " + authConfPath + " (mode 0600)", in.checkAuth, in.applyAuth},
		{"package", "install " + pkgName + versionNote(in.Opts.Version), in.checkPackage, in.applyPackage},
		{"identity_cert", "install the product identity certificate at " + identityPath + " (owner corelight-fleetd, mode 0400)", in.checkIdentity, in.applyIdentity},
		{"config", "set the sensor community-string" + swaggerNote(in.Opts.ExposeSwagger) + " in " + confPath + " (backup first)", in.checkConfig, in.applyConfig},
		{"service", "enable and (re)start " + serviceName + " and wait for the web API", in.checkService, in.applyService},
		{"agent_user", "create the local Fleet Manager admin user \"" + in.Opts.MCPUser + "\" that the agent (fleet-mcp) logs in as (corelight-fleetd create-user; its temporary password is replaced by a generated one stored only for fleet-mcp; an existing user of that name has its password reset)", in.checkMCPUser, in.applyMCPUser},
		{"admin", "create the \"admin\" user with a temporary password returned to you; Fleet Manager requires changing it at first login (an existing admin is left untouched)", in.checkAdmin, in.applyAdmin},
	}
}

func versionNote(v string) string {
	if v == "" {
		return " (newest)"
	}
	return " " + v
}

func swaggerNote(b *bool) string {
	switch {
	case b == nil:
		return ""
	case *b:
		return " and expose-swagger: true"
	default:
		return " and remove expose-swagger"
	}
}

// Plan checks every step without changing anything.
func (in *Installer) Plan(ctx context.Context) ([]StepStatus, error) {
	if err := in.Opts.Validate(); err != nil {
		return nil, err
	}
	in.build()
	var out []StepStatus
	blocked := false
	for _, s := range in.steps {
		st := StepStatus{Step: s.name, What: s.what}
		if blocked {
			st.State, st.Detail = Pending, "after earlier steps"
			out = append(out, st)
			continue
		}
		state, detail, err := s.check(ctx)
		if err != nil {
			return out, fmt.Errorf("%s: %w", s.name, err)
		}
		st.State, st.Detail = state, detail
		if state == Blocked {
			blocked = true
		}
		// A pending package, certificate or config change restarts the
		// service when executed; show the service step as pending too.
		if state == Pending && (s.name == "package" || s.name == "identity_cert" || s.name == "config") {
			in.restartNeeded = true
		}
		// Later checks depend on the package being installed.
		// Later checks need the package installed and the service running;
		// a running service that only needs a restart does not block them.
		if state == Pending && (s.name == "package" || (s.name == "service" && !in.restartNeeded)) {
			blocked = true
		}
		out = append(out, st)
	}
	return out, nil
}

// Execute runs every step that is not done, in order, and stops at the
// first failure.
func (in *Installer) Execute(ctx context.Context) ([]StepStatus, error) {
	if err := in.Opts.Validate(); err != nil {
		return nil, err
	}
	in.build()
	var out []StepStatus
	for i, s := range in.steps {
		st := StepStatus{Step: s.name, What: s.what}
		state, detail, err := s.check(ctx)
		if err != nil {
			st.State, st.Detail = Failed, err.Error()
			return append(out, st), fmt.Errorf("%s: %w", s.name, err)
		}
		if state == Done {
			st.State, st.Detail = Done, detail
			out = append(out, st)
			continue
		}
		if state == Blocked || s.apply == nil {
			st.State, st.Detail = Blocked, detail
			out = append(out, st)
			for _, rest := range in.steps[i+1:] {
				out = append(out, StepStatus{Step: rest.name, What: rest.what, State: Skipped})
			}
			return out, fmt.Errorf("%s: %s", s.name, detail)
		}
		applied, err := s.apply(ctx)
		if err == nil {
			// Never trust an apply on its own: the step's check must now
			// pass, or the step failed.
			var after State
			var why string
			after, why, err = s.check(ctx)
			if err == nil && after != Done {
				err = fmt.Errorf("the change reported success but the check still says %s: %s", after, why)
			}
		}
		if err != nil {
			st.State, st.Detail = Failed, err.Error()
			out = append(out, st)
			for _, rest := range in.steps[i+1:] {
				out = append(out, StepStatus{Step: rest.name, What: rest.what, State: Skipped})
			}
			return out, fmt.Errorf("%s: %w", s.name, err)
		}
		st.State, st.Detail = Done, applied
		out = append(out, st)
	}
	return out, nil
}

// --- steps ---

// blockingWarnings are readiness warnings that stop an install: resources
// below the documented minimums, and an OS the installer cannot automate.
var blockingWarnings = map[string]bool{
	"os": true, "cpus": true, "memory": true, "var_space": true, "tmp_space": true, "shared_space": true,
}

// Blocking returns the findings that stop an install.
func Blocking(rep *Report) []Finding {
	var out []Finding
	for _, f := range rep.Findings {
		if f.Level == Fail || (f.Level == Warn && blockingWarnings[f.Check]) {
			out = append(out, f)
		}
	}
	return out
}

func (in *Installer) checkReadiness(ctx context.Context) (State, string, error) {
	rep, err := Check(ctx, in.R)
	if err != nil {
		return "", "", err
	}
	if blocking := Blocking(rep); len(blocking) > 0 {
		msgs := make([]string, len(blocking))
		for i, f := range blocking {
			msgs[i] = f.Check + ": " + f.Detail
		}
		return Blocked, strings.Join(msgs, "; "), nil
	}
	var notes []string
	for _, f := range rep.Findings {
		if f.Level == Warn {
			notes = append(notes, f.Check+": "+f.Detail)
		}
	}
	detail := rep.Facts["os_name"] + " meets the requirements"
	if len(notes) > 0 {
		detail += " (advisory: " + strings.Join(notes, "; ") + ")"
	}
	return Done, detail, nil
}

func (in *Installer) checkPrereqs(ctx context.Context) (State, string, error) {
	res, err := in.R.Run(ctx, `dpkg-query -W -f='${Status}\n' curl gnupg apt-transport-https 2>/dev/null | grep -c 'install ok installed' || true`)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(res.Stdout) == "3" {
		return Done, "installed", nil
	}
	return Pending, "", nil
}

func (in *Installer) applyPrereqs(ctx context.Context) (string, error) {
	res, err := in.run(ctx, "export DEBIAN_FRONTEND=noninteractive\napt-get update -q >/dev/null\napt-get install -y -q curl gnupg apt-transport-https >/dev/null\n")
	return resultErr(res, err, "installed")
}

func (in *Installer) token() (string, error) {
	t, err := in.Secrets.GetString("", secrets.RepoToken)
	if err != nil {
		return "", err
	}
	if err := secrets.ValidateRepoToken(t); err != nil {
		return "", fmt.Errorf("stored repo-token: %w", err)
	}
	return t, nil
}

func (in *Installer) checkKey(ctx context.Context) (State, string, error) {
	res, err := in.R.Run(ctx, "test -s "+keyringPath+" && gpg --show-keys --with-colons "+keyringPath+" 2>/dev/null | grep -c 'corelight/fleet-stable' || true")
	if err != nil {
		return "", "", err
	}
	if n := strings.TrimSpace(res.Stdout); n != "" && n != "0" {
		return Done, "key present", nil
	}
	if _, err := in.token(); err != nil {
		return Blocked, err.Error(), nil
	}
	return Pending, "", nil
}

// tokenScript defines $TOKEN from a heredoc and $NETRC as a netrc for the
// repository, so the token never appears in a command line.
func tokenScript(tok string) string {
	// The heredoc end marker must stay alone on its line, so ")" follows it.
	return "TOKEN=$(" + host.Heredoc(tok) + ")\n" +
		"NETRC=$(mktemp); chmod 600 \"$NETRC\"; trap 'rm -f \"$NETRC\"' EXIT\n" +
		"printf 'machine pkgrepos.corelight.cloud login %s password irrelevant\\n' \"$TOKEN\" > \"$NETRC\"\n"
}

func (in *Installer) applyKey(ctx context.Context) (string, error) {
	tok, err := in.token()
	if err != nil {
		return "", err
	}
	script := tokenScript(tok) + fmt.Sprintf(`install -d -m 0755 /etc/apt/keyrings
tmp=$(mktemp)
code=$(curl -sSL --netrc-file "$NETRC" -o "$tmp" -w '%%{http_code}' %s)
if [ "$code" != 200 ]; then echo "key download failed: HTTP $code (check the repo-token)" >&2; exit 1; fi
gpg --dearmor < "$tmp" > "$tmp.gpg"
install -m 0644 "$tmp.gpg" %s
rm -f "$tmp" "$tmp.gpg"
gpg --show-keys --with-colons %s | awk -F: '$1=="uid"{print $10; exit}'
`, repoKeyURL, keyringPath, keyringPath)
	res, err := in.run(ctx, script, tok)
	return resultErr(res, err, "key installed")
}

func (in *Installer) checkSources(ctx context.Context) (State, string, error) {
	got, err := in.remoteSHA(ctx, sourcesPath)
	if err != nil {
		return "", "", err
	}
	if got == sha(sourcesList) {
		return Done, "matches the documented repository", nil
	}
	if got != "" {
		return Pending, "exists with different content; it will be replaced", nil
	}
	return Pending, "", nil
}

func (in *Installer) applySources(ctx context.Context) (string, error) {
	res, err := in.run(ctx, writeFileScript(sourcesPath, sourcesList, "0644", "root:root"))
	return resultErr(res, err, "written")
}

func authConf(tok string) string {
	return "machine pkgrepos.corelight.cloud/corelight/fleet-stable/ login " + tok + " password irrelevant\n"
}

func (in *Installer) checkAuth(ctx context.Context) (State, string, error) {
	tok, err := in.token()
	if err != nil {
		return Blocked, err.Error(), nil
	}
	got, err := in.remoteSHA(ctx, authConfPath)
	if err != nil {
		return "", "", err
	}
	if got == sha(authConf(tok)) {
		return Done, "holds the stored token", nil
	}
	if got != "" {
		return Pending, "holds a different token; it will be replaced", nil
	}
	return Pending, "", nil
}

func (in *Installer) applyAuth(ctx context.Context) (string, error) {
	tok, err := in.token()
	if err != nil {
		return "", err
	}
	res, err := in.run(ctx, "install -d -m 0755 /etc/apt/auth.conf.d\n"+writeFileScript(authConfPath, authConf(tok), "0600", "root:root"), tok)
	return resultErr(res, err, "written")
}

func (in *Installer) installedVersion(ctx context.Context) (string, error) {
	res, err := in.R.Run(ctx, `dpkg-query -W -f='${Status}|${Version}' `+pkgName+` 2>/dev/null || true`)
	if err != nil {
		return "", err
	}
	st, ver, _ := strings.Cut(strings.TrimSpace(res.Stdout), "|")
	if st != "install ok installed" {
		return "", nil
	}
	return ver, nil
}

func (in *Installer) checkPackage(ctx context.Context) (State, string, error) {
	ver, err := in.installedVersion(ctx)
	if err != nil {
		return "", "", err
	}
	if ver == "" {
		return Pending, "not installed", nil
	}
	if in.Opts.Version != "" && !strings.HasPrefix(ver, in.Opts.Version) {
		return Blocked, fmt.Sprintf("corelight-fleet %s is installed, not %s; upgrading is a separate operation", ver, in.Opts.Version), nil
	}
	return Done, "corelight-fleet " + ver, nil
}

func (in *Installer) applyPackage(ctx context.Context) (string, error) {
	pin := ""
	if in.Opts.Version != "" {
		pin = in.Opts.Version
	}
	script := fmt.Sprintf(`export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
want=%s
if [ -n "$want" ]; then
  ver=$(apt-cache madison %s | awk -v w="$want" '{v=$3} index(v,w)==1 {print v; exit}')
  if [ -z "$ver" ]; then echo "no %s version starting with $want in the repository; available:" >&2; apt-cache madison %s | awk '{print $3}' | head -10 >&2; exit 1; fi
  apt-get install -y -q %s="$ver" >/dev/null
else
  apt-get install -y -q %s >/dev/null
fi
dpkg-query -W -f='${Version}' %s
`, host.Quote(pin), pkgName, pkgName, pkgName, pkgName, pkgName, pkgName)
	res, err := in.run(ctx, script)
	if out, err := resultErr(res, err, ""); err != nil {
		return out, err
	}
	in.restartNeeded = true
	return "installed corelight-fleet " + strings.TrimSpace(res.Stdout), nil
}

func (in *Installer) checkIdentity(ctx context.Context) (State, string, error) {
	pem, err := in.Secrets.Get("", secrets.IdentityCert)
	if err != nil {
		return Blocked, err.Error(), nil
	}
	sum, err := secrets.ValidateIdentityCert(pem)
	if err != nil {
		return Blocked, "stored identity certificate: " + err.Error(), nil
	}
	got, err := in.remoteSHA(ctx, identityPath)
	if err != nil {
		return "", "", err
	}
	desc := fmt.Sprintf("%s, expires %s", sum.Subject, sum.NotAfter.Format("2006-01-02"))
	if got == sha(string(pem)) {
		return Done, desc, nil
	}
	if got != "" {
		return Pending, "a different certificate is installed; it will be replaced with " + desc, nil
	}
	return Pending, desc, nil
}

func (in *Installer) applyIdentity(ctx context.Context) (string, error) {
	pem, err := in.Secrets.Get("", secrets.IdentityCert)
	if err != nil {
		return "", err
	}
	script := "if [ -f " + identityPath + " ]; then cp -p " + identityPath + " " + identityPath + ".bak-$(date +%Y%m%d-%H%M%S); fi\n" +
		writeFileScript(identityPath, string(pem), "0400", "corelight-fleetd:corelight-fleetd")
	res, err := in.run(ctx, script)
	if out, err := resultErr(res, err, ""); err != nil {
		return out, err
	}
	in.restartNeeded = true
	return "installed", nil
}

// --- config ---

func (in *Installer) readConf(ctx context.Context) (map[string]any, error) {
	res, err := in.R.Run(ctx, "cat "+confPath+" 2>/dev/null || true")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(res.Stdout) == "" {
		return map[string]any{}, nil
	}
	var conf map[string]any
	if err := json.Unmarshal([]byte(res.Stdout), &conf); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", confPath, err)
	}
	return conf, nil
}

func placeholderCommunity(s string) bool {
	return s == "" || s == "provide_a_community_string"
}

// communityString returns the stored community string, adopting a real one
// already in the config, or generating one.
func (in *Installer) communityString(conf map[string]any, create bool) (string, string, error) {
	if v, err := in.Secrets.GetString(in.Host, secrets.CommunityString); err == nil {
		return v, "stored", nil
	}
	cur := communityFrom(conf)
	if !placeholderCommunity(cur) {
		if create {
			if err := in.Secrets.Set(in.Host, secrets.CommunityString, []byte(cur)); err != nil {
				return "", "", err
			}
		}
		return cur, "kept the existing value", nil
	}
	v := Generate(40, false)
	if create {
		if err := in.Secrets.Set(in.Host, secrets.CommunityString, []byte(v)); err != nil {
			return "", "", err
		}
	}
	return v, "generated", nil
}

func communityFrom(conf map[string]any) string {
	m, _ := conf["messaging"].(map[string]any)
	s, _ := m["community-string"].(string)
	return s
}

// desiredConf applies the managed settings to a copy of conf.
func (in *Installer) desiredConf(conf map[string]any, community string) map[string]any {
	out := map[string]any{}
	for k, v := range conf {
		out[k] = v
	}
	defaults := map[string]any{
		"log-level": "INFO", "data-path": "/var/lib/corelight-fleetd",
		"ssl-key-path": identityPath, "ssl-certificate-path": identityPath,
	}
	for k, v := range defaults {
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	}
	msg := map[string]any{}
	if m, ok := out["messaging"].(map[string]any); ok {
		for k, v := range m {
			msg[k] = v
		}
	}
	msg["community-string"] = community
	httpOpts := map[string]any{}
	if h, ok := msg["http-options"].(map[string]any); ok {
		for k, v := range h {
			httpOpts[k] = v
		}
	}
	if _, ok := httpOpts["bind-address"]; !ok {
		httpOpts["bind-address"] = ":1443"
	}
	msg["http-options"] = httpOpts
	out["messaging"] = msg
	if in.Opts.ExposeSwagger != nil {
		if *in.Opts.ExposeSwagger {
			out["expose-swagger"] = true
		} else {
			delete(out, "expose-swagger")
		}
	}
	return out
}

func confEqual(a, b map[string]any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

func (in *Installer) checkConfig(ctx context.Context) (State, string, error) {
	conf, err := in.readConf(ctx)
	if err != nil {
		return Blocked, err.Error(), nil
	}
	if len(conf) == 0 {
		return Pending, confPath + " is missing; it will be created", nil
	}
	community, how, err := in.communityString(conf, false)
	if err != nil {
		return "", "", err
	}
	if confEqual(conf, in.desiredConf(conf, community)) {
		return Done, "community-string set; managed settings match", nil
	}
	return Pending, "community-string: " + how, nil
}

func (in *Installer) applyConfig(ctx context.Context) (string, error) {
	conf, err := in.readConf(ctx)
	if err != nil {
		return "", err
	}
	community, how, err := in.communityString(conf, true)
	if err != nil {
		return "", err
	}
	want := in.desiredConf(conf, community)
	b, err := json.MarshalIndent(want, "", "   ")
	if err != nil {
		return "", err
	}
	script := "if [ -f " + confPath + " ]; then cp -p " + confPath + " " + confPath + ".bak-$(date +%Y%m%d-%H%M%S); fi\n" +
		writeFileScript(confPath, string(b)+"\n", "0640", "root:corelight-fleetd")
	res, err := in.run(ctx, script, community)
	if out, err := resultErr(res, err, ""); err != nil {
		return out, err
	}
	in.restartNeeded = true
	return "written (community-string " + how + "; previous file backed up)", nil
}

// --- service ---

const waitScript = `for i in $(seq 1 60); do
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 https://127.0.0.1/fleet/v1/info || true)
  if [ "$code" = 401 ] || [ "$code" = 200 ]; then echo "api up after ${i}x2s"; exit 0; fi
  sleep 2
done
echo "the web API did not come up within 120s" >&2
systemctl status corelight-fleetd --no-pager -n 0 >&2 || true
journalctl -u corelight-fleetd --no-pager -n 25 >&2 || true
exit 1
`

func (in *Installer) checkService(ctx context.Context) (State, string, error) {
	res, err := in.R.Run(ctx, "echo $(systemctl is-enabled "+serviceName+" 2>/dev/null) $(systemctl is-active "+serviceName+" 2>/dev/null) $(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 https://127.0.0.1/fleet/v1/info || true)")
	if err != nil {
		return "", "", err
	}
	f := strings.Fields(res.Stdout)
	if len(f) == 3 && f[0] == "enabled" && f[1] == "active" && (f[2] == "401" || f[2] == "200") && !in.restartNeeded {
		return Done, "enabled, running, API answering", nil
	}
	if in.restartNeeded {
		return Pending, "restart needed for the new package, certificate or config", nil
	}
	return Pending, strings.TrimSpace(res.Stdout), nil
}

func (in *Installer) applyService(ctx context.Context) (string, error) {
	res, err := in.run(ctx, "systemctl enable "+serviceName+" >/dev/null 2>&1\nsystemctl restart "+serviceName+"\n"+waitScript)
	if out, err := resultErr(res, err, ""); err != nil {
		return out, err
	}
	in.restartNeeded = false
	return strings.TrimSpace(res.Stdout), nil
}

// --- users ---

var tempPassword = regexp.MustCompile(`(?m)^\s*Password:\s*(\S+)\s*$`)

// ParseTempPassword extracts the password from create-user output.
func ParseTempPassword(out string) (string, bool) {
	m := tempPassword.FindStringSubmatch(out)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// fleetdUser runs corelight-fleetd create-user for a Fleet admin user, or
// reset-password when allowed and the user already exists, and returns the
// temporary password it prints.
func (in *Installer) fleetdUser(ctx context.Context, user string, allowReset bool) (temp string, existed bool, err error) {
	cmd := "sudo -u corelight-fleetd " + fleetdBin + " -c " + confPath
	res, err := in.R.Run(ctx, cmd+" create-user -a "+host.Quote(user)+" 2>&1 || true")
	if err != nil {
		return "", false, err
	}
	if temp, ok := ParseTempPassword(res.Stdout); ok {
		return temp, false, nil
	}
	if !strings.Contains(strings.ToLower(res.Stdout), "exist") {
		return "", false, fmt.Errorf("create-user %s did not print a temporary password: %s", user, firstLine(res.Stdout))
	}
	if !allowReset {
		return "", true, nil
	}
	res, err = in.R.Run(ctx, cmd+" reset-password "+host.Quote(user)+" 2>&1 || true")
	if err != nil {
		return "", true, err
	}
	temp, ok := ParseTempPassword(res.Stdout)
	if !ok {
		return "", true, fmt.Errorf("%s exists and reset-password did not print a temporary password: %s", user, firstLine(res.Stdout))
	}
	return temp, true, nil
}

func (in *Installer) checkMCPUser(ctx context.Context) (State, string, error) {
	if in.Bootstrap == nil {
		return Blocked, "no API bootstrapper", nil
	}
	if ok, detail := in.Bootstrap.MCPUserReady(ctx, in); ok {
		return Done, detail, nil
	}
	return Pending, "", nil
}

func (in *Installer) applyMCPUser(ctx context.Context) (string, error) {
	temp, existed, err := in.fleetdUser(ctx, in.Opts.MCPUser, true)
	if err != nil {
		return "", err
	}
	if err := in.Bootstrap.ActivateMCPUser(ctx, in, temp); err != nil {
		return "", err
	}
	if existed {
		return "existed; its password was reset and replaced with a generated one stored for fleet-mcp", nil
	}
	return "created; its password is generated and stored for fleet-mcp", nil
}

func (in *Installer) checkAdmin(ctx context.Context) (State, string, error) {
	if in.Bootstrap == nil {
		return Blocked, "no API bootstrapper", nil
	}
	exists, err := in.Bootstrap.AdminExists(ctx, in)
	if err != nil {
		// Before the MCP user exists (preview of a new install) this is
		// expected; the step will run.
		return Pending, "", nil
	}
	if exists {
		return Done, "the admin user exists and is yours; fleet-mcp does not manage its password", nil
	}
	return Pending, "", nil
}

func (in *Installer) applyAdmin(ctx context.Context) (string, error) {
	temp, existed, err := in.fleetdUser(ctx, "admin", false)
	if err != nil {
		return "", err
	}
	if existed {
		return "the admin user already exists; left untouched", nil
	}
	in.AdminTempPassword = temp
	return fmt.Sprintf("created user \"admin\" with temporary password %s; log in at %s and Fleet Manager will require a new password. fleet-mcp does not keep it.", temp, in.URL()), nil
}

// --- helpers ---

func resultErr(res *host.Result, err error, okMsg string) (string, error) {
	if err != nil {
		return "", err
	}
	if !res.OK() {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(res.Stdout)
		}
		if len(msg) > 1500 {
			msg = msg[len(msg)-1500:]
		}
		return "", fmt.Errorf("exit %d: %s", res.ExitCode, msg)
	}
	if okMsg != "" {
		return okMsg, nil
	}
	return strings.TrimSpace(res.Stdout), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
