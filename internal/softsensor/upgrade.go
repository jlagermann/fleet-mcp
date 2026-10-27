// Package softsensor upgrades Corelight Software Sensors on their Linux
// host over SSH. A Software Sensor cannot update itself: its packages come
// from the Corelight sensor-stable repository, and corelightctl then
// redeploys the sensor with the new images.
package softsensor

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jlagermann/fleet-mcp/internal/host"
)

const (
	// unit is the transient systemd unit the upgrade runs in, so it
	// survives a dropped SSH connection.
	unit = "fleet-mcp-softsensor-upgrade"
	// stateFile records the upgrade's stages; it is kept across reboots.
	stateFile = "/var/lib/fleet-mcp/softsensor-upgrade.state"
	// logFile has the full apt and corelightctl output of the upgrade.
	logFile    = "/var/log/fleet-mcp-softsensor-upgrade.log"
	scriptFile = "/var/lib/fleet-mcp/softsensor-upgrade.sh"
	ctlLog     = "/var/log/corelightctl.log"
	oldRepo    = "/etc/apt/sources.list.d/corelight_corelightctl.list"
	newRepo    = "/etc/apt/sources.list.d/corelight_sensor-stable.list"
	ctlYAML    = "/etc/corelight/corelightctl.yaml"
	// defaultDeployMB is corelightctl's own free-space requirement for a
	// deploy (21.86 GB in 29.0.6) when its log does not say.
	defaultDeployMB = 22385
	// marginMB is kept free on top of what the upgrade needs.
	marginMB = 2048
	// slowSyncMs is the average synchronous write time from which the
	// preview warns about slow storage (etcd's guidance: WAL fsync under
	// 10 ms).
	slowSyncMs = 10
)

// supportedOS are the documented Software Sensor platforms (ID VERSION_ID).
var supportedOS = []string{"ubuntu 22.04", "ubuntu 24.04", "almalinux 8", "almalinux 9", "rhel 8", "rhel 9"}

// Options select the version to install.
type Options struct {
	// Version is a corelight-sensor version or prefix (29.2.2); empty means
	// the newest the Fleet Manager allows.
	Version string `json:"version,omitempty"`
	// AllowDowngrade permits installing an older version.
	AllowDowngrade bool `json:"allow_downgrade,omitempty"`
	// MaxVersion is the Fleet Manager's version: a sensor must not be newer
	// than the Fleet Manager that manages it. Empty skips the check.
	MaxVersion string `json:"max_version,omitempty"`
}

// Plan is what an upgrade will do.
type Plan struct {
	Host       string            `json:"host"`
	OS         string            `json:"os"`
	Installed  string            `json:"installed"`
	Packages   map[string]string `json:"packages,omitempty"`
	Running    string            `json:"running,omitempty"`
	Target     string            `json:"target,omitempty"`
	Available  []string          `json:"available,omitempty"`
	Downgrade  bool              `json:"downgrade,omitempty"`
	DeployOnly bool              `json:"deploy_only,omitempty"`
	DownloadMB int               `json:"download_mb,omitempty"`
	NeededMB   int               `json:"needed_free_mb,omitempty"`
	FreeMB     int               `json:"free_mb"`
	// SyncWriteMs is the average time of a synchronous 4 KiB write on
	// /var/lib, as etcd makes them; 0 when it was not measured.
	SyncWriteMs float64  `json:"sync_write_ms,omitempty"`
	Steps       []string `json:"steps,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Blockers    []string `json:"blockers,omitempty"`
}

// Ready reports whether there is something to do and nothing blocks it.
func (p *Plan) Ready() bool {
	return len(p.Blockers) == 0 && p.Target != "" && (p.Target != p.Installed || p.DeployOnly)
}

// State identifies what the plan was built from.
func (p *Plan) State() string {
	return fmt.Sprintf("%s|%s|%s|%t", p.Installed, p.Running, p.Target, p.DeployOnly)
}

// facts reads everything the plan needs in one SSH call. apt-get update
// refreshes the package lists and changes nothing else; the latency test
// writes 100 synchronous 4 KiB blocks to a temporary file and removes it.
const facts = `export DEBIAN_FRONTEND=noninteractive
. /etc/os-release 2>/dev/null
echo "os=${ID:-unknown} ${VERSION_ID:-}|${PRETTY_NAME:-}"
command -v apt-get >/dev/null 2>&1 && echo "apt=yes"
dpkg-query -W -f='pkg=${Package}|${db:Status-Abbrev}|${Version}\n' 'corelight*' 2>/dev/null
[ -f ` + oldRepo + ` ] && echo "oldrepo=yes"
[ -f ` + newRepo + ` ] && echo "newrepo=yes"
[ -f ` + ctlYAML + ` ] && echo "yaml=$(stat -c %a ` + ctlYAML + `)"
echo "free=$(df -Pm /var/lib | awk 'NR==2 {print $4}')"
req=$(grep -a -o '[0-9.]*GB required' ` + ctlLog + ` 2>/dev/null | tail -n 1 | cut -dG -f1)
echo "deployreq=${req}"
echo "firewalld=$(systemctl is-active firewalld 2>/dev/null)"
echo "unit=$(systemctl is-active ` + unit + ` 2>/dev/null)"
pgrep -f 'corelightctl sensor (deploy|prepare)' >/dev/null && echo "busy=yes"
lat=/var/lib/.fleet-mcp-latency.$$
t0=$(date +%s%N)
if dd if=/dev/zero of=$lat bs=4k count=100 oflag=dsync 2>/dev/null; then echo "syncus=$(( ($(date +%s%N) - t0) / 100000 ))"; fi
rm -f $lat
if apt-get update -q >/tmp/fleet-mcp-apt.$$ 2>&1; then echo "aptupdate=ok"; else echo "aptupdate=failed: $(grep -m1 -iE 'err|401|403|denied' /tmp/fleet-mcp-apt.$$)"; fi
rm -f /tmp/fleet-mcp-apt.$$
apt-cache madison corelight-sensor 2>/dev/null | awk '{print "available=" $3}'
`

// Planner reads a Software Sensor host and upgrades it.
type Planner struct {
	R host.Runner
	// Poll is the pause between status reads while waiting (default 30 s).
	Poll time.Duration
	// OnPoll, if set, is called with each status read while waiting (the
	// tool sends it as MCP progress, so clients do not time out).
	OnPoll func(*Status)
}

// Plan reads the host and the repository and changes nothing.
func (s *Planner) Plan(ctx context.Context, o Options, running string) (*Plan, error) {
	res, err := s.R.Run(ctx, facts)
	if err != nil {
		return nil, err
	}
	if !res.OK() {
		return nil, fmt.Errorf("reading %s failed: %s", s.R.Name(), strings.TrimSpace(res.Stderr))
	}
	p := &Plan{Host: s.R.Name(), Running: running, Packages: map[string]string{}}
	block := func(f string, a ...any) { p.Blockers = append(p.Blockers, fmt.Sprintf(f, a...)) }
	warn := func(f string, a ...any) { p.Warnings = append(p.Warnings, fmt.Sprintf(f, a...)) }
	var osID, yaml, firewalld, unitState string
	var apt, oldRepoSeen, newRepoSeen, busy bool
	deployMB := defaultDeployMB
	for _, l := range strings.Split(res.Stdout, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		switch k {
		case "os":
			osID, p.OS, _ = strings.Cut(v, "|")
		case "apt":
			apt = true
		case "pkg":
			f := strings.Split(v, "|")
			if len(f) == 3 && strings.HasPrefix(f[1], "ii") {
				p.Packages[f[0]] = f[2]
				if f[0] == "corelight-sensor" {
					p.Installed = f[2]
				}
			}
		case "oldrepo":
			oldRepoSeen = true
		case "newrepo":
			newRepoSeen = true
		case "yaml":
			yaml = v
		case "free":
			p.FreeMB, _ = strconv.Atoi(v)
		case "deployreq":
			if gb, err := strconv.ParseFloat(v, 64); err == nil && gb > 0 {
				deployMB = int(gb*1024 + 0.5)
			}
		case "firewalld":
			firewalld = v
		case "unit":
			unitState = v
		case "busy":
			busy = true
		case "syncus":
			if us, err := strconv.Atoi(v); err == nil && us > 0 {
				p.SyncWriteMs = float64(us/10) / 100
			}
		case "aptupdate":
			if v != "ok" {
				block("apt-get update failed (%s); the Software Sensor repository token in /etc/apt/auth.conf.d may have expired", strings.TrimPrefix(v, "failed: "))
			}
		case "available":
			p.Available = append(p.Available, v)
		}
	}
	if !apt {
		block("%s has no apt-get; only Ubuntu Software Sensors are supported so far (RHEL and AlmaLinux use dnf)", p.Host)
		return p, nil
	}
	if p.Installed == "" {
		block("corelight-sensor is not installed on %s; this is not a Software Sensor host", p.Host)
		return p, nil
	}
	if !supported(osID) {
		warn("%s is not a documented Software Sensor platform (Ubuntu 22.04/24.04, RHEL/AlmaLinux 8/9); corelightctl sensor prepare may refuse it", p.OS)
	}
	if unitState == "active" || unitState == "activating" || busy {
		block("an upgrade or corelightctl deploy is already running on %s; follow it with status", p.Host)
	}
	if oldRepoSeen {
		block("%s still has the retired repository file %s; per the Corelight installation guide, set up the sensor-stable repository and remove that file first", p.Host, oldRepo)
	} else if !newRepoSeen {
		warn("no %s; corelight-sensor versions come from another repository configuration", newRepo)
	}
	if yaml == "" {
		block("%s is missing; corelightctl cannot deploy without it", ctlYAML)
	} else if yaml != "600" && yaml != "640" && yaml != "400" {
		warn("%s is mode %s, readable by every local user, and holds the Fleet Manager community string and pairing token; consider chmod 600", ctlYAML, yaml)
	}
	if p.SyncWriteMs >= slowSyncMs {
		warn("slow storage: a synchronous 4 KiB write on /var/lib takes %.1f ms on average (etcd, the sensor's Kubernetes datastore, wants under %d ms). The deploy can then miss corelightctl's fixed 5- and 15-minute waits and fail with exit 3 (no rollback); faster storage avoids it. If it happens and rke2-server keeps running, wait until the host is idle and run this tool again: the preview offers the deploy only", p.SyncWriteMs, slowSyncMs)
	}
	if firewalld == "active" {
		warn("firewalld is running; the installation guide says to stop and disable it on a Software Sensor host")
	}
	if len(p.Available) == 0 {
		block("the repository lists no corelight-sensor versions")
		return p, nil
	}
	p.Target = s.pick(ctx, p.Available, o)
	if p.Target == "" {
		switch {
		case o.Version != "":
			block("no corelight-sensor version starting with %s in the repository", o.Version)
		default:
			block("no corelight-sensor version in the repository is at or below Fleet Manager %s", o.MaxVersion)
		}
		return p, nil
	}
	if o.MaxVersion != "" && newer(base(p.Target), base(o.MaxVersion)) {
		block("%s is newer than its Fleet Manager (%s); a Fleet Manager must be the same version as its sensors or newer: upgrade Fleet Manager first", base(p.Target), base(o.MaxVersion))
	}
	if p.Target == p.Installed {
		if running != "" && base(running) != base(p.Target) {
			// The packages were installed, but the deploy did not finish
			// (e.g. a reboot was needed).
			p.DeployOnly = true
			warn("corelight-sensor %s is installed but the sensor still runs %s: only the deploy is left", p.Installed, running)
		} else {
			warn("corelight-sensor %s is already installed and running", p.Installed)
			return p, nil
		}
	}
	if !p.DeployOnly {
		cmp, err := s.compare(ctx, p.Target, p.Installed)
		if err != nil {
			return nil, err
		}
		if cmp < 0 {
			p.Downgrade = true
			if !o.AllowDowngrade {
				block("%s is older than the installed %s; a downgrade needs allow_downgrade", p.Target, p.Installed)
			} else {
				warn("downgrading: the sensor's data and configuration were last deployed by a newer version")
			}
		}
		dl, largest, err := s.sizes(ctx, p.Target, o.AllowDowngrade)
		if err != nil {
			return nil, err
		}
		p.DownloadMB = dl
		// apt keeps the download while dpkg replaces each image archive
		// in /opt/corelight; after apt-get clean, the deploy needs its own
		// free space.
		p.NeededMB = max(dl+largest, deployMB) + marginMB
	} else {
		p.NeededMB = deployMB + marginMB
	}
	if p.FreeMB < p.NeededMB {
		block("only %d MB free on /var/lib; this upgrade needs about %d MB (download %d MB, corelightctl deploy requires %d MB free, plus %d MB margin). Grow the filesystem first (e.g. lvextend -r on an LVM root)", p.FreeMB, p.NeededMB, p.DownloadMB, deployMB, marginMB)
	}
	if !p.DeployOnly {
		allow := ""
		if p.Downgrade {
			allow = " --allow-downgrades"
		}
		p.Steps = append(p.Steps,
			fmt.Sprintf("apt-get install%s corelightctl=%s corelight-sensor=%s (the image packages follow; existing configuration files are kept), then apt-get clean", allow, p.Target, p.Target))
	}
	p.Steps = append(p.Steps,
		"corelightctl sensor prepare (if it needs a reboot, the upgrade stops there: reboot, then run this tool again to deploy)",
		"corelightctl sensor deploy -v: loads the new images from /opt/corelight and redeploys; it snapshots the deployment first and rolls back on failure",
		"wait for the result and check the version Fleet Manager reports")
	warn("capture and export stop during the deploy; on slow storage a deploy can take 40 minutes or more")
	warn("the upgrade runs on the host as systemd unit %s, so a dropped SSH connection does not stop it; its output is in %s", unit, logFile)
	return p, nil
}

// pick returns the newest available version matching o.
func (s *Planner) pick(ctx context.Context, avail []string, o Options) string {
	for _, v := range avail { // madison lists newest first
		if o.Version != "" && v != o.Version && !strings.HasPrefix(v, o.Version+"-") && !strings.HasPrefix(v, o.Version+".") {
			continue
		}
		if o.Version == "" && o.MaxVersion != "" && newer(base(v), base(o.MaxVersion)) {
			continue
		}
		return v
	}
	return ""
}

// sizes returns the download size and the largest installed size of the
// packages an install of version would fetch, in MB.
func (s *Planner) sizes(ctx context.Context, version string, downgrade bool) (int, int, error) {
	allow := ""
	if downgrade {
		allow = "--allow-downgrades "
	}
	v := host.Quote(version)
	res, err := s.R.Run(ctx, fmt.Sprintf("export DEBIAN_FRONTEND=noninteractive\napt-get install -qq --print-uris %scorelightctl=%s corelight-sensor=%s\n", allow, v, v))
	if err != nil {
		return 0, 0, err
	}
	if !res.OK() {
		return 0, 0, fmt.Errorf("apt cannot install corelight-sensor %s: %s", version, strings.TrimSpace(res.Stdout+" "+res.Stderr))
	}
	// Each line: 'URL' name_version_arch.deb size checksum
	var dl int64
	var pkgs []string
	for _, l := range strings.Split(res.Stdout, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || !strings.HasPrefix(f[0], "'") {
			continue
		}
		if n, err := strconv.ParseInt(f[2], 10, 64); err == nil {
			dl += n
		}
		if parts := strings.Split(f[1], "_"); len(parts) == 3 {
			pkgs = append(pkgs, parts[0]+"="+strings.ReplaceAll(parts[1], "%3a", ":"))
		}
	}
	var largest int64
	if len(pkgs) > 0 {
		var b strings.Builder
		for _, p := range pkgs {
			fmt.Fprintf(&b, "apt-cache show %s 2>/dev/null | sed -n 's/^Installed-Size: *//p' | head -n 1\n", host.Quote(p))
		}
		res, err := s.R.Run(ctx, b.String())
		if err != nil {
			return 0, 0, err
		}
		for _, l := range strings.Fields(res.Stdout) {
			if n, err := strconv.ParseInt(l, 10, 64); err == nil {
				largest = max(largest, n<<10) // KiB
			}
		}
	}
	return int(dl >> 20), int(largest >> 20), nil
}

// compare returns -1, 0 or 1 as a is older than, equal to or newer than b,
// by Debian version rules.
func (s *Planner) compare(ctx context.Context, a, b string) (int, error) {
	res, err := s.R.Run(ctx, fmt.Sprintf("if dpkg --compare-versions %s lt %s; then echo -1; elif dpkg --compare-versions %s gt %s; then echo 1; else echo 0; fi",
		host.Quote(a), host.Quote(b), host.Quote(a), host.Quote(b)))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(res.Stdout))
}

func supported(osID string) bool {
	for _, s := range supportedOS {
		if osID == s {
			return true
		}
	}
	return false
}

// base is the numeric release of a package or Fleet Manager version:
// 29.2.2-1 and 29.2.2-16847904621 are both 29.2.2.
func base(v string) string {
	v, _, _ = strings.Cut(v, "-")
	return v
}

// newer reports whether release a is newer than release b (dotted numbers).
func newer(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(as), len(bs)); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			return x > y
		}
	}
	return false
}
