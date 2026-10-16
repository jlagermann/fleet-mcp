package install

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jlagermann/fleet-mcp/internal/host"
)

// minUpgradeFreeMB is the free space an upgrade needs on / and on the data
// path: the package is a few hundred MB and the backup lands in the data
// path.
const minUpgradeFreeMB = 2048

// UpgradeOptions select the version to install.
type UpgradeOptions struct {
	// Version is a corelight-fleet version or prefix (29.2.2); empty means
	// the newest in the repository.
	Version string `json:"version,omitempty"`
	// AllowDowngrade permits installing an older version.
	AllowDowngrade bool `json:"allow_downgrade,omitempty"`
	// Backup makes a Fleet Manager backup first.
	Backup bool `json:"backup"`
}

// UpgradePlan is what an upgrade will do.
type UpgradePlan struct {
	Host      string   `json:"host"`
	Installed string   `json:"installed"`
	Target    string   `json:"target,omitempty"`
	Available []string `json:"available,omitempty"`
	Downgrade bool     `json:"downgrade,omitempty"`
	Backup    bool     `json:"backup"`
	DataPath  string   `json:"data_path"`
	FreeMB    []string `json:"free_mb,omitempty"`
	Steps     []string `json:"steps,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Blockers  []string `json:"blockers,omitempty"`
}

// Ready reports whether there is a version to install and nothing blocks it.
func (p *UpgradePlan) Ready() bool {
	return len(p.Blockers) == 0 && p.Target != "" && p.Target != p.Installed
}

// State identifies what the plan was built from.
func (p *UpgradePlan) State() string { return p.Installed + "|" + p.Target }

// upgradeFacts reads everything the plan needs in one SSH call.
const upgradeFacts = `export DEBIAN_FRONTEND=noninteractive
echo "installed=$(dpkg-query -W -f='${Status}|${Version}' ` + pkgName + ` 2>/dev/null)"
dp=$(sed -ne '/"data-path"[[:space:]]*:/s/^.*"data-path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*$/\1/p' ` + confPath + ` 2>/dev/null)
echo "datapath=${dp:-/var/lib/corelight-fleetd}"
for d in / "${dp:-/var/lib/corelight-fleetd}"; do echo "free=$d $(df -Pm "$d" 2>/dev/null | awk 'NR==2 {print $4}')"; done
echo "active=$(systemctl is-active ` + serviceName + ` 2>/dev/null)"
if apt-get update -q >/tmp/fleet-mcp-apt.$$ 2>&1; then echo "aptupdate=ok"; else echo "aptupdate=failed: $(grep -m1 -iE 'err|401|403|denied' /tmp/fleet-mcp-apt.$$)"; fi
rm -f /tmp/fleet-mcp-apt.$$
apt-cache madison ` + pkgName + ` 2>/dev/null | awk '{print "available=" $3}'
`

// Upgrader installs another corelight-fleet version.
type Upgrader struct {
	R host.Runner
	// StartBackup asks Fleet Manager for a backup (POST
	// /fleet/v1/server/backup); nil when there is no API connection.
	StartBackup func(ctx context.Context) error
	// BackupTimeout bounds the wait for the backup file (default 10 min).
	BackupTimeout time.Duration
}

// Plan reads the host and the repository and changes nothing (apt-get
// update refreshes the package lists).
func (u *Upgrader) Plan(ctx context.Context, o UpgradeOptions) (*UpgradePlan, error) {
	res, err := u.R.Run(ctx, upgradeFacts)
	if err != nil {
		return nil, err
	}
	p := &UpgradePlan{Host: u.R.Name(), Backup: o.Backup}
	block := func(f string, a ...any) { p.Blockers = append(p.Blockers, fmt.Sprintf(f, a...)) }
	active := ""
	for _, l := range strings.Split(res.Stdout, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		switch k {
		case "installed":
			if st, ver, _ := strings.Cut(v, "|"); st == "install ok installed" {
				p.Installed = ver
			}
		case "datapath":
			p.DataPath = v
		case "free":
			p.FreeMB = append(p.FreeMB, v)
			f := strings.Fields(v)
			if len(f) == 2 {
				if mb, err := strconv.Atoi(f[1]); err == nil && mb < minUpgradeFreeMB {
					block("only %d MB free on %s; an upgrade needs %d MB", mb, f[0], minUpgradeFreeMB)
				}
			}
		case "active":
			active = v
		case "aptupdate":
			if v != "ok" {
				block("apt-get update failed (%s); the repository token may have expired: check with fm_host_check", strings.TrimPrefix(v, "failed: "))
			}
		case "available":
			p.Available = append(p.Available, v)
		}
	}
	if p.Installed == "" {
		block("corelight-fleet is not installed on %s; use fm_host_install", p.Host)
		return p, nil
	}
	if active != "active" {
		p.Warnings = append(p.Warnings, "corelight-fleetd is "+active+" now")
	}
	if len(p.Available) == 0 {
		block("the repository lists no corelight-fleet versions")
		return p, nil
	}
	p.Target = pickVersion(p.Available, o.Version)
	if p.Target == "" {
		block("no corelight-fleet version starting with %s in the repository", o.Version)
		return p, nil
	}
	if p.Target == p.Installed {
		p.Warnings = append(p.Warnings, "corelight-fleet "+p.Installed+" is already installed")
		return p, nil
	}
	if cmp, err := u.compare(ctx, p.Target, p.Installed); err != nil {
		return nil, err
	} else if cmp < 0 {
		p.Downgrade = true
		if !o.AllowDowngrade {
			block("%s is older than the installed %s; a downgrade needs allow_downgrade, and Fleet Manager's database may not work with an older version", p.Target, p.Installed)
		} else {
			p.Warnings = append(p.Warnings, "downgrading: Fleet Manager's database was migrated by the newer version and may not work with the older one; keep the backup")
		}
	}
	if !o.Backup {
		p.Warnings = append(p.Warnings, "no backup first: without one, a failed upgrade cannot be undone")
	} else if u.StartBackup == nil {
		block("a backup first needs the Fleet Manager's API: give fleet, or set backup to false")
	}
	if o.Backup {
		p.Steps = append(p.Steps, "make a Fleet Manager backup and wait for the new file in "+p.DataPath+"/backup")
		p.Warnings = append(p.Warnings, "Fleet Manager keeps one backup: the new one replaces the current backup image (download it first from the web interface if you need it)")
	}
	p.Steps = append(p.Steps,
		fmt.Sprintf("apt-get install corelight-fleet=%s, keeping the existing corelight-fleetd.conf", p.Target),
		"restart corelight-fleetd and wait up to 2 minutes for its API; the web interface is down meanwhile and sensors reconnect on their own",
		"check the installed version")
	p.Warnings = append(p.Warnings, "this changes Fleet Manager only; sensors keep their software version (see fm_sensor_updates_status)")
	return p, nil
}

// pickVersion returns the first (newest; madison lists newest first)
// version starting with want, or the newest when want is empty.
func pickVersion(avail []string, want string) string {
	for _, v := range avail {
		if want == "" || v == want || strings.HasPrefix(v, want+"-") || strings.HasPrefix(v, want+".") {
			return v
		}
	}
	return ""
}

// compare returns -1, 0 or 1 as a is older than, equal to or newer than b,
// by Debian version rules.
func (u *Upgrader) compare(ctx context.Context, a, b string) (int, error) {
	res, err := u.R.Run(ctx, fmt.Sprintf("if dpkg --compare-versions %s lt %s; then echo -1; elif dpkg --compare-versions %s gt %s; then echo 1; else echo 0; fi",
		host.Quote(a), host.Quote(b), host.Quote(a), host.Quote(b)))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(res.Stdout))
}

// UpgradeResult is what an upgrade did.
type UpgradeResult struct {
	Done    []string `json:"done"`
	Backup  string   `json:"backup,omitempty"`
	Version string   `json:"version,omitempty"`
}

// Apply makes the backup, installs the version, restarts and verifies.
func (u *Upgrader) Apply(ctx context.Context, p *UpgradePlan) (*UpgradeResult, error) {
	if !p.Ready() {
		return nil, fmt.Errorf("nothing to install, or blocked: %s", strings.Join(p.Blockers, "; "))
	}
	out := &UpgradeResult{}
	if p.Backup {
		file, err := u.backup(ctx, p.DataPath)
		if err != nil {
			return out, fmt.Errorf("backup failed, nothing was upgraded: %w", err)
		}
		out.Backup = file
		out.Done = append(out.Done, "backup "+file)
	}
	allow := ""
	if p.Downgrade {
		allow = "--allow-downgrades "
	}
	script := fmt.Sprintf(`set -e
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -q %s-o Dpkg::Options::=--force-confold %s=%s >/tmp/fleet-mcp-apt.log 2>&1 || { tail -n 15 /tmp/fleet-mcp-apt.log >&2; exit 1; }
systemctl restart %s
%s
`, allow, pkgName, host.Quote(p.Target), serviceName, waitScript)
	res, err := u.R.Run(ctx, script)
	if err != nil {
		return out, err
	}
	if !res.OK() {
		msg := strings.TrimSpace(res.Stderr)
		if strings.Contains(msg, "]: ERROR: ") {
			msg = failReason(msg)
		}
		return out, fmt.Errorf("installing %s failed: %s", p.Target, msg)
	}
	out.Done = append(out.Done, "installed corelight-fleet "+p.Target+" and restarted ("+lastLine(res.Stdout)+")")
	in := &Installer{R: u.R}
	got, err := in.installedVersion(ctx)
	if err != nil {
		return out, err
	}
	out.Version = got
	if got != p.Target {
		return out, fmt.Errorf("corelight-fleet %s is installed, not %s", got, p.Target)
	}
	return out, nil
}

// backup starts a Fleet Manager backup and waits for its file, a new
// fleet_backup_*.zip in the data path's backup directory whose size has
// stopped changing.
func (u *Upgrader) backup(ctx context.Context, dataPath string) (string, error) {
	dir := host.Quote(strings.TrimRight(dataPath, "/") + "/backup")
	res, err := u.R.Run(ctx, "date +%s")
	if err != nil {
		return "", err
	}
	since := strings.TrimSpace(res.Stdout)
	if err := u.StartBackup(ctx); err != nil {
		return "", err
	}
	timeout := u.BackupTimeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	secs := int(timeout / (5 * time.Second))
	script := fmt.Sprintf(`last=""
for i in $(seq 1 %d); do
  f=$(find %s -maxdepth 1 -name 'fleet_backup_*.zip' -newermt "@%s" -printf '%%T@ %%p\n' 2>/dev/null | sort -n | tail -n 1 | cut -d' ' -f2-)
  if [ -n "$f" ]; then
    s=$(stat -c %%s "$f")
    if [ "$s" = "$last" ] && [ "$s" -gt 0 ]; then echo "$f $s"; exit 0; fi
    last=$s
  fi
  sleep 5
done
echo "no new backup file in %s after %ds" >&2
exit 1
`, secs, dir, since, strings.Trim(dir, "'"), secs*5)
	res, err = u.R.Run(ctx, script)
	if err != nil {
		return "", err
	}
	if !res.OK() {
		return "", fmt.Errorf("%s", strings.TrimSpace(res.Stderr))
	}
	f := strings.Fields(strings.TrimSpace(res.Stdout))
	if len(f) == 2 {
		if n, err := strconv.ParseInt(f[1], 10, 64); err == nil {
			if n < 1<<20 {
				return fmt.Sprintf("%s (%d KB)", f[0], (n+512)>>10), nil
			}
			return fmt.Sprintf("%s (%d MB)", f[0], (n+1<<19)>>20), nil
		}
	}
	return strings.TrimSpace(res.Stdout), nil
}
