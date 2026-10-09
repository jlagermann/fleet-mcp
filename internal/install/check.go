// Package install installs and sets up Fleet Manager on a Linux host.
package install

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jlagermann/fleet-mcp/internal/host"
)

// Level grades one readiness finding.
type Level string

const (
	Pass Level = "pass"
	Warn Level = "warn"
	Fail Level = "fail"
	Info Level = "info"
)

// Finding is one readiness result.
type Finding struct {
	Check  string `json:"check"`
	Level  Level  `json:"level"`
	Detail string `json:"detail"`
}

// Report is the result of a host readiness check.
type Report struct {
	Host     string            `json:"host"`
	Ready    bool              `json:"ready"`
	Findings []Finding         `json:"findings"`
	Facts    map[string]string `json:"facts"`
}

// Documented Fleet Manager minimums for up to 10 sensors.
const (
	minMemMB   = 8 * 1024
	minCPUs    = 2
	minVarGB   = 30
	minTmpGB   = 20
	minTotalGB = 50
)

const factsScript = `
. /etc/os-release 2>/dev/null
echo "os_id=${ID:-}"
echo "os_version=${VERSION_ID:-}"
echo "os_name=${PRETTY_NAME:-}"
echo "arch=$(uname -m)"
echo "cpus=$(nproc)"
echo "mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)"
echo "var_free_gb=$(df -BG --output=avail /var | tail -1 | tr -dc 0-9)"
echo "tmp_free_gb=$(df -BG --output=avail /tmp | tail -1 | tr -dc 0-9)"
echo "var_fs=$(df --output=target /var | tail -1)"
echo "tmp_fs=$(df --output=target /tmp | tail -1)"
echo "var_size_gb=$(df -BG --output=size /var | tail -1 | tr -dc 0-9)"
for p in 443 1443; do
  owner=$(ss -Hltnp "sport = :$p" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -1)
  if ss -Hltn "sport = :$p" 2>/dev/null | grep -q .; then echo "port_${p}=${owner:-in-use}"; else echo "port_${p}=free"; fi
done
echo "fleet_pkg=$(dpkg-query -W -f='${Status}|${Version}' corelight-fleet 2>/dev/null || rpm -q --qf '%{VERSION}-%{RELEASE}' corelight-fleet 2>/dev/null)"
echo "fleet_service=$(systemctl is-active corelight-fleetd 2>/dev/null)"
echo "fleet_conf=$(test -f /etc/corelight-fleetd.conf && echo present || echo absent)"
echo "identity_pem=$(test -s /etc/corelight-fleetd.pem && echo present || echo absent)"
echo "repo_configured=$(test -f /etc/apt/sources.list.d/corelight_fleet-stable.list -o -f /etc/yum.repos.d/corelight_fleet-stable.repo && echo yes || echo no)"
echo "repo_http=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://pkgrepos.corelight.cloud/corelight/fleet-stable/gpgkey 2>/dev/null)"
echo "docker=$(command -v docker >/dev/null && docker --version 2>/dev/null | head -1)"
echo "ufw=$(command -v ufw >/dev/null && ufw status 2>/dev/null | head -1 | sed 's/Status: //')"
echo "firewalld=$(systemctl is-active firewalld 2>/dev/null)"
echo "ntp_synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
echo "hostname=$(hostname -f 2>/dev/null || hostname)"
echo "python3=$(python3 --version 2>/dev/null | cut -d' ' -f2)"
`

// ParseFacts reads key=value lines.
func ParseFacts(s string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// Check gathers facts about a host and grades them.
func Check(ctx context.Context, r host.Runner) (*Report, error) {
	res, err := r.Run(ctx, factsScript)
	if err != nil {
		return nil, err
	}
	facts := ParseFacts(res.Stdout)
	if facts["os_id"] == "" && facts["arch"] == "" {
		return nil, fmt.Errorf("no facts returned from %s: %s", r.Name(), strings.TrimSpace(res.Stderr))
	}
	rep := Grade(facts)
	rep.Host = r.Name()
	return rep, nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// Grade turns facts into findings.
func Grade(f map[string]string) *Report {
	rep := &Report{Facts: f, Ready: true}
	add := func(check string, l Level, format string, a ...any) {
		rep.Findings = append(rep.Findings, Finding{Check: check, Level: l, Detail: fmt.Sprintf(format, a...)})
		if l == Fail {
			rep.Ready = false
		}
	}

	switch os := f["os_id"] + " " + f["os_version"]; {
	case f["os_id"] == "ubuntu" && (f["os_version"] == "22.04" || f["os_version"] == "24.04"):
		add("os", Pass, "%s is supported", f["os_name"])
	case (f["os_id"] == "rhel" || f["os_id"] == "almalinux") && (strings.HasPrefix(f["os_version"], "8") || strings.HasPrefix(f["os_version"], "9")):
		add("os", Warn, "%s is supported by Fleet Manager, but fm_host_install only automates Ubuntu so far", f["os_name"])
	default:
		add("os", Fail, "%s (%s) is not a supported Fleet Manager OS (Ubuntu 22.04/24.04, RHEL/AlmaLinux 8/9)", f["os_name"], strings.TrimSpace(os))
	}
	if f["arch"] == "x86_64" {
		add("arch", Pass, "x86_64")
	} else {
		add("arch", Fail, "%s; Fleet Manager packages are x86_64 only", f["arch"])
	}

	if n := atoi(f["cpus"]); n >= minCPUs {
		add("cpus", Pass, "%d vCPUs (minimum %d)", n, minCPUs)
	} else {
		add("cpus", Warn, "%d vCPUs; Fleet Manager recommends at least %d", n, minCPUs)
	}
	// MemTotal excludes kernel-reserved memory, so allow ~5% under.
	if mb := atoi(f["mem_mb"]); mb >= minMemMB*95/100 {
		add("memory", Pass, "%d MB (minimum %d MB for up to 10 sensors)", mb, minMemMB)
	} else {
		add("memory", Warn, "%d MB; Fleet Manager recommends at least %d MB for up to 10 sensors (16 GB for 11-200)", mb, minMemMB)
	}
	varFree, tmpFree := atoi(f["var_free_gb"]), atoi(f["tmp_free_gb"])
	if varFree >= minVarGB {
		add("var_space", Pass, "%d GB free on %s (minimum %d GB)", varFree, f["var_fs"], minVarGB)
	} else {
		add("var_space", Warn, "%d GB free on %s; the docs ask for at least %d GB for /var (50 GB storage for up to 10 sensors)", varFree, f["var_fs"], minVarGB)
	}
	if tmpFree >= minTmpGB {
		add("tmp_space", Pass, "%d GB free on %s (minimum %d GB)", tmpFree, f["tmp_fs"], minTmpGB)
	} else {
		add("tmp_space", Warn, "%d GB free on %s; the docs ask for at least %d GB for /tmp", tmpFree, f["tmp_fs"], minTmpGB)
	}
	if f["var_fs"] == f["tmp_fs"] && varFree < minVarGB+minTmpGB {
		add("shared_space", Warn, "/var and /tmp share %s, so both minimums (%d GB together) come from the same %d GB", f["var_fs"], minVarGB+minTmpGB, varFree)
	}

	installed := strings.HasPrefix(f["fleet_pkg"], "install ok installed")
	for _, p := range []string{"443", "1443"} {
		switch owner := f["port_"+p]; {
		case owner == "free":
			add("port_"+p, Pass, "port %s is free", p)
		case strings.Contains(owner, "corelight-fleet"):
			add("port_"+p, Info, "port %s is used by Fleet Manager", p)
		default:
			add("port_"+p, Fail, "port %s is in use by %s; Fleet Manager needs it (or change bind-address)", p, owner)
		}
	}

	switch code := f["repo_http"]; code {
	case "401", "200":
		add("repository", Pass, "pkgrepos.corelight.cloud is reachable (HTTP %s)", code)
	case "", "000":
		add("repository", Fail, "cannot reach pkgrepos.corelight.cloud; online installs need HTTPS access to it (use an offline install otherwise)")
	default:
		add("repository", Warn, "pkgrepos.corelight.cloud answered HTTP %s", code)
	}

	if installed {
		ver := f["fleet_pkg"][strings.LastIndex(f["fleet_pkg"], "|")+1:]
		add("existing_install", Info, "corelight-fleet %s is installed; service is %s", ver, f["fleet_service"])
	} else {
		add("existing_install", Info, "Fleet Manager is not installed")
	}
	if f["ufw"] == "active" || f["firewalld"] == "active" {
		add("firewall", Warn, "a host firewall is active; allow inbound 443 (admins) and 1443 (sensors)")
	}
	if f["ntp_synced"] != "" && f["ntp_synced"] != "yes" {
		add("time_sync", Warn, "the clock is not NTP-synchronized; TLS with sensors depends on correct time")
	}
	return rep
}
