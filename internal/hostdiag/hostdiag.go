// Package hostdiag checks the health of a Fleet Manager host over SSH,
// read-only: the service, version, resources, data path, journal,
// certificates, ports, time sync and file permissions.
package hostdiag

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jlagermann/fleet-mcp/internal/host"
)

// Finding is one result.
type Finding struct {
	Severity string `json:"severity"` // error, warning, info
	Area     string `json:"area"`
	Message  string `json:"message"`
	Fix      string `json:"fix,omitempty"`
}

// Report is the diagnosis of one host.
type Report struct {
	Host     string            `json:"host"`
	Service  map[string]string `json:"service"`
	Version  map[string]string `json:"version"`
	Memory   map[string]int64  `json:"memory_mb,omitempty"`
	Load     string            `json:"load,omitempty"`
	CPUs     int               `json:"cpus,omitempty"`
	Disks    []Disk            `json:"disks,omitempty"`
	DataPath map[string]int64  `json:"data_path_mb,omitempty"`
	Certs    []Cert            `json:"certificates,omitempty"`
	Journal  Journal           `json:"journal_24h"`
	Ports    []string          `json:"listening,omitempty"`
	Findings []Finding         `json:"findings"`
}

// Disk is one filesystem.
type Disk struct {
	Mount  string `json:"mount"`
	SizeMB int64  `json:"size_mb"`
	FreeMB int64  `json:"free_mb"`
	UsePct int    `json:"use_pct"`
}

// Cert is one certificate file.
type Cert struct {
	Path     string `json:"path"`
	Use      string `json:"use"`
	Subject  string `json:"subject"`
	Issuer   string `json:"issuer"`
	NotAfter string `json:"not_after"`
	DaysLeft int    `json:"days_left"`
}

// Journal summarizes the service's warnings and errors.
type Journal struct {
	Errors   int            `json:"errors"`
	Warnings int            `json:"warnings"`
	Top      map[string]int `json:"top_messages,omitempty"`
}

const conf = "/etc/corelight-fleetd.conf"

// script prints sections headed "### <name>". It only reads.
const script = `C=` + conf + `
section() { echo "### $1"; }
val() { grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" $C 2>/dev/null | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/'; }
DP=$(val data-path); [ -n "$DP" ] || DP=/var/lib/corelight-fleetd
CERT=$(val ssl-certificate-path)
section service
for u in corelight-fleetd corelight-fleetd-ldap-auth; do
  systemctl cat $u >/dev/null 2>&1 || continue
  # Optional units (LDAP authentication) only matter when enabled.
  [ $u = corelight-fleetd ] || [ "$(systemctl is-enabled $u 2>/dev/null)" = enabled ] || continue
  echo "$u $(systemctl show -p ActiveState --value $u) $(systemctl show -p SubState --value $u) restarts=$(systemctl show -p NRestarts --value $u) since=$(systemctl show -p ActiveEnterTimestamp --value $u | tr ' ' '_')"
done
section version
echo "installed $(dpkg-query -W -f='${Version}' corelight-fleet 2>/dev/null)"
echo "candidate $(apt-cache policy corelight-fleet 2>/dev/null | awk '/Candidate:/{print $2}')"
section resources
echo "cpus $(nproc)"
echo "load $(cut -d' ' -f1-3 /proc/loadavg)"
awk '/^MemTotal:/{print "memtotal", int($2/1024)} /^MemAvailable:/{print "memavail", int($2/1024)}' /proc/meminfo
section disks
df -Pm / /tmp "$DP" 2>/dev/null | awk 'NR>1{print $6, $2, $4, $5}' | sort -u
section datapath
echo "path $DP"
for d in "$DP"/*; do [ -e "$d" ] && echo "$(du -sm "$d" 2>/dev/null | cut -f1) $(basename "$d")"; done
section certs
echo "tls $CERT"
for p in "$CERT" /etc/corelight-fleetd.pem; do
  [ -n "$p" ] && [ -f "$p" ] || continue
  echo "path $p"
  openssl x509 -noout -subject -issuer -enddate -in "$p" 2>/dev/null
done
section journal
journalctl -u corelight-fleetd --since "-24h" --no-pager -o cat 2>/dev/null | grep -E '"level":"(ERROR|WARN|WARNING|FATAL)"|[[:space:]](ERROR|WARN|FATAL)[[:space:]]' | tail -n 2000
section ports
ss -Hltn 2>/dev/null | awk '{print $4}' | grep -E ':(443|1443)$' | sort -u
section time
timedatectl show -p NTPSynchronized -p Timezone 2>/dev/null
for d in ntpsec ntp chrony systemd-timesyncd; do [ "$(systemctl is-active $d 2>/dev/null)" = active ] && echo "daemon=$d"; done
if command -v ntpq >/dev/null 2>&1; then
  ntpq -c rv 2>/dev/null | grep -q sync_unspec && echo "ntpd=unsynchronized"
  ntpq -pn 2>/dev/null | awk 'NR>2 && $9 ~ /^-?[0-9.]+$/ && $7 != "0" { o = $9 < 0 ? -$9 : $9; if (o > m) m = o } END { if (m != "") print "maxoffsetms=" m }'
fi
command -v chronyc >/dev/null 2>&1 && chronyc tracking 2>/dev/null | awk -F': ' '/System time/{print "chrony=" $2}'
section perms
for f in $C $C.* /etc/corelight-fleetd.pem* /etc/corelight-fleet-license.txt* /etc/corelight-fleet-*.ini /etc/corelight-fleet-*.toml; do
  [ -f "$f" ] || continue
  # Authentication templates hold a secret only once a password is filled in.
  case "$f" in
    *.ini|*.toml) n=$(grep -cE '^[[:space:]]*[A-Za-z_.-]*(pass|secret)[A-Za-z_.-]*[[:space:]]*[=:][[:space:]]*[^[:space:]#;]' "$f") ;;
    *) n=- ;;
  esac
  echo "$(stat -c '%a %U:%G %n' "$f") $n"
done
section backup
ls -1t "$DP"/backup 2>/dev/null | head -1 | while read f; do stat -c '%Y %n' "$DP/backup/$f"; done
section end
`

// Run diagnoses the host behind r.
func Run(ctx context.Context, r host.Runner) (*Report, error) {
	res, err := r.Run(ctx, script)
	if err != nil {
		return nil, err
	}
	if !res.OK() && !strings.Contains(res.Stdout, "### end") {
		return nil, fmt.Errorf("the diagnosis script failed on %s (%d): %s", r.Name(), res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	rep := parse(res.Stdout, time.Now())
	rep.Host = r.Name()
	return rep, nil
}

func sections(out string) map[string][]string {
	s := map[string][]string{}
	cur := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if name, ok := strings.CutPrefix(line, "### "); ok {
			cur = name
			continue
		}
		if cur != "" && strings.TrimSpace(line) != "" {
			s[cur] = append(s[cur], line)
		}
	}
	return s
}

var (
	jsonMsg    = regexp.MustCompile(`"message":"([^"]*)"`)
	textMsg    = regexp.MustCompile(`\s(?:ERROR|WARN|FATAL)\s+\S+\s+\S+\s+(.*)$`)
	numbers    = regexp.MustCompile(`[0-9a-f]{2}(-[0-9a-f]{2}){7}|\b[0-9a-f]{12,}\b|\b\d+\b`)
	worldBits  = regexp.MustCompile(`^[0-7]{2}[4-7]$`)
	secretFile = regexp.MustCompile(`corelight-fleetd\.conf|corelight-fleetd\.pem|license|ldap\.ini|radius\.toml|saml\.ini`)
)

func parse(out string, now time.Time) *Report {
	sec := sections(out)
	r := &Report{Service: map[string]string{}, Version: map[string]string{}, Memory: map[string]int64{}, DataPath: map[string]int64{}}
	add := func(sev, area, msg, fix string) {
		r.Findings = append(r.Findings, Finding{Severity: sev, Area: area, Message: msg, Fix: fix})
	}

	// Service.
	if len(sec["service"]) == 0 {
		add("error", "service", "corelight-fleetd is not installed as a service", "")
	}
	for _, l := range sec["service"] {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		r.Service[f[0]] = strings.Join(f[1:], " ")
		if f[1] != "active" {
			add("error", "service", fmt.Sprintf("%s is %s (%s)", f[0], f[1], f[2]), "sudo systemctl status "+f[0]+"; sudo journalctl -u "+f[0]+" -n 100")
		}
		if n, _ := strconv.Atoi(strings.TrimPrefix(f[3], "restarts=")); n > 0 {
			add("warning", "service", fmt.Sprintf("%s restarted %d time(s) since it was started", f[0], n), "")
		}
	}

	// Version.
	for _, l := range sec["version"] {
		k, v, _ := strings.Cut(l, " ")
		r.Version[k] = strings.TrimSpace(v)
	}
	if in, c := r.Version["installed"], r.Version["candidate"]; in != "" && c != "" && c != "(none)" && in != c {
		add("info", "version", fmt.Sprintf("corelight-fleet %s is installed; %s is available from the package repository", in, c), "")
	}

	// Resources.
	for _, l := range sec["resources"] {
		k, v, _ := strings.Cut(l, " ")
		switch k {
		case "cpus":
			r.CPUs, _ = strconv.Atoi(v)
		case "load":
			r.Load = v
		case "memtotal", "memavail":
			r.Memory[k], _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if t, a := r.Memory["memtotal"], r.Memory["memavail"]; t > 0 && a*10 < t {
		add("warning", "memory", fmt.Sprintf("only %d of %d MB memory available", a, t), "")
	}
	if f := strings.Fields(r.Load); len(f) > 0 && r.CPUs > 0 {
		if l, err := strconv.ParseFloat(f[0], 64); err == nil && l > float64(r.CPUs)*1.5 {
			add("warning", "cpu", fmt.Sprintf("load %.1f on %d CPUs", l, r.CPUs), "")
		}
	}

	// Disks.
	for _, l := range sec["disks"] {
		f := strings.Fields(l)
		if len(f) != 4 {
			continue
		}
		d := Disk{Mount: f[0]}
		d.SizeMB, _ = strconv.ParseInt(f[1], 10, 64)
		d.FreeMB, _ = strconv.ParseInt(f[2], 10, 64)
		d.UsePct, _ = strconv.Atoi(strings.TrimSuffix(f[3], "%"))
		r.Disks = append(r.Disks, d)
		switch {
		case d.UsePct >= 95:
			add("error", "disk", fmt.Sprintf("%s is %d%% full (%d MB free)", d.Mount, d.UsePct, d.FreeMB), "")
		case d.UsePct >= 85:
			add("warning", "disk", fmt.Sprintf("%s is %d%% full (%d MB free)", d.Mount, d.UsePct, d.FreeMB), "")
		}
	}

	// Data path.
	path := ""
	for _, l := range sec["datapath"] {
		if p, ok := strings.CutPrefix(l, "path "); ok {
			path = p
			continue
		}
		n, name, ok := strings.Cut(l, " ")
		if !ok {
			continue
		}
		mb, _ := strconv.ParseInt(n, 10, 64)
		r.DataPath[name] = mb
	}
	if len(r.DataPath) == 0 && path != "" {
		add("warning", "data", "nothing found in the data path "+path, "")
	}

	// Certificates.
	var cur *Cert
	tlsPath := ""
	for _, l := range sec["certs"] {
		switch {
		case strings.HasPrefix(l, "tls "):
			tlsPath = strings.TrimSpace(strings.TrimPrefix(l, "tls "))
		case strings.HasPrefix(l, "path "):
			r.Certs = append(r.Certs, Cert{Path: strings.TrimPrefix(l, "path ")})
			cur = &r.Certs[len(r.Certs)-1]
		case cur == nil:
		case strings.HasPrefix(l, "subject="):
			cur.Subject = strings.TrimSpace(strings.TrimPrefix(l, "subject="))
		case strings.HasPrefix(l, "issuer="):
			cur.Issuer = strings.TrimSpace(strings.TrimPrefix(l, "issuer="))
		case strings.HasPrefix(l, "notAfter="):
			cur.NotAfter = strings.TrimPrefix(l, "notAfter=")
			if t, err := time.Parse("Jan _2 15:04:05 2006 MST", cur.NotAfter); err == nil {
				cur.DaysLeft = int(t.Sub(now).Hours() / 24)
			}
		}
	}
	seen := map[string]bool{}
	var certs []Cert
	for _, c := range r.Certs {
		if seen[c.Path] {
			continue
		}
		seen[c.Path] = true
		switch {
		case c.Path == "/etc/corelight-fleetd.pem" && c.Path == tlsPath:
			c.Use = "product identity (sensor connections) and TLS (web interface and API)"
		case c.Path == "/etc/corelight-fleetd.pem":
			c.Use = "product identity (sensor connections)"
		default:
			c.Use = "TLS (web interface and API)"
		}
		certs = append(certs, c)
		switch {
		case c.NotAfter == "":
			add("warning", "certificate", c.Path+": could not read the certificate", "")
		case c.DaysLeft < 0:
			add("error", "certificate", fmt.Sprintf("%s (%s) expired on %s", c.Path, c.Use, c.NotAfter), "")
		case c.DaysLeft < 30:
			add("warning", "certificate", fmt.Sprintf("%s (%s) expires in %d days (%s)", c.Path, c.Use, c.DaysLeft, c.NotAfter), "")
		case c.DaysLeft < 120:
			add("info", "certificate", fmt.Sprintf("%s (%s) expires in %d days (%s)", c.Path, c.Use, c.DaysLeft, c.NotAfter), "")
		}
	}
	r.Certs = certs

	// Journal.
	r.Journal.Top = map[string]int{}
	for _, l := range sec["journal"] {
		isErr := strings.Contains(l, `"level":"ERROR"`) || strings.Contains(l, `"level":"FATAL"`) || strings.Contains(l, " ERROR ") || strings.Contains(l, " FATAL ")
		if isErr {
			r.Journal.Errors++
		} else {
			r.Journal.Warnings++
		}
		msg := ""
		if m := jsonMsg.FindStringSubmatch(l); m != nil {
			msg = m[1]
		} else if m := textMsg.FindStringSubmatch(l); m != nil {
			msg = m[1]
		} else {
			msg = l
		}
		msg = numbers.ReplaceAllString(msg, "N")
		if len(msg) > 160 {
			msg = msg[:157] + "..."
		}
		r.Journal.Top[msg]++
	}
	if len(r.Journal.Top) > 8 {
		type kv struct {
			k string
			v int
		}
		var all []kv
		for k, v := range r.Journal.Top {
			all = append(all, kv{k, v})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
		r.Journal.Top = map[string]int{}
		for _, x := range all[:8] {
			r.Journal.Top[x.k] = x.v
		}
	}
	if len(r.Journal.Top) == 0 {
		r.Journal.Top = nil
	}
	if r.Journal.Errors > 0 {
		add("info", "journal", fmt.Sprintf("%d error and %d warning lines from corelight-fleetd in the last 24 hours (see journal_24h.top_messages)", r.Journal.Errors, r.Journal.Warnings), "")
	}

	// Ports.
	r.Ports = sec["ports"]
	for _, port := range []string{"443", "1443"} {
		found := false
		for _, l := range r.Ports {
			if strings.HasSuffix(l, ":"+port) {
				found = true
			}
		}
		if !found && len(r.Service) > 0 {
			use := "the web interface and API"
			if port == "1443" {
				use = "sensor connections"
			}
			add("error", "ports", fmt.Sprintf("nothing listens on port %s (%s)", port, use), "")
		}
	}

	// Time.
	synced, daemon, ntpdBad, maxOff := true, "", false, 0.0
	for _, l := range sec["time"] {
		switch {
		case strings.HasPrefix(l, "NTPSynchronized="):
			synced = strings.TrimPrefix(l, "NTPSynchronized=") == "yes"
		case strings.HasPrefix(l, "daemon="):
			daemon = strings.TrimPrefix(l, "daemon=")
		case l == "ntpd=unsynchronized":
			ntpdBad = true
		case strings.HasPrefix(l, "maxoffsetms="):
			maxOff, _ = strconv.ParseFloat(strings.TrimPrefix(l, "maxoffsetms="), 64)
		}
	}
	// timedatectl only knows systemd-timesyncd: with ntpd it says "no"
	// even when ntpd is in sync, so ntpd's own state decides then.
	unsynced := !synced
	if strings.HasPrefix(daemon, "ntp") {
		unsynced = ntpdBad
	}
	if unsynced || maxOff > 1000 {
		msg := "the clock is not NTP-synchronized"
		if daemon != "" {
			msg += " (" + daemon + ")"
		}
		if maxOff > 1000 {
			msg += fmt.Sprintf("; NTP servers see it up to %.0f seconds off", maxOff/1000)
		}
		add("warning", "time", msg+". Sensor connections, certificates and log times depend on a correct clock",
			"check the NTP servers in the daemon's configuration and that the host (or hypervisor) keeps time; ntpq -pn or chronyc sources")
	}

	// Permissions.
	var open []string
	for _, l := range sec["perms"] {
		f := strings.Fields(l)
		if len(f) == 3 {
			f = append(f, "-")
		}
		if len(f) == 4 && worldBits.MatchString(f[0]) && secretFile.MatchString(f[2]) && (f[3] == "-" || f[3] != "0") {
			open = append(open, fmt.Sprintf("%s (%s)", f[2], f[0]))
		}
	}
	if len(open) > 0 {
		add("warning", "permissions", "files that may hold secrets (community string, keys, license, directory credentials) are readable by every local user: "+strings.Join(open, ", "),
			"sudo chmod o-rwx <file> (a backup made by fleet-mcp before 2026-10-16 kept the package default 0644)")
	}

	// Backup.
	if l := sec["backup"]; len(l) > 0 {
		if ts, err := strconv.ParseInt(strings.Fields(l[0])[0], 10, 64); err == nil {
			age := now.Sub(time.Unix(ts, 0))
			if age > 8*24*time.Hour {
				add("warning", "backup", fmt.Sprintf("the newest backup in the data path is %d days old", int(age.Hours()/24)), "check the automatic backup schedule (fm_backups)")
			}
		}
	} else {
		add("info", "backup", "no backup file in the data path's backup directory", "fm_backups shows the backup schedule")
	}

	if len(r.Findings) == 0 {
		add("info", "summary", "no problems found", "")
	}
	sort.SliceStable(r.Findings, func(i, j int) bool { return rank(r.Findings[i].Severity) < rank(r.Findings[j].Severity) })
	return r
}

func rank(s string) int {
	switch s {
	case "error":
		return 0
	case "warning":
		return 1
	}
	return 2
}
