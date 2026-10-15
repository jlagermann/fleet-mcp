package hostdiag

import (
	"strings"
	"testing"
	"time"
)

const sample = `### service
corelight-fleetd active running restarts=2 since=Thu_2026-10-15_08:00:00_CDT
### version
installed 29.2.2-1
candidate 29.2.3-1
### resources
cpus 4
load 9.10 2.00 1.00
memtotal 16000
memavail 1000
### disks
/ 61000 5000 92%
/tmp 61000 5000 92%
### datapath
path /var/lib/corelight-fleetd
350 sensor-catalog
1 admin
### certs
tls /etc/corelight-fleetd.pem
path /etc/corelight-fleetd.pem
subject=CN = internal.example.fleet.product.corelight.io
issuer=CN = Corelight Product CA
notAfter=Feb 27 12:00:00 2027 GMT
path /etc/corelight-fleetd.pem
subject=CN = internal.example.fleet.product.corelight.io
issuer=CN = Corelight Product CA
notAfter=Feb 27 12:00:00 2027 GMT
### journal
{"time":"2026-10-15T08:11:39-05:00","level":"ERROR","message":"sensor 3d-57-a1-4d-83-d1-ad-42 request failed 500"}
{"time":"2026-10-15T08:12:39-05:00","level":"ERROR","message":"sensor 12-17-96-78-8a-ad-35-96 request failed 500"}
2026-10-15T08:14:21.661-0500 WARN update-manager.manager/worker updater.git@v0.9.8/worker.go:501 slow rule build 12 s
### ports
0.0.0.0:443
### time
NTPSynchronized=no
Timezone=America/Chicago
### perms
640 root:corelight-fleetd /etc/corelight-fleetd.conf
644 root:root /etc/corelight-fleetd.conf.bak-20261009-172908
400 corelight-fleetd:corelight-fleetd /etc/corelight-fleetd.pem
644 root:root /etc/corelight-fleet-ldap.ini 1
644 root:root /etc/corelight-fleet-saml.ini 0
### backup
### end
`

func TestParse(t *testing.T) {
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	r := parse(sample, now)
	msgs := ""
	for _, f := range r.Findings {
		msgs += f.Severity + " " + f.Area + ": " + f.Message + "\n"
	}
	for _, want := range []string{
		"error ports: nothing listens on port 1443 (sensor connections)",
		"warning service: corelight-fleetd restarted 2 time(s)",
		"warning memory: only 1000 of 16000 MB memory available",
		"warning cpu: load 9.1 on 4 CPUs",
		"warning disk: / is 92% full",
		"warning time: the clock is not NTP-synchronized",
		"warning permissions: files that may hold secrets",
		"/etc/corelight-fleetd.conf.bak-20261009-172908 (644)",
		"/etc/corelight-fleet-ldap.ini (644)",

		"info version: corelight-fleet 29.2.2-1 is installed; 29.2.3-1 is available",
		"info certificate: /etc/corelight-fleetd.pem (product identity (sensor connections) and TLS (web interface and API)) expires in 88 days",
		"info journal: 2 error and 1 warning lines",
		"info backup: no backup file",
	} {
		if !strings.Contains(msgs, want) {
			t.Errorf("findings lack %q:\n%s", want, msgs)
		}
	}
	if strings.Contains(msgs, "saml.ini") {
		t.Error("an unconfigured template is not a secret")
	}
	if strings.Contains(msgs, "/etc/corelight-fleetd.conf (640)") {
		t.Error("0640 is not world-readable")
	}
	if len(r.Certs) != 1 || r.Certs[0].DaysLeft != 88 {
		t.Errorf("certs: %+v", r.Certs)
	}
	if r.Journal.Top["sensor N request failed N"] != 2 {
		t.Errorf("journal top: %v", r.Journal.Top)
	}
	if r.Findings[0].Severity != "error" {
		t.Errorf("errors first: %v", r.Findings[0])
	}
}
