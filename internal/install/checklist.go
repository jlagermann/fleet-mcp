package install

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jlagermann/fleet-mcp/internal/host"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
)

// ItemStatus is the state of one checklist item.
type ItemStatus string

const (
	Ready     ItemStatus = "ready"
	Missing   ItemStatus = "missing"
	Problem   ItemStatus = "problem"
	Unchecked ItemStatus = "unchecked"
	Optional  ItemStatus = "optional"
	Decide    ItemStatus = "decide"
	Note      ItemStatus = "note"
)

// Item is one thing the user provides or decides before an install.
type Item struct {
	Section  string     `json:"section"`
	Item     string     `json:"item"`
	Required bool       `json:"required"`
	Status   ItemStatus `json:"status"`
	Detail   string     `json:"detail,omitempty"`
	HowTo    string     `json:"how_to"`
}

// Checklist lists everything the user provides for an install, with the
// status of what can be checked: stored secrets always, and the host when
// r is not nil.
func Checklist(ctx context.Context, store *secrets.Store, hostName string, r host.Runner) ([]Item, error) {
	var items []Item
	add := func(it Item) { items = append(items, it) }

	// --- Host ---
	var rep *Report
	var checkErr error
	if r != nil {
		rep, checkErr = Check(ctx, r)
	}
	finding := func(checks ...string) (ItemStatus, string) {
		if r == nil {
			return Unchecked, "give the host to check it"
		}
		if checkErr != nil {
			return Problem, checkErr.Error()
		}
		st, detail := Ready, ""
		for _, f := range rep.Findings {
			for _, c := range checks {
				if f.Check != c {
					continue
				}
				if detail != "" {
					detail += "; "
				}
				detail += f.Detail
				if f.Level == Fail || (f.Level == Warn && blockingWarnings[c]) {
					st = Problem
				}
			}
		}
		return st, detail
	}

	st, d := finding()
	if r != nil && checkErr == nil {
		st, d = Ready, "connected as "+r.Name()+" with passwordless sudo"
	}
	add(Item{"Host", "SSH access from this machine with key authentication (no password prompt) to a user with passwordless sudo; the host key already accepted in known_hosts", true, st, d,
		"Set up an SSH key for the host and run `ssh <user>@<host> sudo -n true` once from this machine."})
	st, d = finding("os", "arch")
	add(Item{"Host", "Ubuntu 22.04 or 24.04 LTS, x86_64", true, st, d, "Install a supported Ubuntu release on the host."})
	st, d = finding("cpus", "memory", "var_space", "tmp_space", "shared_space")
	add(Item{"Host", "Resources for up to 10 sensors: 2+ vCPUs, 8 GB memory, 50 GB storage with 30 GB free for /var and 20 GB for /tmp (more for more sensors). Any shortfall stops the install.", true, st, d,
		"Add CPU, memory or disk to the host (on Ubuntu LVM installs, unallocated volume-group space can be added with lvextend -r)."})
	st, d = finding("port_443", "port_1443")
	add(Item{"Host", "Ports 443 (web UI and API, from admin networks and this machine) and 1443 (from sensor management interfaces) free on the host and allowed through firewalls", true, st, d,
		"Stop anything using 443/1443, and open them in host and network firewalls."})
	st, d = finding("repository")
	add(Item{"Host", "Outbound HTTPS from the host to pkgrepos.corelight.cloud", true, st, d, "Allow the host to reach pkgrepos.corelight.cloud:443 (or use an offline install, not yet automated)."})
	st, d = finding("time_sync")
	if st == Ready && rep != nil {
		for _, f := range rep.Findings {
			if f.Check == "time_sync" {
				st = Problem
			}
		}
		if st == Ready {
			d = "clock is NTP-synchronized"
		}
	}
	add(Item{"Host", "Clock synchronized with NTP (recommended; TLS with sensors depends on correct time)", false, st, d, "Configure NTP on the host and confirm it synchronizes."})

	// --- From Corelight ---
	if store != nil {
		tokenStatus, tokenDetail := Missing, ""
		if _, err := store.GetString("", secrets.RepoToken); err == nil {
			tokenStatus, tokenDetail = Ready, "stored"
		}
		add(Item{"From Corelight", "Package repository auth token (Corelight Customer Portal → Downloads → Fleet Manager)", true, tokenStatus, tokenDetail,
			"In a terminal on this machine: fleet-mcp secret set repo-token (hidden prompt). Never paste it into the chat."})

		certStatus, certDetail := Missing, ""
		if b, err := store.Get("", secrets.IdentityCert); err == nil {
			if sum, err := secrets.ValidateIdentityCert(b); err != nil {
				certStatus, certDetail = Problem, err.Error()
			} else {
				certStatus = Ready
				certDetail = fmt.Sprintf("%s, expires %s (%d days)", sum.Subject, sum.NotAfter.Format("2006-01-02"), sum.DaysLeft)
				if time.Until(sum.NotAfter) < 30*24*time.Hour {
					certStatus, certDetail = Problem, certDetail+"; renew it with Corelight soon"
				}
			}
		}
		add(Item{"From Corelight", "Fleet Manager product identity certificate (.pem with certificate and private key; it carries the Fleet Manager license)", true, certStatus, certDetail,
			"Save the .pem from Corelight on this machine, then import it with fm_secret_import_file (name identity-cert.pem and the file path) or: fleet-mcp secret import identity-cert.pem <path>."})

		licStatus := Optional
		if _, err := store.Get("", secrets.SensorLicense); err == nil {
			licStatus = Ready
		}
		add(Item{"From Corelight", "Software Sensor license (only if Fleet Manager will license Software Sensors)", false, licStatus, "",
			"Import it with fm_secret_import_file (name sensor-license.txt) or: fleet-mcp secret import sensor-license.txt <path>."})

		csStatus, csDetail := Optional, "will be generated"
		if hostName != "" {
			if _, err := store.GetString(hostName, secrets.CommunityString); err == nil {
				csStatus, csDetail = Ready, "stored for this host"
			}
		}
		add(Item{"Your choices", "Sensor community string (pre-shared secret sensors use to connect). Generated if you do not set one; set your own if existing sensors already use a value.", false, csStatus, csDetail,
			"To use your own: fleet-mcp secret set community-string -host <host>. To read it later for pairing sensors: fleet-mcp secret show community-string -host <host> (your terminal only)."})
	}

	add(Item{"Your choices", "Fleet Manager version (default: newest in the repository)", false, Decide, "", "Pass version, e.g. 29.2.2, to pin one."})
	add(Item{"Your choices", "Agent user name (default claude): the Fleet Manager admin user the agent logs in as; its password is generated and kept only by fleet-mcp", false, Decide, "", "Pass agent_user to choose another name."})
	add(Item{"Your choices", "Address you will use for Fleet Manager (default https://<host>); a DNS name is better for a lasting install", false, Decide, "", "Pass url if this machine should reach it by another name."})
	add(Item{"Your choices", "Serve the REST API spec (expose-swagger; default on, so fleet-mcp can describe and check API calls; Fleet Manager serves no REST spec without it)", false, Decide, "", "Pass expose_swagger false to leave it off."})
	add(Item{"After the install", "You receive the admin user's temporary password; Fleet Manager requires a new one at first login. fleet-mcp keeps no admin password.", true, Note, "",
		"Log in at the Fleet Manager address as admin right after the install and set your password."})
	return items, nil
}

// ChecklistReady reports whether every required item that can be checked
// is ready (Unchecked and Decide items are not blocking).
func ChecklistReady(items []Item) bool {
	for _, it := range items {
		if it.Required && (it.Status == Missing || it.Status == Problem) {
			return false
		}
	}
	return true
}

var statusMark = map[ItemStatus]string{
	Note: "[i] note", Ready: "[x]", Missing: "[ ] MISSING", Problem: "[!] PROBLEM", Unchecked: "[?] not checked", Optional: "[-] optional", Decide: "[~] your choice",
}

// RenderChecklist formats the checklist as Markdown for display.
func RenderChecklist(items []Item) string {
	var b strings.Builder
	b.WriteString("## Fleet Manager install checklist\n")
	section := ""
	for _, it := range items {
		if it.Section != section {
			section = it.Section
			b.WriteString("\n### " + section + "\n")
		}
		req := ""
		if it.Required {
			req = " (required)"
		}
		fmt.Fprintf(&b, "- %s %s%s\n", statusMark[it.Status], it.Item, req)
		if it.Detail != "" {
			fmt.Fprintf(&b, "  - %s\n", it.Detail)
		}
		if it.Status == Missing || it.Status == Problem || it.Status == Unchecked {
			fmt.Fprintf(&b, "  - How: %s\n", it.HowTo)
		}
	}
	if ChecklistReady(items) {
		b.WriteString("\nEverything required that can be checked is ready.\n")
	} else {
		b.WriteString("\nResolve the MISSING and PROBLEM items before installing.\n")
	}
	return b.String()
}
