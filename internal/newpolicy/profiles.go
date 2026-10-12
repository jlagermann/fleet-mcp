// Package newpolicy builds a new sensor policy from a deployment profile
// (north-south or east-west) and the user's answers about access, network,
// exports, packages, detection, performance monitoring and updates.
package newpolicy

import "sort"

// Profiles a new policy can start from.
const (
	NorthSouth = "north-south"
	EastWest   = "east-west"
	NoProfile  = "none"

	// ICSOT is the collection of ICS/OT protocol analyzers.
	ICSOT = "ICS/OT"
)

// Where a recommendation comes from.
const (
	SourceDocsTable = "sensor docs: deployment recommendations table"
	SourceDocsPage  = "sensor docs: package page tag"
	SourceFleetMCP  = "fleet-mcp recommendation"
)

// Package is one Zeek package and whether each profile enables it.
type Package struct {
	Key        string `json:"key"` // bro.pkgs.corelight.<name>.loaded
	Name       string `json:"name"`
	Collection string `json:"collection"`
	NS         bool   `json:"north_south"`
	EW         bool   `json:"east_west"`
	// OptIn packages are never enabled by a profile, only on request:
	// ICS/OT protocols, environment-specific and advanced packages.
	OptIn  bool   `json:"opt_in,omitempty"`
	Source string `json:"source"`
	Why    string `json:"why"`
}

func pkg(name, collection, short string, ns, ew bool, source, why string) Package {
	return Package{Key: "bro.pkgs.corelight." + short + ".loaded", Name: name, Collection: collection, NS: ns, EW: ew, Source: source, Why: why}
}

func optIn(name, collection, short, why string) Package {
	p := pkg(name, collection, short, false, false, SourceFleetMCP, why)
	p.OptIn = true
	return p
}

// Packages is the recommendation for every Corelight package Fleet
// Manager 29.2 knows. The sensor docs' deployment recommendations are the
// starting point; packages added since then are judged by what they detect
// and where that traffic is seen. Machine learning (ml_package) and the
// packages loaded by default are handled outside the profiles.
var Packages = []Package{
	// From the deployment recommendations table.
	pkg("Bitcoin Detector (Cryptomining)", "Core", "zeek_cryptomining", true, true, SourceDocsTable, "mining pools are reached across the border, miners also talk inside"),
	pkg("Cert Hygiene", "ETC", "cert_hygiene", true, true, SourceDocsTable, "certificate problems on internal and external services"),
	pkg("Community ID", "Core", "zeek_community_id", true, true, SourceDocsTable, "flow hash that joins Corelight logs with other tools"),
	pkg("Data Reduction", "Core", "datared", false, true, SourceDocsTable, "trims high-volume internal logs"),
	pkg("DGA", "C2", "dga", true, true, SourceDocsTable, "algorithmically generated domains in DNS"),
	pkg("DNS Tunnels", "C2", "dns_tunnels", true, true, SourceDocsTable, "data hidden in DNS queries"),
	pkg("Encrypted DNS", "ETC", "encrypted_dns", true, true, SourceDocsTable, "DNS over HTTPS/TLS servers"),
	pkg("Encryption Detection", "ETC", "encryption_detection", false, false, SourceDocsTable, "the docs recommend it for neither profile; enable on request"),
	pkg("Eternal Safety", "Core", "zeek_eternal_safety", false, true, SourceDocsTable, "EternalBlue-style SMB exploitation, an internal protocol"),
	pkg("HASSH", "Core", "hassh", true, true, SourceDocsTable, "SSH client and server fingerprints"),
	pkg("HTTP C2", "C2", "http_c2", true, true, SourceDocsTable, "C2 over HTTP and HTTP hygiene"),
	pkg("HTTP POST Bodies", "Core", "log_add_http_post_bodies", true, true, SourceDocsTable, "POST body excerpts for investigations"),
	pkg("ICMP Tunnels", "C2", "icmp_tunnels", true, true, SourceDocsTable, "data hidden in ICMP echo"),
	pkg("JA3", "Core", "ja3", true, true, SourceDocsTable, "TLS client and server fingerprints"),
	pkg("Long Connections", "Core", "zeek_long_connections", true, true, SourceDocsTable, "logs connections that stay open, common for C2 and tunnels"),
	pkg("MAC Addresses", "Core", "mac_logging", false, true, SourceDocsTable, "MAC addresses are only meaningful on the local segment"),
	pkg("Meterpreter Detection", "C2", "meterpreter", true, true, SourceDocsTable, "Metasploit Meterpreter sessions"),
	pkg("MITRE BZAR", "Core", "bzar", false, true, SourceDocsTable, "ATT&CK lateral movement over SMB and DCE-RPC"),
	pkg("MITRE HTTP/2", "Core", "bro_http2", false, false, SourceDocsTable, "the docs recommend it for neither profile; enable on request"),
	pkg("Name cache", "Core", "namecache", false, false, SourceDocsTable, "the docs recommend it for neither profile; enable on request"),
	pkg("RDP Inference", "ETC", "rdp_inference", true, true, SourceDocsTable, "infers RDP behavior inside encrypted sessions"),
	pkg("SHA256 File Hashes", "Core", "file_sha256", true, true, SourceDocsTable, "SHA256 for extracted file hashes"),
	pkg("SMTP Links", "Core", "smtp_links", true, false, SourceDocsTable, "links in email arriving from outside"),
	optIn("Shunting Support", "Core", "corelight_shunting", "needs a supported packet broker"),
	pkg("Simple Scan", "Core", "zeek_simple_scan", true, true, SourceDocsTable, "port and address scans"),
	pkg("SSH Inference (GGFAST)", "ETC", "ssh_inference", true, true, SourceDocsTable, "infers SSH behavior inside encrypted sessions"),
	pkg("Stepping Stones", "ETC", "stepping_stones", false, true, SourceDocsTable, "relayed interactive sessions between internal hosts"),
	pkg("Traceroute", "Core", "detect_traceroute", true, true, SourceDocsTable, "traceroute activity"),
	pkg("VLANs", "Core", "vlan_logging", false, true, SourceDocsTable, "VLAN tags are an internal construct"),
	pkg("Windows Version Detector", "Core", "windows_version_detection", true, true, SourceDocsTable, "Windows versions from traffic"),

	// Tagged on their own docs pages.
	pkg("AWS Service Enumeration Detection", "Core", "aws_service_enumeration", true, true, SourceDocsPage, "enumeration of AWS service endpoints"),
	pkg("AWS Storage Exfiltration Detection", "Core", "aws_storage_exfil", true, true, SourceDocsPage, "large uploads to AWS S3"),
	pkg("Azure Service Enumeration Detection", "Core", "azure_service_enumeration", true, true, SourceDocsPage, "enumeration of Azure service endpoints"),
	pkg("Azure Storage Exfiltration Detection", "Core", "azure_storage_exfil", true, true, SourceDocsPage, "large uploads to Azure Storage"),
	pkg("GCP Service Enumeration Detection", "Core", "gcp_service_enumeration", true, true, SourceDocsPage, "enumeration of GCP service endpoints"),
	pkg("GCP Storage Exfiltration Detection", "Core", "gcp_storage_exfil", true, true, SourceDocsPage, "large uploads to GCP storage"),
	pkg("Brute-Force Detections", "Core", "brute_force_detections", true, true, SourceDocsPage, "password guessing against many protocols"),
	pkg("Kerberos Logs", "Core", "kerberos_logs", true, true, SourceDocsPage, "Kerberos logging"),
	pkg("Kerberos Detections", "Core", "kerberos_detections", false, true, SourceDocsPage, "Kerberos attacks against domain controllers"),
	pkg("Pacu Detector", "Core", "pacu_detector", true, true, SourceDocsPage, "the Pacu AWS exploitation framework"),
	pkg("Scanners", "Core", "scanners", true, true, SourceDocsPage, "known scanners and scanning tools"),
	pkg("Unknown Protocols", "Core", "unknown_protocols", true, true, SourceDocsPage, "packets Zeek cannot parse"),
	pkg("VPC Flow Brute-Force Detector", "Core", "vpc_flow_brute_force_detector", true, true, SourceDocsPage, "brute force seen in VPC flow data"),
	pkg("Windows Logs", "Core", "windows_logs", false, true, SourceDocsPage, "Windows protocol logs (internal)"),
	pkg("Fast Reverse Proxy (FRP) Detector", "C2", "frp_detector", true, false, SourceDocsPage, "FRP tunnels that bypass the perimeter"),
	pkg("Ligolo-ng Tunnel Detector", "C2", "ligolo_detector", true, false, SourceDocsPage, "Ligolo-ng reverse tunnels started from inside"),
	pkg("Scout Detector", "C2", "scout_detector", true, false, SourceDocsPage, "Scout C2"),
	pkg("Sliver", "C2", "sliver", true, false, SourceDocsPage, "Sliver C2 framework"),
	pkg("AMQP Analyzer", "Analyzers", "zeek_spicy_amqp", true, true, SourceDocsPage, "AMQP message queues"),
	pkg("Telnet+TN3270 Analyzer", "Analyzers", "zeek_spicy_telnet", true, true, SourceDocsPage, "cleartext Telnet and mainframe TN3270"),
	{Key: "bro.pkgs.corelight.responder.loaded", Name: "Responder", Collection: "Core", NS: false, EW: true, Source: SourceFleetMCP,
		Why: "LLMNR/NBT-NS poisoning happens on the local segment; its docs page tags it N/S, which looks like an error"},

	// Packages the recommendations predate: fleet-mcp's call.
	pkg("AgentTesla", "C2", "agenttesla_detector", true, false, SourceFleetMCP, "malware C2 calls out across the border"),
	pkg("Amadey Detector", "C2", "amadey_detector", true, false, SourceFleetMCP, "malware C2 calls out across the border"),
	pkg("AsyncRAT Detector", "C2", "asyncrat_detector", true, false, SourceFleetMCP, "malware C2 calls out across the border"),
	pkg("BitRAT Detector", "C2", "bitrat_detector", true, false, SourceFleetMCP, "malware C2 calls out across the border"),
	pkg("Caldera Detector", "C2", "caldera_detector", true, false, SourceFleetMCP, "MITRE Caldera agents beacon to their server"),
	pkg("Formbook", "C2", "formbook_detector", true, false, SourceFleetMCP, "malware C2 calls out across the border"),
	pkg("Gozi Detector", "C2", "gozi_detector", true, false, SourceFleetMCP, "malware C2 calls out across the border"),
	pkg("NetSupport Detector", "C2", "netsupport_detector", true, false, SourceFleetMCP, "NetSupport RAT abused for C2 over the internet"),
	pkg("QuasarRAT Detector", "C2", "quasarrat_detector", true, false, SourceFleetMCP, "malware C2 calls out across the border"),
	pkg("Redline", "C2", "redline_detector", true, false, SourceFleetMCP, "infostealer exfiltrating to its server"),
	pkg("Remcos Detector", "C2", "remcos_detector", true, false, SourceFleetMCP, "malware C2 calls out across the border"),
	pkg("SolarMarker Detector", "C2", "solarmarker_detector", true, false, SourceFleetMCP, "malware C2 calls out across the border"),
	pkg("njRAT", "C2", "zeek_spicy_njrat", true, false, SourceFleetMCP, "malware C2 calls out across the border"),
	pkg("STRRAT Detector", "C2", "zeek_spicy_strrat", true, false, SourceFleetMCP, "malware C2 calls out across the border"),
	pkg("Log4Shell", "Core", "log4shell", true, false, SourceFleetMCP, "exploitation attempts mostly arrive from the internet"),
	pkg("Is Darknet", "Core", "zeek_is_darknet", true, false, SourceFleetMCP, "traffic to unused address space, typical of internet scanning"),
	pkg("Application Identification", "Entity", "application_identification", true, true, SourceFleetMCP, "identifies applications in connections; Anomaly Detection's application baseline uses it"),
	pkg("Known Entities", "Entity", "known_entities", true, true, SourceFleetMCP, "inventory of hosts, services and software"),
	pkg("Local Subnets", "Entity", "local_subnets", false, true, SourceFleetMCP, "discovers internal subnets"),
	pkg("VPN Insights", "ETC", "vpn_insights", true, true, SourceFleetMCP, "VPN protocols, mostly to the internet but also internal"),
	pkg("LDAP Analyzer", "Analyzers", "zeek_spicy_ldap", false, true, SourceFleetMCP, "directory traffic stays internal"),
	pkg("SSDP Analyzer", "Analyzers", "zeek_spicy_ssdp", false, true, SourceFleetMCP, "UPnP discovery is link-local"),
	pkg("GENA Analyzer", "Analyzers", "zeek_spicy_gena", false, true, SourceFleetMCP, "UPnP event notification is local"),
	pkg("IPsec Analyzer", "Analyzers", "zeek_spicy_ipsec", true, false, SourceFleetMCP, "site-to-site and remote-access VPNs cross the border"),
	pkg("OpenVPN Analyzer", "Analyzers", "zeek_spicy_openvpn", true, false, SourceFleetMCP, "VPN tunnels cross the border"),
	pkg("WireGuard Analyzer", "Analyzers", "zeek_spicy_wireguard", true, false, SourceFleetMCP, "VPN tunnels cross the border"),
	pkg("STUN Analyzer", "Analyzers", "zeek_spicy_stun", true, false, SourceFleetMCP, "NAT traversal toward internet services"),
	pkg("TDS (Microsoft SQL)", "ICS/OT", "zeek_plugin_tds", false, true, SourceFleetMCP, "database traffic stays internal"),
	pkg("CVE-2022-26937 (NFS)", "Core", "cve_2022_26937", false, true, SourceFleetMCP, "NFS exploitation, an internal protocol"),

	// Opt-in: environment-specific or advanced.
	optIn("HTTP Cookie Variables", "Core", "http_cookie_vars", "adds cookie values to http.log; privacy and log volume"),
	optIn("Network Performance Monitoring", "Core", "net_perf", "network performance anomalies; ask in performance monitoring"),
	optIn("Netskope Enrichment", "Core", "netskope_enrich", "only with Netskope in the path"),
	optIn("Geneve", "Analyzers", "corelight_geneve", "only for Geneve-encapsulated mirrors (cloud load balancers)"),
	optIn("Corelight Dropper", "Core", "corelight_dropper", "advanced: drops selected traffic"),
	optIn("Global Log Filter Presets", "Core", "logfilter", "advanced: filters log entries"),
	optIn("BACnet", "ICS/OT", "zeek_plugin_bacnet", "ICS/OT protocol: only where OT traffic is monitored"),
	optIn("BSAP", "ICS/OT", "zeek_plugin_bsap", "ICS/OT protocol: only where OT traffic is monitored"),
	optIn("DNP3", "ICS/OT", "zeek_plugin_dnp3", "ICS/OT protocol: only where OT traffic is monitored"),
	optIn("ENIP", "ICS/OT", "zeek_plugin_enip", "ICS/OT protocol: only where OT traffic is monitored"),
	optIn("EtherCAT", "ICS/OT", "zeek_plugin_ethercat", "ICS/OT protocol: only where OT traffic is monitored"),
	optIn("Modbus", "ICS/OT", "zeek_plugin_modbus", "ICS/OT protocol: only where OT traffic is monitored"),
	optIn("OPC UA Binary", "ICS/OT", "zeek_plugin_opcua_binary", "ICS/OT protocol: only where OT traffic is monitored"),
	optIn("PROFINET", "ICS/OT", "zeek_plugin_profinet", "ICS/OT protocol: only where OT traffic is monitored"),
	optIn("S7comm", "ICS/OT", "zeek_plugin_s7comm", "ICS/OT protocol: only where OT traffic is monitored"),
	optIn("Genisys", "ICS/OT", "zeek_spicy_genisys", "ICS/OT protocol: only where OT traffic is monitored"),
	optIn("IEC 104", "ICS/OT", "spicy_iec104", "ICS/OT protocol: only where OT traffic is monitored"),
	optIn("ROC Plus", "ICS/OT", "roc_plus", "ICS/OT protocol: only where OT traffic is monitored"),
}

// Recommended returns the packages a profile enables, by key.
func Recommended(profile string) map[string]Package {
	out := map[string]Package{}
	for _, p := range Packages {
		if p.OptIn {
			continue
		}
		if (profile == NorthSouth && p.NS) || (profile == EastWest && p.EW) {
			out[p.Key] = p
		}
	}
	return out
}

// Lookup finds a package by key, short name ("ja3") or display name.
func Lookup(ref string) (Package, bool) {
	for _, p := range Packages {
		if p.Key == ref || p.Key == "bro.pkgs.corelight."+ref+".loaded" || equalFold(p.Name, ref) {
			return p, true
		}
	}
	return Package{}, false
}

// Sorted returns the packages with duplicates removed, sorted by collection
// and name.
func Sorted() []Package {
	seen := map[string]bool{}
	var out []Package
	for _, p := range Packages {
		if !seen[p.Key] {
			seen[p.Key] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Collection != out[j].Collection {
			return out[i].Collection < out[j].Collection
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
