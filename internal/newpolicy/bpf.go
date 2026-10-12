package newpolicy

import (
	"fmt"
	"regexp"
	"strings"
)

// The sensor's traffic exclusion filter (bro.site.ignore_bpf) is a limited
// BPF. It names only what to exclude: the sensor evaluates
// not (<filter>). Compared with standard BPF (sensor docs, "Traffic
// exclusion filter"):
//   - unidirectional filters (src host x, dst port y) are not supported:
//     dropping one side of a connection breaks Zeek's analysis of it. Only
//     "src or dst" and "src and dst" are allowed, or no direction at all.
//     bro.site.restrictive_bpf=false lifts this at packet level, which
//     Corelight recommends only with Support.
//   - nothing about VLAN tagging (the sensor handles VLANs itself);
//   - nothing about ATM, MTP2 or MTP3;
//   - no arithmetic and no access to data inside packets (tcp[13], len).

var bpfToken = regexp.MustCompile(`&&|\|\||!=|>=|<=|[()\[\]!<>=+*&|^-]|[^\s()\[\]!<>=+*&|^-]+`)

var bpfUnsupported = func() map[string]string {
	m := map[string]string{}
	for what, words := range map[string]string{
		"VLAN tagging":             "vlan",
		"ATM":                      "atm oam oamf4 oamf4ec oamf4sc sc ilmic lane metac bcc connectmsg metaconnect vpi vci",
		"MTP2":                     "fisu lssu msu hfisu hlssu hmsu",
		"MTP3":                     "sio opc dpc sls hsio hopc hdpc hsls",
		"packet length arithmetic": "len less greater",
	} {
		for _, w := range strings.Fields(words) {
			m[w] = what
		}
	}
	return m
}()

// CheckExclusionFilter returns why a traffic exclusion filter would not
// work on a sensor, with a suggested rewrite where there is one. With
// restrictive false (bro.site.restrictive_bpf off), single-direction
// filters are allowed.
func CheckExclusionFilter(filter string, restrictive bool) []string {
	toks := bpfToken.FindAllString(strings.ToLower(filter), -1)
	var problems []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			problems = append(problems, p)
		}
	}
	for i, t := range toks {
		switch {
		case t == "src" || t == "dst":
			// Allowed: "src or dst", "src and dst" (either order).
			if i+2 < len(toks) && (toks[i+1] == "or" || toks[i+1] == "and") && (toks[i+2] == "src" || toks[i+2] == "dst") && toks[i+2] != t {
				continue
			}
			if i > 1 && (toks[i-1] == "or" || toks[i-1] == "and") && (toks[i-2] == "src" || toks[i-2] == "dst") && toks[i-2] != t {
				continue
			}
			if restrictive {
				add(fmt.Sprintf("%q is a one-direction filter: the sensor does not support those, because dropping one side of a connection breaks Zeek's analysis of it. Leave out %q (for example %q) to exclude both directions",
					t+" "+next(toks, i), t, strings.TrimSpace(next(toks, i))))
			}
		case bpfUnsupported[t] != "":
			add(fmt.Sprintf("%q: filters on %s are not supported by the sensor", t, bpfUnsupported[t]))
		case t == "[" || t == "]":
			add("accessing data inside packets (proto[offset]) is not supported by the sensor")
		case t == "+" || t == "*" || t == "&" || t == "|" || t == "^" || t == ">" || t == "<" || t == "=" || t == ">=" || t == "<=" || t == "!=":
			add("arithmetic and comparisons are not supported by the sensor")
		}
	}
	return problems
}

// next returns the words after a direction keyword up to its value, for
// the message: "host 10.1.1.1", "port 53", "net 10.0.0.0/8".
func next(toks []string, i int) string {
	keyword := map[string]bool{"host": true, "port": true, "portrange": true, "net": true, "proto": true,
		"tcp": true, "udp": true, "ip": true, "ip6": true, "icmp": true, "ether": true}
	var out []string
	for j := i + 1; j < len(toks) && len(out) < 3; j++ {
		out = append(out, toks[j])
		if !keyword[toks[j]] {
			break
		}
	}
	return strings.Join(out, " ")
}
