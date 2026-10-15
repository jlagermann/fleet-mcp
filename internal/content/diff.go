package content

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
)

const sampleSize = 15

// suricataRule is one rule of a rules file.
type suricataRule struct {
	enabled bool
	text    string
}

var (
	ruleAction = regexp.MustCompile(`^(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s`)
	ruleSID    = regexp.MustCompile(`(?:^|[;(\s])sid\s*:\s*(\d+)\s*;`)
)

// parseSuricata indexes the rules of a file by SID; commented-out rules
// count as disabled. Lines that are not rules are ignored.
func parseSuricata(b []byte) (map[string]suricataRule, int) {
	rules := map[string]suricataRule{}
	noSID := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		enabled := true
		if strings.HasPrefix(line, "#") {
			enabled = false
			line = strings.TrimSpace(strings.TrimLeft(line, "#"))
		}
		if !ruleAction.MatchString(line) {
			continue
		}
		m := ruleSID.FindStringSubmatch(line)
		if m == nil {
			if enabled {
				noSID++
			}
			continue
		}
		rules[m[1]] = suricataRule{enabled: enabled, text: line}
	}
	return rules, noSID
}

func countEnabled(rules map[string]suricataRule) int {
	n := 0
	for _, r := range rules {
		if r.enabled {
			n++
		}
	}
	return n
}

// diffSuricata compares two rules files by SID.
func diffSuricata(old, cur []byte, haveOld bool) map[string]any {
	nr, noSID := parseSuricata(cur)
	out := map[string]any{"rules": len(nr), "enabled": countEnabled(nr)}
	if noSID > 0 {
		out["enabled_rules_without_sid"] = noSID
	}
	if !haveOld {
		return out
	}
	or, _ := parseSuricata(old)
	out["current_rules"], out["current_enabled"] = len(or), countEnabled(or)
	var added, removed, changed, enabled, disabled []string
	for sid, r := range nr {
		o, ok := or[sid]
		switch {
		case !ok:
			added = append(added, sid)
		case o.text != r.text:
			changed = append(changed, sid)
		}
		if ok && o.enabled != r.enabled {
			if r.enabled {
				enabled = append(enabled, sid)
			} else {
				disabled = append(disabled, sid)
			}
		}
	}
	for sid := range or {
		if _, ok := nr[sid]; !ok {
			removed = append(removed, sid)
		}
	}
	for k, v := range map[string][]string{"added_sids": added, "removed_sids": removed, "changed_sids": changed, "newly_enabled_sids": enabled, "newly_disabled_sids": disabled} {
		if len(v) > 0 {
			sortNumeric(v)
			out[k] = map[string]any{"count": len(v), "sample": sample(v, sampleSize)}
		}
	}
	return out
}

func sortNumeric(s []string) {
	sort.Slice(s, func(i, j int) bool {
		if len(s[i]) != len(s[j]) {
			return len(s[i]) < len(s[j])
		}
		return s[i] < s[j]
	})
}

// records returns the data lines of a Zeek TSV file (intel or input) keyed
// by keyFields leading columns (0 = the whole line), and its #fields header.
func records(b []byte, keyFields int) (map[string]bool, string) {
	set := map[string]bool{}
	header := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, "#fields") {
			header = line
			continue
		}
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key := line
		if keyFields > 0 {
			if f := strings.SplitN(line, "\t", keyFields+1); len(f) > keyFields {
				key = strings.Join(f[:keyFields], "\t")
			}
		}
		set[key] = true
	}
	return set, header
}

// diffRecords compares two TSV files. Intel files are keyed by indicator
// and type; other files by the whole line.
func diffRecords(old, cur []byte, haveOld bool, keyFields int, what string) map[string]any {
	nr, nh := records(cur, keyFields)
	out := map[string]any{what: len(nr)}
	if nh == "" {
		out["fields_header"] = "missing (Zeek's input framework needs a #fields line)"
	}
	if !haveOld {
		return out
	}
	or, oh := records(old, keyFields)
	out["current_"+what] = len(or)
	if oh != nh {
		out["fields_header_changed"] = map[string]string{"from": oh, "to": nh}
	}
	var added, removed []string
	for k := range nr {
		if !or[k] {
			added = append(added, clip(k))
		}
	}
	for k := range or {
		if !nr[k] {
			removed = append(removed, clip(k))
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	if len(added) > 0 {
		out["added"] = map[string]any{"count": len(added), "sample": sample(added, sampleSize)}
	}
	if len(removed) > 0 {
		out["removed"] = map[string]any{"count": len(removed), "sample": sample(removed, sampleSize)}
	}
	return out
}

func clip(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}

var yaraRule = regexp.MustCompile(`(?m)^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)`)

func yaraRules(b []byte) map[string]bool {
	set := map[string]bool{}
	for _, m := range yaraRule.FindAllSubmatch(b, -1) {
		set[string(m[1])] = true
	}
	return set
}

// diffYara compares two YARA files by rule name.
func diffYara(old, cur []byte, haveOld bool) map[string]any {
	nr := yaraRules(cur)
	out := map[string]any{"rules": len(nr)}
	if !haveOld {
		return out
	}
	or := yaraRules(old)
	out["current_rules"] = len(or)
	var added, removed []string
	for k := range nr {
		if !or[k] {
			added = append(added, k)
		}
	}
	for k := range or {
		if !nr[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	if len(added) > 0 {
		out["added_rules"] = map[string]any{"count": len(added), "sample": sample(added, sampleSize)}
	}
	if len(removed) > 0 {
		out["removed_rules"] = map[string]any{"count": len(removed), "sample": sample(removed, sampleSize)}
	}
	return out
}

// bundlePackage is one package of a Zeek package bundle.
type bundlePackage struct {
	Source   string `json:"source"`
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
}

// PackageKey is the name Fleet Manager gives a bundled package: its source
// with "://" and "/" turned into ":" (https://github.com/corelight/x is
// https:github.com:corelight:x, /home/u/x is :home:u:x).
func PackageKey(source string) string {
	return strings.ReplaceAll(strings.Replace(source, "://", ":", 1), "/", ":")
}

// parseBundle reads a zkg bundle (a gzipped tar with manifest.txt and one
// directory per package) and returns its packages by Fleet Manager key.
func parseBundle(b []byte) (map[string]bundlePackage, error) {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("not a gzipped package bundle: %w", err)
	}
	tr := tar.NewReader(gz)
	var manifest []byte
	// gitFiles holds each package's .git/HEAD, refs and packed-refs, to
	// find the checked-out commit.
	gitFiles := map[string]map[string]string{} // package directory -> path in .git -> content
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the bundle: %w", err)
		}
		name := strings.TrimPrefix(path.Clean(h.Name), "./")
		switch {
		case name == "manifest.txt":
			if manifest, err = io.ReadAll(io.LimitReader(tr, 1<<20)); err != nil {
				return nil, err
			}
		default:
			dir, rest, _ := strings.Cut(name, "/.git/")
			if dir == "" || strings.Contains(dir, "/") || h.Typeflag != tar.TypeReg ||
				(rest != "HEAD" && rest != "packed-refs" && !strings.HasPrefix(rest, "refs/")) {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(tr, 1<<20))
			if gitFiles[dir] == nil {
				gitFiles[dir] = map[string]string{}
			}
			gitFiles[dir][rest] = string(b)
		}
	}
	if manifest == nil {
		return nil, errors.New("the bundle has no manifest.txt; build it with zkg bundle")
	}
	pkgs := map[string]bundlePackage{}
	inBundle := false
	for _, line := range strings.Split(string(manifest), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inBundle = line == "[bundle]"
			continue
		}
		if !inBundle {
			continue
		}
		src, ver, _ := strings.Cut(line, "=")
		src, ver = strings.TrimSpace(src), strings.TrimSpace(ver)
		if src == "" {
			continue
		}
		pkgs[PackageKey(src)] = bundlePackage{Source: src, Version: ver, Revision: headRevision(gitFiles[path.Base(src)])}
	}
	if len(pkgs) == 0 {
		return nil, errors.New("the bundle's manifest.txt lists no packages")
	}
	return pkgs, nil
}

// headRevision resolves a package's .git/HEAD to a commit: HEAD holds the
// hash when detached (a tag checkout), otherwise "ref: refs/heads/<b>",
// found in the ref file or packed-refs. Empty when it cannot be resolved.
func headRevision(git map[string]string) string {
	head := strings.TrimSpace(git["HEAD"])
	ref, ok := strings.CutPrefix(head, "ref: ")
	if !ok {
		return head
	}
	if v := strings.TrimSpace(git[ref]); v != "" {
		return v
	}
	for _, line := range strings.Split(git["packed-refs"], "\n") {
		if hash, name, ok := strings.Cut(strings.TrimSpace(line), " "); ok && name == ref {
			return hash
		}
	}
	return ""
}

// diffBundle compares the new bundle's packages with the current bundle's
// (from Fleet Manager's bundle info) and the policy's enabled packages.
func diffBundle(cur map[string]bundlePackage, old map[string]any, enabled map[string]bool) (map[string]any, []string) {
	out := map[string]any{"packages": len(cur)}
	var warnings []string
	var added, removed, changed, unchanged []string
	for _, k := range sortedKeys(cur) {
		n := cur[k]
		o := obj(old[k])
		switch {
		case o == nil:
			added = append(added, fmt.Sprintf("%s = %s", k, n.Version))
		case str(o["version"]) != n.Version || (n.Revision != "" && str(o["revision"]) != "" && str(o["revision"]) != n.Revision):
			changed = append(changed, fmt.Sprintf("%s: %s %s -> %s %s", k, str(o["version"]), short(str(o["revision"])), n.Version, short(n.Revision)))
		default:
			unchanged = append(unchanged, k)
		}
	}
	for _, k := range sortedKeys(old) {
		if _, ok := cur[k]; !ok {
			removed = append(removed, k)
			if enabled[k] {
				warnings = append(warnings, fmt.Sprintf("package %s is enabled in the policy but is not in the new bundle: sensors stop loading it", k))
			}
		}
	}
	if len(added) > 0 {
		out["added"] = added
		warnings = append(warnings, fmt.Sprintf("%d new package(s) arrive disabled: they are copied to the sensors but not loaded until enabled in the policy", len(added)))
	}
	if len(changed) > 0 {
		out["changed"] = changed
	}
	if len(removed) > 0 {
		out["removed"] = removed
	}
	out["unchanged"] = len(unchanged)
	return out, warnings
}

func short(rev string) string {
	if len(rev) > 8 {
		return rev[:8]
	}
	return rev
}

// diffLines compares two text files line by line (Suricata configuration
// files).
func diffLines(old, cur []byte, haveOld bool) map[string]any {
	nl := lineSet(cur)
	out := map[string]any{"lines": len(nl)}
	if !haveOld {
		return out
	}
	ol := lineSet(old)
	var added, removed []string
	for l := range nl {
		if !ol[l] {
			added = append(added, clip(l))
		}
	}
	for l := range ol {
		if !nl[l] {
			removed = append(removed, clip(l))
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	if len(added) > 0 {
		out["added_lines"] = map[string]any{"count": len(added), "sample": sample(added, sampleSize)}
	}
	if len(removed) > 0 {
		out["removed_lines"] = map[string]any{"count": len(removed), "sample": sample(removed, sampleSize)}
	}
	return out
}

func lineSet(b []byte) map[string]bool {
	set := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			set[l] = true
		}
	}
	return set
}
