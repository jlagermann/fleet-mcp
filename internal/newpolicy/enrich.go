package newpolicy

import (
	"fmt"
	"strconv"
	"strings"
)

// Connector-fed enrichments work only when the whole chain is in place
// (Fleet Manager docs, Connectors): a connector (authentication) feeds a
// source (one file), sources are grouped in a collection, the collection is
// linked to the sensor policy, and - for input files - a Zeek package in
// the same policy reads the file. Without that package the file reaches
// the sensor and nothing uses it. Intel files are read by the Zeek intel
// framework itself; asset classification needs asset_classification.enable.

// EnrichmentCheck is the preview of one linked collection.
type EnrichmentCheck struct {
	Kind       string         `json:"kind"` // input, intel or asset classification
	Collection string         `json:"collection"`
	Sources    []SourceStatus `json:"sources"`
	Notes      []string       `json:"notes,omitempty"`
}

// SourceStatus is one source of a linked collection.
type SourceStatus struct {
	Alias     string `json:"alias"`
	File      string `json:"file"`
	Connector string `json:"connector,omitempty"` // empty: an uploaded file
	Status    string `json:"status"`
	ReadBy    string `json:"read_by,omitempty"`
}

// A suggestion is the package fleet-mcp expects to read an input file. It
// is only a suggestion: customers write their own packages (which no docs
// list) and packages change (a newer version may stop reading a file), so
// the user can name any package as a file's reader with input_readers.
type suggestion struct {
	name   string
	key    string   // bro.pkgs.corelight.<key>.loaded, for Corelight packages
	bundle []string // words a custom bundle package's name contains
	wl     bool     // an allowlist named after its package (*-wl.txt)
}

// suggestions maps input file names (or prefixes ending in "-") to the
// package expected to read them: the sensor docs ("Zeek packages that
// support input files"), the *-wl.txt allowlists named after their
// package, the connector docs (host and CVE data) and icannTLD.
var suggestions = map[string]suggestion{
	"cert-hygiene-":           {name: "Cert Hygiene", key: "cert_hygiene", wl: true},
	"datared-":                {name: "Data Reduction", key: "datared", wl: true},
	"encryption-detection-":   {name: "Encryption Detection", key: "encryption_detection", wl: true},
	"rdp-inference-":          {name: "RDP Inference", key: "rdp_inference", wl: true},
	"stepping-stone-":         {name: "Stepping Stones", key: "stepping_stones", wl: true},
	"hosts_data.tsv":          {name: "an endpoint enrichment package (custom bundle)", bundle: []string{"endpoint-enrichment"}},
	"cve_data.tsv":            {name: "an endpoint or CVE enrichment package (custom bundle)", bundle: []string{"endpoint-enrichment", "cve-enrichment"}},
	"trusted_domains.dat":     {name: "icannTLD (custom bundle)", bundle: []string{"icanntld"}},
	"_level_public_icann.dat": {name: "icannTLD (custom bundle)", bundle: []string{"icanntld"}},
}

// obsolete input files are no longer read by any current Corelight
// package; a source for one can be removed.
var obsolete = map[string]bool{
	"sni-wl.txt":                  true,
	"ssh-inference-server-wl.txt": true,
}

func suggestFor(file string) (suggestion, bool) {
	if s, ok := suggestions[file]; ok {
		return s, true
	}
	for k, s := range suggestions {
		if (strings.HasSuffix(k, "-") && strings.HasPrefix(file, k)) || (strings.HasPrefix(k, "_") && strings.HasSuffix(file, k)) {
			return s, true
		}
	}
	return suggestion{}, false
}

// enabled returns the enabled package matching s, if any.
func (p *Plan) enabled(s suggestion) string {
	if s.key != "" && p.Built.Configuration["bro.pkgs.corelight."+s.key+".loaded"] == true {
		return s.name
	}
	return p.bundlePackage(s.bundle...)
}

// packageEnabled reports whether a package the user named is enabled: a
// Corelight package by name or key, or a bundle package by part of its name.
func (p *Plan) packageEnabled(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, pk := range p.Built.Packages {
		if strings.ToLower(pk.Name) == n || strings.Contains(strings.ToLower(pk.Key), "."+n+".") {
			return true
		}
	}
	return n != "" && p.bundlePackage(n) != ""
}

// bundlePackage returns the enabled bundle package whose name contains one
// of words.
func (p *Plan) bundlePackage(words ...string) string {
	for _, bp := range p.BundlePackages {
		for _, w := range words {
			if strings.Contains(strings.ToLower(bp), w) {
				return bp
			}
		}
	}
	return ""
}

// packageInputs are input files a package cannot run without (required)
// or can use (optional), for packages fleet-mcp knows; any other package
// may need files fleet-mcp cannot know about.
var packageInputs = []struct {
	words    []string // in the bundle package name
	name     string
	anyOf    []string // at least one of these
	required []string // all of these
}{
	{words: []string{"icanntld"}, name: "icannTLD", required: []string{"1st_level_public_icann.dat", "2nd_level_public_icann.dat", "3rd_level_public_icann.dat", "4th_level_public_icann.dat"}},
	{words: []string{"endpoint-enrichment"}, name: "endpoint enrichment", anyOf: []string{"hosts_data.tsv", "cve_data.tsv"}},
}

// checkEnrichment follows a linked collection down to its sources and the
// packages that read them, and records warnings for broken links.
func (p *Plan) checkEnrichment(kind string, coll map[string]any) {
	c := EnrichmentCheck{Kind: kind, Collection: str(coll["name"])}
	warn := func(format string, a ...any) {
		p.Built.Warnings = append(p.Built.Warnings, fmt.Sprintf("%s collection %s: ", kind, c.Collection)+fmt.Sprintf(format, a...))
	}
	sources, _ := coll["sources"].([]any)
	if len(sources) == 0 {
		warn("it has no sources, so nothing is sent to the sensors")
	}
	indicators := 0
	var unknown []string // input files with no known reader
	defer func() {
		if len(unknown) > 0 {
			p.Questions = append(p.Questions, fmt.Sprintf("Which packages read %s? fleet-mcp does not know them (they are likely read by custom packages); name each reader (input_readers) or confirm the package is in this policy, since without one the file does nothing.", strings.Join(unknown, ", ")))
		}
		p.Enrichments = append(p.Enrichments, c)
	}()
	for _, el := range sources {
		s := obj(el)
		st := SourceStatus{Alias: str(s["alias"]), File: str(s["name"]), Connector: str(obj(s["connector"])["name"])}
		switch {
		case s["enabled"] == false:
			st.Status = "disabled"
			warn("source %s is disabled", st.Alias)
		case str(s["processingError"]) != "":
			st.Status = "error: " + str(s["processingError"])
			warn("source %s failed to fetch: %s (check its connector)", st.Alias, str(s["processingError"]))
		case s["isProcessing"] == true:
			st.Status = "fetching"
		case s["fileId"] == nil:
			st.Status = "no file yet"
			warn("source %s has no file yet", st.Alias)
		default:
			st.Status = "ready"
		}
		indicators += int(idOf(obj(s["metadata"])["numberOfIndicators"]))
		if kind == "input" {
			if reader, said := p.Spec.InputReaders[st.File]; said {
				st.ReadBy = reader + " (as the user said)"
				if !p.packageEnabled(reader) {
					warn("%s is to be read by %s, which is not among this policy's enabled packages: make sure it is loaded (for example from the custom bundle)", st.File, reader)
				}
			} else if obsolete[st.File] {
				st.ReadBy = "nothing (obsolete)"
				warn("%s (source %s) is an old input file no current Corelight package reads: remove the source from the collection", st.File, st.Alias)
			} else if sg, known := suggestFor(st.File); known {
				if st.ReadBy = p.enabled(sg); st.ReadBy == "" {
					caveat := ""
					if sg.wl {
						caveat = " (newer versions of a package can stop using an input file)"
					}
					p.Questions = append(p.Questions, fmt.Sprintf("Which package reads %s (source %s)? It is usually %s%s, which this policy does not enable. Enable it, or name the package that reads it (input_readers), for example a custom one; if nothing does, the file reaches the sensors and nothing uses it.", st.File, st.Alias, sg.name, caveat))
				}
			} else {
				unknown = append(unknown, st.File)
			}
		}
		c.Sources = append(c.Sources, st)
	}
	switch kind {
	case "intel":
		c.Notes = append(c.Notes, "intel files are read by the Zeek intel framework itself; the ExtendIntel package (custom bundle) adds the intel metadata to the logs")
		limit := 100000
		if v, ok := p.Spec.Settings["bro.intel.max_indicators"]; ok {
			if n, err := strconv.Atoi(fmt.Sprint(v)); err == nil {
				limit = n
			}
		}
		if indicators > limit {
			warn("its sources hold %d indicators, more than the sensor's limit of %d (bro.intel.max_indicators)", indicators, limit)
		}
	case "asset classification":
		c.Notes = append(c.Notes, "asset_classification.enable is turned on with it (Early Access; appliances that meet the requirements, with an asset classification license)")
	}
}

// checkPackageInputs warns when an enabled package fleet-mcp knows needs
// input files that no linked input collection provides.
func (p *Plan) checkPackageInputs(input map[string]any) {
	have := map[string]bool{}
	for _, el := range anySlice(input["sources"]) {
		have[str(obj(el)["name"])] = true
	}
	for _, need := range packageInputs {
		bp := p.bundlePackage(need.words...)
		if bp == "" {
			continue
		}
		var missing []string
		for _, f := range need.required {
			if !have[f] {
				missing = append(missing, f)
			}
		}
		if len(missing) > 0 {
			p.Built.Warnings = append(p.Built.Warnings, fmt.Sprintf("package %s needs %s in the linked input collection to run; missing: %s", bp, strings.Join(need.required, ", "), strings.Join(missing, ", ")))
		}
		if len(need.anyOf) > 0 {
			found := false
			for _, f := range need.anyOf {
				found = found || have[f]
			}
			if !found {
				p.Built.Warnings = append(p.Built.Warnings, fmt.Sprintf("package %s is enabled but the linked input collection has none of %s, so it has no data: set up a connector, an input source and an input collection for it", bp, strings.Join(need.anyOf, ", ")))
			}
		}
	}
}

func anySlice(v any) []any {
	s, _ := v.([]any)
	return s
}
