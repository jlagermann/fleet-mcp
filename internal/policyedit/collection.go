package policyedit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// CollectionRequest creates, changes or deletes a content collection: an
// intel, input, asset classification (resource) or CA bundle collection, or
// a YARA ruleset. One request can also add and remove sources and link the
// collection to sensor policies or unlink it.
type CollectionRequest struct {
	Action         string   `json:"action" jsonschema:"create, update or delete"`
	Kind           string   `json:"kind,omitempty" jsonschema:"intel, input, resource (asset classification), ca_bundle or yara (a YARA ruleset). create: required. update/delete: optional, narrows the lookup when names repeat across kinds"`
	Collection     string   `json:"collection" jsonschema:"collection or YARA ruleset id or exact name (create: the new one's name)"`
	NewName        string   `json:"new_name,omitempty" jsonschema:"update: rename the collection"`
	Description    *string  `json:"description,omitempty" jsonschema:"create/update: description (an empty string clears it)"`
	AddSources     []string `json:"add_sources,omitempty" jsonschema:"create/update: sources to add, by id, alias or file name (YARA: source id or name); a source can be in several collections, and one created by another tool (Corelight-update) can be added without uploading it again"`
	RemoveSources  []string `json:"remove_sources,omitempty" jsonschema:"update: sources to take out of the collection (the sources themselves are kept)"`
	LinkPolicies   []string `json:"link_policies,omitempty" jsonschema:"create/update: sensor policies (id or exact name) that should use this collection; a policy has one collection of each kind, so this replaces the one it has"`
	UnlinkPolicies []string `json:"unlink_policies,omitempty" jsonschema:"update/delete: sensor policies (id or exact name) that should stop using this collection; they are left with no collection of this kind. A collection a policy still uses cannot be deleted"`
}

// collectionKinds maps a request kind to the Fleet Manager types and the
// sensor policy field that links it.
var collectionKinds = map[string]struct {
	Type, SourceType, Field, What string
}{
	"intel":     {"INTEL", "INTEL", "intelCollectionID", "intel collection"},
	"input":     {"INPUT", "INPUT", "inputCollectionID", "input collection"},
	"resource":  {"RESOURCE", "RESOURCE", "resourceCollectionID", "asset classification (resource) collection"},
	"ca_bundle": {"CA_BUNDLES", "CA_BUNDLES", "caBundleCollectionID", "CA bundle collection"},
	"yara":      {"", "YARA", "yaraRulesetID", "YARA ruleset"},
}

func kindOfType(t string) string {
	for k, v := range collectionKinds {
		if v.Type == t && v.Type != "" {
			return k
		}
	}
	return ""
}

// SourceInfo is a source in a collection preview.
type SourceInfo struct {
	ID        int64  `json:"id"`
	Alias     string `json:"alias,omitempty"`
	File      string `json:"file,omitempty"`
	Enabled   bool   `json:"enabled"`
	Connector string `json:"connector,omitempty"`
	ManagedBy string `json:"managed_by,omitempty"`
}

func (s SourceInfo) label() string {
	if s.Alias != "" && s.File != "" && s.Alias != s.File {
		return fmt.Sprintf("%q (%s, id %d)", s.Alias, s.File, s.ID)
	}
	n := s.Alias
	if n == "" {
		n = s.File
	}
	return fmt.Sprintf("%q (id %d)", n, s.ID)
}

// CollectionPlan is what a collection change will do; the exported fields
// are the preview.
type CollectionPlan struct {
	Action     string       `json:"action"`
	Kind       string       `json:"kind"`
	What       string       `json:"what"`
	Collection Ref          `json:"collection"`
	Sources    []SourceInfo `json:"sources_after,omitempty"`
	Policies   []Ref        `json:"policies_after,omitempty"`
	Groups     []GroupInfo  `json:"groups_affected,omitempty"`
	Changes    []Change     `json:"changes,omitempty"`
	Enrichment []string     `json:"enrichment,omitempty"`
	Steps      []string     `json:"steps"`
	Notes      []string     `json:"notes,omitempty"`
	Warnings   []string     `json:"warnings,omitempty"`
	Blockers   []string     `json:"blockers,omitempty"`

	field        string
	rename       *string
	description  *string
	add, remove  []int64
	link, unlink []Ref
	wantSources  []int64
	state        string
}

// Ready reports whether there is something to do and nothing blocks it.
func (p *CollectionPlan) Ready() bool {
	return len(p.Blockers) == 0 && (p.Action == "create" || p.Action == "delete" || len(p.Changes) > 0)
}

// State is what the plan was built from, for the confirm token.
func (p *CollectionPlan) State() string { return p.state }

func (p *CollectionPlan) block(f string, a ...any) {
	p.Blockers = append(p.Blockers, fmt.Sprintf(f, a...))
}
func (p *CollectionPlan) warn(f string, a ...any) {
	p.Warnings = append(p.Warnings, fmt.Sprintf(f, a...))
}
func (p *CollectionPlan) note(f string, a ...any) { p.Notes = append(p.Notes, fmt.Sprintf(f, a...)) }
func (p *CollectionPlan) step(f string, a ...any) { p.Steps = append(p.Steps, fmt.Sprintf(f, a...)) }

type collRec struct {
	id      int64
	name    string
	kind    string
	sources []int64
}

// contentState is every collection and ruleset with its sources, and every
// source of the kinds a collection holds.
type contentState struct {
	colls   []collRec
	sources map[string][]SourceInfo // kind -> sources
	raw     []any                   // for the state hash
}

const (
	qCollState = `query { fileCollections(input: {pagination: {limit: 10000}}) { collections { id name type sources { id } } } }`
	qRulesets  = `query { yaraRulesets { rulesets { id name sources { id } } } }`
	qSources   = `query($input: FileSourceQuery) { fileSources(input: $input) { sources { id alias name description createdBy enabled connector { name } } } }`
	qYaraSrcs  = `query { yaraSources { sources { id name description enabled } } }`
)

func readContent(ctx context.Context, api API, kind string) (*contentState, error) {
	st := &contentState{sources: map[string][]SourceInfo{}}
	var fc struct {
		FileCollections struct {
			Collections []map[string]any `json:"collections"`
		} `json:"fileCollections"`
	}
	if err := gql(ctx, api, qCollState, nil, &fc); err != nil {
		return nil, fmt.Errorf("listing collections: %w", err)
	}
	for _, c := range fc.FileCollections.Collections {
		r := collRec{id: idOf(c["id"]), name: str(c["name"]), kind: kindOfType(str(c["type"]))}
		for _, s := range listOf(c["sources"]) {
			r.sources = append(r.sources, idOf(obj(s)["id"]))
		}
		st.colls = append(st.colls, r)
		st.raw = append(st.raw, c)
	}
	var yr struct {
		YaraRulesets struct {
			Rulesets []map[string]any `json:"rulesets"`
		} `json:"yaraRulesets"`
	}
	if err := gql(ctx, api, qRulesets, nil, &yr); err != nil {
		return nil, fmt.Errorf("listing YARA rulesets: %w", err)
	}
	for _, c := range yr.YaraRulesets.Rulesets {
		r := collRec{id: idOf(c["id"]), name: str(c["name"]), kind: "yara"}
		for _, s := range listOf(c["sources"]) {
			r.sources = append(r.sources, idOf(obj(s)["id"]))
		}
		st.colls = append(st.colls, r)
		st.raw = append(st.raw, c)
	}
	if kind == "" {
		return st, nil
	}
	if err := st.loadSources(ctx, api, kind); err != nil {
		return nil, err
	}
	return st, nil
}

func (st *contentState) loadSources(ctx context.Context, api API, kind string) error {
	if _, ok := st.sources[kind]; ok {
		return nil
	}
	var list []SourceInfo
	if kind == "yara" {
		var out struct {
			YaraSources struct {
				Sources []map[string]any `json:"sources"`
			} `json:"yaraSources"`
		}
		if err := gql(ctx, api, qYaraSrcs, nil, &out); err != nil {
			return fmt.Errorf("listing YARA sources: %w", err)
		}
		for _, s := range out.YaraSources.Sources {
			list = append(list, SourceInfo{ID: idOf(s["id"]), Alias: str(s["name"]), Enabled: s["enabled"] == true,
				ManagedBy: managedBy(str(s["name"]), str(s["description"]), "")})
		}
	} else {
		var out struct {
			FileSources struct {
				Sources []map[string]any `json:"sources"`
			} `json:"fileSources"`
		}
		vars := map[string]any{"input": map[string]any{"type": collectionKinds[kind].SourceType, "pagination": map[string]any{"limit": 10000}}}
		if err := gql(ctx, api, qSources, vars, &out); err != nil {
			return fmt.Errorf("listing %s sources: %w", kind, err)
		}
		for _, s := range out.FileSources.Sources {
			si := SourceInfo{ID: idOf(s["id"]), Alias: str(s["alias"]), File: str(s["name"]), Enabled: s["enabled"] == true,
				ManagedBy: managedBy(str(s["alias"]), str(s["description"]), str(s["createdBy"]))}
			if c := obj(s["connector"]); c != nil {
				si.Connector = str(c["name"])
			}
			list = append(list, si)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	st.sources[kind] = list
	return nil
}

// managedBy names the tool that manages a source, from the conventions
// Corelight-update and Fleet-client use (the same rules as fm_content_push).
func managedBy(name, description, createdBy string) string {
	d := strings.ToLower(description + " " + createdBy)
	switch {
	case strings.Contains(d, "corelight update") || strings.Contains(d, "corelight-update") ||
		strings.HasPrefix(strings.ToLower(name), "corelight-update"):
		return "Corelight-update"
	case strings.Contains(d, "fleet client") || strings.Contains(d, "fleet-client") || strings.EqualFold(name, "fleet-client"):
		return "Fleet-client"
	case strings.Contains(d, "fleet-mcp"):
		return "fleet-mcp"
	}
	return ""
}

// findSource resolves a source by id, alias or file name among list.
func findSource(list []SourceInfo, ref string) (SourceInfo, error) {
	ref = strings.TrimSpace(ref)
	id, _ := strconv.ParseInt(ref, 10, 64)
	var byAlias, byFile []SourceInfo
	for _, s := range list {
		if id > 0 && s.ID == id {
			return s, nil
		}
		if s.Alias == ref {
			byAlias = append(byAlias, s)
		}
		if s.File == ref {
			byFile = append(byFile, s)
		}
	}
	match := byAlias
	if len(match) == 0 {
		match = byFile
	}
	switch len(match) {
	case 1:
		return match[0], nil
	case 0:
		return SourceInfo{}, fmt.Errorf("no source %q", ref)
	}
	var l []string
	for _, s := range match {
		l = append(l, s.label())
	}
	return SourceInfo{}, fmt.Errorf("source %q matches %d sources (%s); use the id", ref, len(match), strings.Join(l, ", "))
}

// PrepareCollection builds the plan. It changes nothing.
func PrepareCollection(ctx context.Context, api API, req CollectionRequest) (*CollectionPlan, error) {
	act := strings.ToLower(strings.TrimSpace(req.Action))
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if kind != "" {
		if _, ok := collectionKinds[kind]; !ok {
			return nil, fmt.Errorf("unknown kind %q: use intel, input, resource, ca_bundle or yara", req.Kind)
		}
	}
	name := strings.TrimSpace(req.Collection)
	if name == "" {
		return nil, fmt.Errorf("collection is required")
	}
	switch act {
	case "create", "update", "delete":
	default:
		return nil, fmt.Errorf("unknown action %q: use create, update or delete", req.Action)
	}

	st, err := readContent(ctx, api, "")
	if err != nil {
		return nil, err
	}
	p := &CollectionPlan{Action: act}

	// Find the collection.
	var cur *collRec
	if act == "create" {
		if kind == "" {
			return nil, fmt.Errorf("kind is required to create a collection: intel, input, resource, ca_bundle or yara")
		}
		for i, c := range st.colls {
			if c.kind == kind && c.name == name {
				cur = &st.colls[i]
			}
		}
		if cur != nil {
			p.block("a %s named %q already exists (id %d); use action update to change it", collectionKinds[kind].What, name, cur.id)
		}
		p.Collection = Ref{Name: name}
	} else {
		id, _ := strconv.ParseInt(name, 10, 64)
		var hits []*collRec
		for i, c := range st.colls {
			if kind != "" && c.kind != kind {
				continue
			}
			if (id > 0 && c.id == id) || c.name == name {
				hits = append(hits, &st.colls[i])
			}
		}
		switch {
		case len(hits) == 0:
			var names []string
			for _, c := range st.colls {
				if kind == "" || c.kind == kind {
					names = append(names, fmt.Sprintf("%s %q (%d)", c.kind, c.name, c.id))
				}
			}
			sort.Strings(names)
			return nil, fmt.Errorf("no collection %q; there are: %s", name, strings.Join(names, ", "))
		case len(hits) > 1:
			var l []string
			for _, h := range hits {
				l = append(l, fmt.Sprintf("%s %q (%d)", h.kind, h.name, h.id))
			}
			return nil, fmt.Errorf("collection %q matches %s; pass kind or the id", name, strings.Join(l, ", "))
		}
		cur = hits[0]
		kind = cur.kind
		p.Collection = Ref{ID: cur.id, Name: cur.name}
	}
	k := collectionKinds[kind]
	p.Kind, p.What, p.field = kind, k.What, k.Field
	if err := st.loadSources(ctx, api, kind); err != nil {
		return nil, err
	}
	srcByID := map[int64]SourceInfo{}
	for _, s := range st.sources[kind] {
		srcByID[s.ID] = s
	}

	// Policies and which use the collection now.
	pols, err := policies(ctx, api)
	if err != nil {
		return nil, err
	}
	var polRefs []Ref
	using := map[int64]bool{}
	linkOf := map[int64]int64{}
	for _, pol := range pols {
		r := Ref{ID: idOf(pol["id"]), Name: str(pol["name"])}
		polRefs = append(polRefs, r)
		linkOf[r.ID] = idOf(pol[k.Field])
		if cur != nil && act != "create" && linkOf[r.ID] == cur.id {
			using[r.ID] = true
		}
	}
	collName := func(id int64) string {
		for _, c := range st.colls {
			if c.id == id && c.kind == kind {
				return fmt.Sprintf("%q (%d)", c.name, c.id)
			}
		}
		return fmt.Sprintf("%d", id)
	}

	// Name and description.
	if act == "create" {
		p.step("create %s %q", k.What, name)
		if req.Description != nil {
			p.description = req.Description
		}
	}
	if nn := strings.TrimSpace(req.NewName); nn != "" {
		if act != "update" {
			p.block("new_name is only for action update")
		} else if nn != cur.name {
			for _, c := range st.colls {
				if c.kind == kind && c.name == nn && c.id != cur.id {
					p.block("another %s is already named %q (id %d)", k.What, nn, c.id)
				}
			}
			p.rename = &nn
			p.Changes = append(p.Changes, Change{Kind: "name", Key: "name", From: cur.name, To: nn})
			p.step("rename %s %s to %q", k.What, p.Collection, nn)
		}
	}
	if act == "update" && req.Description != nil {
		p.description = req.Description
		p.Changes = append(p.Changes, Change{Kind: "description", Key: "description", To: *req.Description})
		p.step("set the description of %s %s", k.What, p.Collection)
	}
	if act == "delete" && (req.NewName != "" || req.Description != nil || len(req.AddSources) > 0 || len(req.RemoveSources) > 0 || len(req.LinkPolicies) > 0) {
		p.block("delete only takes unlink_policies; leave out new_name, description, add_sources, remove_sources and link_policies")
	}
	if act == "create" && len(req.RemoveSources) > 0 {
		p.block("remove_sources is not used with create")
	}
	if act == "create" && len(req.UnlinkPolicies) > 0 {
		p.block("unlink_policies is not used with create")
	}

	// Sources.
	in := map[int64]bool{}
	if cur != nil && act != "create" {
		for _, id := range cur.sources {
			in[id] = true
		}
	}
	for _, ref := range req.AddSources {
		s, err := findSource(st.sources[kind], ref)
		if err != nil {
			p.block("add_sources: %v among the %s sources", err, kind)
			continue
		}
		if in[s.ID] {
			p.note("source %s is already in the collection", s.label())
			continue
		}
		in[s.ID] = true
		p.add = append(p.add, s.ID)
		p.Changes = append(p.Changes, Change{Kind: "source", Key: s.label(), To: "added"})
		if !s.Enabled {
			p.warn("source %s is disabled: sensors do not get it until it is enabled", s.label())
		}
		if s.ManagedBy != "" {
			p.note("source %s is managed by %s, which keeps updating its content; adding it here only changes which collections include it", s.label(), s.ManagedBy)
		}
	}
	for _, ref := range req.RemoveSources {
		s, err := findSource(st.sources[kind], ref)
		if err != nil {
			p.block("remove_sources: %v among the %s sources", err, kind)
			continue
		}
		if !in[s.ID] {
			p.note("source %s is not in the collection", s.label())
			continue
		}
		delete(in, s.ID)
		p.remove = append(p.remove, s.ID)
		p.Changes = append(p.Changes, Change{Kind: "source", Key: s.label(), From: "in the collection", To: "removed (the source is kept)"})
	}
	if len(p.add) > 0 {
		p.step("add %d source(s) to the %s", len(p.add), k.What)
	}
	if len(p.remove) > 0 {
		p.step("remove %d source(s) from the %s", len(p.remove), k.What)
	}
	if act != "delete" {
		// Enabled sources that share a file name: the sensors get one file
		// of that name. Warn when this change adds such a source; a clash
		// that is already there is only noted.
		added := map[int64]bool{}
		for _, id := range p.add {
			added[id] = true
		}
		files := map[string][]string{}
		newClash := map[string]bool{}
		for id := range in {
			s, ok := srcByID[id]
			if !ok {
				continue
			}
			p.Sources = append(p.Sources, s)
			if s.File != "" && s.Enabled {
				files[s.File] = append(files[s.File], s.label())
				if added[id] {
					newClash[s.File] = true
				}
			}
		}
		sort.Slice(p.Sources, func(i, j int) bool { return p.Sources[i].ID < p.Sources[j].ID })
		for _, f := range sortedKeys(files) {
			l := files[f]
			if len(l) < 2 {
				continue
			}
			sort.Strings(l)
			msg := fmt.Sprintf("%d enabled sources in the collection have the file name %s: %s; the sensors get one file of that name, so they must use the same format", len(l), f, strings.Join(l, ", "))
			if newClash[f] {
				p.warn("%s", msg)
			} else {
				p.note("already so: %s", msg)
			}
		}
		for id := range in {
			p.wantSources = append(p.wantSources, id)
		}
		sort.Slice(p.wantSources, func(i, j int) bool { return p.wantSources[i] < p.wantSources[j] })
	}

	// Policies.
	after := map[int64]bool{}
	for id := range using {
		after[id] = true
	}
	for _, ref := range req.LinkPolicies {
		r, err := pick(polRefs, ref, "sensor policy")
		if err != nil {
			p.block("link_policies: %v", err)
			continue
		}
		if using[r.ID] {
			p.note("sensor policy %s already uses this %s", r, k.What)
			continue
		}
		after[r.ID] = true
		p.link = append(p.link, r)
		from := "(none)"
		if old := linkOf[r.ID]; old > 0 {
			from = k.What + " " + collName(old)
			p.warn("sensor policy %s uses %s %s now; linking replaces it, so its sensors stop getting sources that are only in that one", r, k.What, collName(old))
		}
		p.Changes = append(p.Changes, Change{Kind: "link", Key: fmt.Sprintf("sensor policy %s %s", r, k.Field), From: from, To: k.What + " " + p.Collection.Name})
		p.step("set %s of sensor policy %s to this %s", k.Field, r, k.What)
	}
	for _, ref := range req.UnlinkPolicies {
		r, err := pick(polRefs, ref, "sensor policy")
		if err != nil {
			p.block("unlink_policies: %v", err)
			continue
		}
		if !using[r.ID] {
			p.note("sensor policy %s does not use this %s", r, k.What)
			continue
		}
		delete(after, r.ID)
		p.unlink = append(p.unlink, r)
		p.Changes = append(p.Changes, Change{Kind: "link", Key: fmt.Sprintf("sensor policy %s %s", r, k.Field), From: k.What + " " + p.Collection.Name, To: "(none)"})
		p.warn("sensor policy %s is left with no %s: its sensors stop getting these sources", r, k.What)
		p.step("unlink this %s from sensor policy %s", k.What, r)
	}
	for _, r := range polRefs {
		if after[r.ID] {
			p.Policies = append(p.Policies, r)
		}
	}
	if act == "delete" {
		if len(after) > 0 {
			var l []string
			for _, r := range p.Policies {
				l = append(l, r.String())
			}
			p.block("sensor policies still use this %s: %s; add them to unlink_policies (they are left with no %s) or link another one to them first", k.What, strings.Join(l, ", "), k.What)
		}
		p.Policies = nil
		p.step("delete %s %s (its %d source(s) are kept)", k.What, p.Collection, len(cur.sources))
		p.Changes = append(p.Changes, Change{Kind: "collection", Key: p.Collection.String(), From: "exists", To: "deleted"})
	} else if len(after) == 0 {
		p.note("no sensor policy uses this %s, so no sensor gets its sources; pass link_policies to link it", k.What)
	}

	// Sensor groups that see the change.
	affected := map[int64]bool{}
	if len(p.add) > 0 || len(p.remove) > 0 {
		for id := range after {
			affected[id] = true
		}
	}
	for _, r := range p.link {
		affected[r.ID] = true
	}
	for _, r := range p.unlink {
		affected[r.ID] = true
	}
	if len(affected) > 0 {
		groups, err := listGroups(ctx, api)
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			if affected[g.PolicyID] {
				p.Groups = append(p.Groups, g)
			}
		}
		if len(p.Groups) == 0 {
			p.note("no sensor group uses the sensor policies this changes, so no sensor is affected yet")
		}
	}

	if kind == "input" && act != "delete" && len(p.Policies) > 0 {
		p.checkReaders(ctx, api)
	}

	b, _ := json.Marshal(map[string]any{"content": st.raw, "links": linkOf, "sources": st.sources[kind]})
	p.state = string(b)
	return p, nil
}

// checkReaders notes which loaded package on the connected sensors reads
// each input file the collection delivers (bro.inputs lists the files a
// loaded package looks for).
func (p *CollectionPlan) checkReaders(ctx context.Context, api API) {
	var cat struct {
		List []map[string]any `json:"list"`
	}
	if err := api.GetJSON(ctx, pathCatalog, nil, &cat); err != nil {
		return
	}
	readers := map[string]map[string]bool{}
	connected := 0
	for _, s := range cat.List {
		if s["fleet.connected"] != true {
			continue
		}
		connected++
		for _, in := range listOf(s["bro.inputs"]) {
			m := obj(in)
			if readers[str(m["name"])] == nil {
				readers[str(m["name"])] = map[string]bool{}
			}
			readers[str(m["name"])][str(m["package"])] = true
		}
	}
	if connected == 0 {
		p.Enrichment = append(p.Enrichment, "no sensor is connected, so which package reads each input file cannot be checked")
		return
	}
	seen := map[string]bool{}
	for _, s := range p.Sources {
		if s.File == "" || seen[s.File] || !s.Enabled {
			continue
		}
		seen[s.File] = true
		if r := readers[s.File]; len(r) > 0 {
			p.Enrichment = append(p.Enrichment, fmt.Sprintf("input file %s is read by %s on the connected sensors", s.File, strings.Join(sortedKeys(r), ", ")))
		} else {
			p.Enrichment = append(p.Enrichment, fmt.Sprintf("no connected sensor has a loaded package that reads input file %s: it does nothing until one is enabled", s.File))
		}
	}
}

// CollectionResult is what a collection change did.
type CollectionResult struct {
	ID           int64    `json:"id,omitempty"`
	Done         []string `json:"done"`
	Verification []string `json:"verification,omitempty"`
}

// ApplyCollection makes the change, in the order of the plan's steps, and
// reads the collection and policies back. It stops at the first error and
// reports what was already done.
func ApplyCollection(ctx context.Context, api API, p *CollectionPlan) (*CollectionResult, error) {
	if !p.Ready() {
		return nil, fmt.Errorf("nothing to change or blocked: %v", p.Blockers)
	}
	res := &CollectionResult{ID: p.Collection.ID}
	yara := p.Kind == "yara"
	k := collectionKinds[p.Kind]
	ids := func(l []int64) []any {
		out := make([]any, len(l))
		for i, v := range l {
			out[i] = v
		}
		return out
	}

	if p.Action == "create" {
		var out map[string]map[string]any
		in := map[string]any{"name": p.Collection.Name}
		if p.description != nil {
			in["description"] = *p.description
		}
		q, key := `mutation($input: NewFileCollection!) { createFileCollection(input: $input) { id } }`, "createFileCollection"
		if yara {
			q, key = `mutation($input: NewYaraRuleset!) { createYaraRuleset(input: $input) { id } }`, "createYaraRuleset"
		} else {
			in["type"] = k.Type
		}
		if err := gql(ctx, api, q, map[string]any{"input": in}, &out); err != nil {
			return res, fmt.Errorf("creating %s %q: %w", k.What, p.Collection.Name, err)
		}
		res.ID = idOf(out[key]["id"])
		if res.ID == 0 {
			return res, fmt.Errorf("creating %s %q: Fleet Manager returned no id", k.What, p.Collection.Name)
		}
		p.Collection.ID = res.ID
		res.Done = append(res.Done, fmt.Sprintf("created %s %s", k.What, p.Collection))
	}
	if p.Action == "update" && (p.rename != nil || p.description != nil) {
		in := map[string]any{"id": fmt.Sprint(p.Collection.ID)}
		if p.rename != nil {
			in["name"] = *p.rename
		}
		if p.description != nil {
			in["description"] = *p.description
		}
		q := `mutation($input: UpdateFileCollection!) { updateFileCollection(input: $input) { id } }`
		if yara {
			q = `mutation($input: UpdateYaraRuleset!) { updateYaraRuleset(input: $input) { id } }`
		}
		if err := gql(ctx, api, q, map[string]any{"input": in}, nil); err != nil {
			return res, fmt.Errorf("updating %s %s: %w", k.What, p.Collection, err)
		}
		res.Done = append(res.Done, fmt.Sprintf("updated the name/description of %s %s", k.What, p.Collection))
	}
	assoc := func(add bool, src []int64) error {
		if len(src) == 0 {
			return nil
		}
		in := map[string]any{"collectionID": p.Collection.ID, "sourceIDs": ids(src)}
		typ, op := "FileCollectionToSourcesInput", "associateFileCollectionToSources"
		if !add {
			op = "unassociateFileCollectionFromSources"
		}
		if yara {
			in = map[string]any{"rulesetID": p.Collection.ID, "sourceIDs": ids(src)}
			typ, op = "YaraRulesetToSourcesInput", "associateYaraRulesetToSources"
			if !add {
				op = "unassociateYaraRulesetFromSources"
			}
		}
		q := fmt.Sprintf(`mutation($input: %s!) { %s(input: $input) { message } }`, typ, op)
		return gql(ctx, api, q, map[string]any{"input": in}, nil)
	}
	if err := assoc(true, p.add); err != nil {
		return res, fmt.Errorf("adding sources to %s %s: %w", k.What, p.Collection, err)
	}
	if len(p.add) > 0 {
		res.Done = append(res.Done, fmt.Sprintf("added %d source(s)", len(p.add)))
	}
	if err := assoc(false, p.remove); err != nil {
		return res, fmt.Errorf("removing sources from %s %s: %w", k.What, p.Collection, err)
	}
	if len(p.remove) > 0 {
		res.Done = append(res.Done, fmt.Sprintf("removed %d source(s)", len(p.remove)))
	}
	setLink := func(r Ref, v any) error {
		_, err := api.Do(ctx, http.MethodPut, fmt.Sprintf("%s/%d", pathPolicy, r.ID), nil, jsonBody(map[string]any{k.Field: v}), "application/json")
		return err
	}
	for _, r := range p.link {
		if err := setLink(r, p.Collection.ID); err != nil {
			return res, fmt.Errorf("linking sensor policy %s: %w", r, err)
		}
		res.Done = append(res.Done, fmt.Sprintf("linked sensor policy %s", r))
	}
	for _, r := range p.unlink {
		if err := setLink(r, nil); err != nil {
			return res, fmt.Errorf("unlinking sensor policy %s: %w", r, err)
		}
		res.Done = append(res.Done, fmt.Sprintf("unlinked sensor policy %s", r))
	}
	if p.Action == "delete" {
		q := `mutation($ids: [ID!]!) { deleteFileCollections(ids: $ids) { message } }`
		if yara {
			q = `mutation($ids: [ID!]!) { deleteYaraRulesets(ids: $ids) { message } }`
		}
		if err := gql(ctx, api, q, map[string]any{"ids": []any{fmt.Sprint(p.Collection.ID)}}, nil); err != nil {
			return res, fmt.Errorf("deleting %s %s: %w", k.What, p.Collection, err)
		}
		res.Done = append(res.Done, fmt.Sprintf("deleted %s %s", k.What, p.Collection))
	}

	p.verify(ctx, api, res)
	return res, nil
}

// verify reads the collection and the changed policies back.
func (p *CollectionPlan) verify(ctx context.Context, api API, res *CollectionResult) {
	bad := func(f string, a ...any) { res.Verification = append(res.Verification, fmt.Sprintf(f, a...)) }
	st, err := readContent(ctx, api, "")
	if err != nil {
		bad("could not read the collections back: %v", err)
		return
	}
	var got *collRec
	for i, c := range st.colls {
		if c.kind == p.Kind && c.id == p.Collection.ID {
			got = &st.colls[i]
		}
	}
	switch {
	case p.Action == "delete":
		if got != nil {
			bad("%s %s still exists", p.What, p.Collection)
		}
	case got == nil:
		bad("%s %s is not there", p.What, p.Collection)
	default:
		if p.rename != nil && got.name != *p.rename {
			bad("the name is %q, wanted %q", got.name, *p.rename)
		}
		have := append([]int64(nil), got.sources...)
		sort.Slice(have, func(i, j int) bool { return have[i] < have[j] })
		if fmt.Sprint(have) != fmt.Sprint(p.wantSources) {
			bad("the sources are %v, wanted %v", have, p.wantSources)
		}
	}
	check := func(r Ref, want int64) {
		var pol map[string]any
		if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathPolicy, r.ID), nil, &pol); err != nil {
			bad("could not read sensor policy %s back: %v", r, err)
			return
		}
		if idOf(pol[p.field]) != want {
			bad("sensor policy %s has %s %v, wanted %d", r, p.field, pol[p.field], want)
		}
	}
	for _, r := range p.link {
		check(r, p.Collection.ID)
	}
	for _, r := range p.unlink {
		check(r, 0)
	}
	if p.Kind == "yara" && p.Action != "delete" && (len(p.add) > 0 || len(p.remove) > 0) {
		var rs struct {
			YaraRuleset map[string]any `json:"yaraRuleset"`
		}
		if err := gql(ctx, api, `query($id: ID!) { yaraRuleset(id: $id) { id isProcessing processingError } }`, map[string]any{"id": fmt.Sprint(p.Collection.ID)}, &rs); err == nil {
			if e := str(rs.YaraRuleset["processingError"]); e != "" {
				bad("YARA ruleset %s reports a processing error: %s", p.Collection, e)
			}
		}
	}
}
