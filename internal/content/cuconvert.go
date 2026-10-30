package content

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Answers to the cu_modifiers decision.
const (
	CUConvert    = "convert"
	CUCommentOut = "comment_out"
)

// Decision is a question the user must answer before the push can run.
type Decision struct {
	ID       string `json:"id"`
	Question string `json:"question"`
	// Resolve says how each answer changes the request.
	Resolve map[string]string `json:"resolve"`
}

// Conversion is the preview of rewriting Corelight-update syntax that
// Fleet Manager rejects or ignores.
type Conversion struct {
	Answer string          `json:"answer,omitempty"`
	Lines  []ConvertedLine `json:"lines"`
	// Count is the number of lines in Corelight-update syntax.
	Count int `json:"count"`
	// Output is the converted file written next to the user's file.
	Output       string `json:"output_file,omitempty"`
	OutputSHA256 string `json:"output_sha256,omitempty"`
	// FrozenSIDs got a RuleOptions line with the rule's whole option text.
	FrozenSIDs []string `json:"frozen_sids,omitempty"`
	// NeedRulesFile lists lines that touch rules whose original text
	// fleet-mcp could not read; rules_file lets it convert them.
	NeedRulesFile []int  `json:"need_rules_file,omitempty"`
	RuleText      string `json:"rule_text,omitempty"`
}

// ConvertedLine is one Corelight-update line and what it becomes.
type ConvertedLine struct {
	Line     int      `json:"line"`
	Original string   `json:"original"`
	Reason   string   `json:"reason"`
	Action   string   `json:"action"` // converted or commented out
	Result   []string `json:"result,omitempty"`
}

// cuOptionKeys are Corelight-update change keys Fleet Manager rejects that
// edit a rule's options; each becomes a RuleOptions line per rule.
var cuOptionKeys = map[string]string{"msg": "Msg", "sid": "SID", "gid": "GID", "rev": "Rev", "classtype": "Classtype",
	"metadata": "Metadata", "metadataappend": "MetadataAppend", "threshold": "Threshold", "target": "Target",
	"otherappend": "OtherAppend", "flowbitsnoalert": "FlowbitsNoAlert", "noalert": "NoAlert"}

// modLine is one line of a configuration file.
type modLine struct {
	n             int
	text          string // without a trailing comment
	match, change string
	reason        string // why Fleet Manager cannot take it as written; "" = it can
	fixMatch      bool
	key, value    string // change key (lower case) and value
	legacy        bool
	from, to      string
	other         bool
}

// parseModLine reads a line; it returns nil for blank lines and comments.
func parseModLine(kind Kind, n int, raw string) *modLine {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	if j := strings.Index(line, " #"); j > 0 && !strings.Contains(line[:j], "\"") {
		line = strings.TrimSpace(line[:j])
	}
	ml := &modLine{n: n, text: line}
	ml.match, ml.change = splitModifier(line)
	var reasons []string
	lower := strings.ToLower(ml.match)
	switch {
	case ml.match == "*":
		ml.fixMatch = true
		reasons = append(reasons, "Fleet Manager has no * match")
	case strings.HasPrefix(lower, "re:") && !strings.HasPrefix(ml.match[3:], "/"):
		ml.fixMatch = true
		reasons = append(reasons, "Fleet Manager needs the regex enclosed in slashes (re:/.../)")
	case strings.HasPrefix(lower, "metadata:"):
		ml.fixMatch = true
		reasons = append(reasons, "a Metadata: match matches no rule in Fleet Manager")
	default:
		bare := strings.TrimSpace(ml.match)
		if strings.HasPrefix(lower, "sid:") {
			bare = strings.TrimSpace(bare[4:])
		}
		if sids, ok := sidList(bare); ok {
			switch {
			case len(sids) > 1:
				ml.fixMatch = true
				reasons = append(reasons, "Fleet Manager does not accept a list of SIDs on one line")
			case strings.Contains(bare, ":"):
				ml.fixMatch = true
				reasons = append(reasons, "Fleet Manager accepts gid:sid but it matches no rule")
			}
		}
	}
	if kind == SuricataModify && ml.change != "" {
		switch {
		case strings.HasPrefix(ml.change, "\""):
			ml.legacy = true
			if i := strings.Index(ml.change, "\" \""); i > 0 && strings.HasSuffix(ml.change, "\"") && len(ml.change) >= i+4 {
				ml.from, ml.to = ml.change[1:i], ml.change[i+3:len(ml.change)-1]
			}
			reasons = append(reasons, "Fleet Manager does not support Corelight-update's regex rewrite (\"<from>\" \"<to>\")")
		default:
			key, val, _ := strings.Cut(ml.change, ":")
			ml.key = strings.ToLower(strings.TrimSpace(key))
			ml.value = val
			switch {
			case ml.key == "other":
				ml.other = true
				reasons = append(reasons, "Fleet Manager rejects Other:, and it replaces all detection options, so fleet-mcp does not convert it")
			case cuOptionKeys[ml.key] != "":
				reasons = append(reasons, fmt.Sprintf("Fleet Manager rejects the change key %s", cuOptionKeys[ml.key]))
			}
		}
	}
	ml.reason = strings.Join(reasons, "; ")
	return ml
}

// cu reports whether the line uses Corelight-update syntax.
func (ml *modLine) cu() bool { return ml.reason != "" }

// needsText reports whether converting the line needs the rules' text.
func (ml *modLine) needsText() bool { return ml.legacy || cuOptionKeys[ml.key] != "" }

// fixedMatches returns the line's match in Fleet Manager syntax (several
// for a SID list).
func (ml *modLine) fixedMatches() []string {
	m := strings.TrimSpace(ml.match)
	lower := strings.ToLower(m)
	switch {
	case m == "*":
		return []string{"re:/./"}
	case strings.HasPrefix(lower, "re:"):
		return []string{"re:/" + escapeSlashes(regexOf(m[3:])) + "/"}
	case strings.HasPrefix(lower, "metadata:"):
		return []string{"re:/metadata:[^;]*" + escapeSlashes(regexp.QuoteMeta(trimQuotes(m[9:]))) + "/"}
	}
	bare := m
	if strings.HasPrefix(lower, "sid:") {
		bare = strings.TrimSpace(m[4:])
	}
	if sids, ok := sidList(bare); ok {
		return sids
	}
	return []string{m}
}

// escapeSlashes escapes each unescaped '/' so a regex fits in /.../.
func escapeSlashes(re string) string {
	var b strings.Builder
	for i := 0; i < len(re); i++ {
		switch re[i] {
		case '\\':
			b.WriteByte('\\')
			if i+1 < len(re) {
				i++
				b.WriteByte(re[i])
			}
		case '/':
			b.WriteString(`\/`)
		default:
			b.WriteByte(re[i])
		}
	}
	return b.String()
}

// convOut is the result of converting a file.
type convOut struct {
	text          []byte
	lines         []ConvertedLine
	count         int
	frozen        []string
	needRulesFile []int
	notes, warns  []string
}

// convertModifier rewrites the Corelight-update lines of a configuration
// file. With comment_out they are commented out; otherwise they are
// converted, which for option changes and regex rewrites works on rs, the
// rules as they are before the file applies. Lines are simulated in file
// order, the way both tools apply them.
func convertModifier(kind Kind, b []byte, answer string, rs *ruleSet) *convOut {
	out := &convOut{}
	var buf strings.Builder
	frozen := map[string]bool{}
	seen := map[string]bool{}
	unknownNoted := false
	emit := func(s string) { buf.WriteString(s); buf.WriteByte('\n') }
	raws := strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n")
	if len(raws) > 0 && raws[len(raws)-1] == "" {
		raws = raws[:len(raws)-1]
	}
	for i, raw := range raws {
		ml := parseModLine(kind, i+1, raw)
		if ml == nil {
			emit(raw)
			continue
		}
		if !ml.cu() {
			emit(raw)
			if rs != nil && kind == SuricataModify {
				if m, err := compileMatch(ml.match); err == nil {
					if m.unknown && !unknownNoted {
						unknownNoted = true
						out.notes = append(out.notes, fmt.Sprintf("line %d matches by a key fleet-mcp cannot evaluate (%s); the conversion assumes it changes none of the converted rules", ml.n, ml.match))
					}
					applyNative(rs, m, ml.key, ml.value)
				}
			}
			continue
		}
		out.count++
		cl := ConvertedLine{Line: ml.n, Original: ml.text, Reason: ml.reason}
		commentOut := func(why string) {
			cl.Action = "commented out"
			if why != "" {
				cl.Reason = why
			}
			emit(fmt.Sprintf("# fleet-mcp: commented out (%s): %s", cl.Reason, raw))
		}
		var result []string
		switch {
		case seen[ml.text]:
			commentOut("a repeat of an earlier line; Corelight-update applies it only once")
		case answer == CUCommentOut:
			commentOut("")
		case ml.other:
			commentOut("")
		case ml.legacy && ml.from == "":
			commentOut("cannot read the \"<from>\" \"<to>\" part")
		case !ml.needsText():
			for _, m := range ml.fixedMatches() {
				if ml.change == "" {
					result = append(result, m)
				} else {
					result = append(result, m+" "+ml.change)
				}
			}
			if rs != nil && kind == SuricataModify {
				if m, err := compileMatch(ml.match); err == nil {
					applyNative(rs, m, ml.key, ml.value)
				}
			}
		case rs == nil && answer == "":
			cl.Action = "converted if you choose convert"
			cl.Reason += "; what it becomes depends on the rules' text, which fleet-mcp reads only after you choose convert"
			emit(raw)
		case rs == nil:
			commentOut("no rule text to convert it with")
		default:
			var why string
			var unresolved bool
			result, why, unresolved = convertWithText(ml, rs, frozen, &out.notes)
			if unresolved {
				out.needRulesFile = append(out.needRulesFile, ml.n)
			}
			if why != "" {
				commentOut(why)
				result = nil
			}
		}
		seen[ml.text] = true
		if result != nil {
			cl.Action = "converted"
			emit(fmt.Sprintf("# fleet-mcp: converted from Corelight-update syntax (%s): %s", ml.reason, raw))
			for _, r := range result {
				emit(r)
			}
			cl.Result = sample(result, 5)
		}
		out.lines = append(out.lines, cl)
	}
	out.frozen = rs.orderedSIDs(frozen)
	out.text = []byte(buf.String())
	return out
}

// orderedSIDs returns the SIDs in set, in rule order.
func (rs *ruleSet) orderedSIDs(set map[string]bool) []string {
	if rs == nil || len(set) == 0 {
		return nil
	}
	var out []string
	for _, r := range rs.list {
		if set[r.SID] {
			out = append(out, r.SID)
		}
	}
	return out
}

func (rs *ruleSet) matching(m *matcher) []*rule {
	var out []*rule
	for _, r := range rs.list {
		if m.matches(r) {
			out = append(out, r)
		}
	}
	return out
}

// applyNative applies a change Fleet Manager supports to the rules m
// selects.
func applyNative(rs *ruleSet, m *matcher, key, value string) {
	if key == "" {
		return
	}
	for _, r := range rs.matching(m) {
		switch {
		case key == "ruleoptions":
			r.Opts = strings.TrimSpace(value)
		case key == "priority":
			r.Opts = setOption(r.Opts, "priority", "priority:"+strings.TrimSuffix(trimQuotes(value), ";")+";")
		default:
			if p := r.field(key); p != nil {
				*p = trimQuotes(value)
			}
		}
	}
}

// convertWithText converts an option change or a regex rewrite. It
// returns the new lines, or why the line has to be commented out.
func convertWithText(ml *modLine, rs *ruleSet, frozen map[string]bool, notes *[]string) (lines []string, why string, unresolved bool) {
	m, err := compileMatch(ml.match)
	if err != nil {
		return nil, err.Error(), false
	}
	m.cu = true
	if m.unknown {
		return nil, "fleet-mcp cannot evaluate this match", false
	}
	matched := rs.matching(m)
	if len(matched) == 0 {
		return nil, "matches no rule in the Suricata policy", false
	}
	var missing []string
	for _, r := range matched {
		if rs.unresolved[r.SID] {
			missing = append(missing, r.SID)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Sprintf("the current modify.conf on Fleet Manager changes SID %s and its original text is not available; give rules_file to convert this line",
			strings.Join(sample(missing, 3), ", ")), true
	}
	if !ml.legacy {
		for _, r := range matched {
			r.Opts = cuChange(r.Opts, ml.key, ml.value)
			if ml.key == "sid" {
				r.SID = strings.TrimSuffix(trimQuotes(ml.value), ";")
			}
			lines = append(lines, fmt.Sprintf("%s RuleOptions:%s", r.SID, r.Opts))
			frozen[r.SID] = true
		}
		return lines, "", false
	}
	from, err := regexp.Compile(ml.from)
	if err != nil {
		return nil, fmt.Sprintf("the <from> regex does not compile: %v", err), false
	}
	// Only rules whose text the rewrite changes count.
	changed := map[*rule]*rule{}
	var order []*rule
	for _, r := range matched {
		text := from.ReplaceAllString(r.cuText(), ml.to)
		if text == r.cuText() {
			continue
		}
		nr, ok := parseRule(text)
		if !ok {
			return nil, fmt.Sprintf("the rewrite turns SID %s into text that is not a rule", r.SID), false
		}
		nr.File = r.File
		changed[r] = nr
		order = append(order, r)
	}
	if len(order) == 0 {
		return nil, "the rewrite changes none of the rules it matches", false
	}
	if g, extra, ok := groupRewrite(m, order, changed, rs); ok {
		lines = g
		if extra > 0 {
			*notes = append(*notes, fmt.Sprintf("line %d: the converted lines also change %d disabled rule(s). Corelight-update tries the regex against \"#alert ...\" for a rule that is commented out, so it leaves them alone; Fleet Manager matches disabled rules too. No effect while they stay disabled, and Corelight-update would change one too once it is enabled",
				ml.n, extra))
		}
	} else {
		for _, r := range order {
			nr := changed[r]
			if nr.Dir != r.Dir {
				return nil, fmt.Sprintf("the rewrite changes the direction of SID %s, which Fleet Manager cannot change", r.SID), false
			}
			if nr.SID != r.SID {
				return nil, fmt.Sprintf("the rewrite changes the SID of SID %s", r.SID), false
			}
			oh, nh := r.header(), nr.header()
			for i, k := range headerFields {
				if k != "" && oh[i] != nh[i] {
					lines = append(lines, fmt.Sprintf("%s %s:%s", r.SID, headerKey[k], quoteValue(nh[i])))
				}
			}
			if nr.Opts != r.Opts {
				lines = append(lines, fmt.Sprintf("%s RuleOptions:%s", r.SID, nr.Opts))
				frozen[r.SID] = true
			}
		}
	}
	for r, nr := range changed {
		sid := r.SID
		*r = *nr
		r.SID = sid
	}
	return lines, "", false
}

// groupRewrite turns a regex rewrite that changes one header field into
// one re: line per original value of that field, so rules added to the
// source later are still changed. It works only when, over the enabled
// rules, that selects exactly the rules the rewrite changes (matched).
// extra counts disabled rules the lines change that the rewrite does not.
func groupRewrite(m *matcher, matched []*rule, changed map[*rule]*rule, rs *ruleSet) (lines []string, extra int, ok bool) {
	if m.re == nil {
		return nil, 0, false
	}
	idx := -1
	for _, r := range matched {
		nr := changed[r]
		if nr.Opts != r.Opts || nr.Dir != r.Dir {
			return nil, 0, false
		}
		oh, nh := r.header(), nr.header()
		diff := -1
		for i := range oh {
			if oh[i] != nh[i] {
				if diff >= 0 {
					return nil, 0, false
				}
				diff = i
			}
		}
		if diff < 0 || (idx >= 0 && diff != idx) || headerFields[diff] == "" {
			return nil, 0, false
		}
		idx = diff
		for _, t := range oh[:idx] {
			if strings.ContainsAny(t, " \t") {
				return nil, 0, false
			}
		}
	}
	// One line per original value, in first-seen order.
	var order []string
	newVal := map[string]string{}
	for _, r := range matched {
		ov, nv := r.header()[idx], changed[r].header()[idx]
		if w, ok := newVal[ov]; ok {
			if w != nv {
				return nil, 0, false
			}
			continue
		}
		newVal[ov] = nv
		order = append(order, ov)
	}
	for _, ov := range order {
		pattern := "^" + strings.Repeat(`\S+ `, idx) + regexp.QuoteMeta(ov) + " .*(?:" + m.re.String() + ")"
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, 0, false
		}
		for _, r := range rs.list {
			_, ch := changed[r]
			want := ch && r.header()[idx] == ov
			switch got := re.MatchString(r.text()); {
			case got == want:
			case r.Disabled && got:
				extra++ // Fleet Manager changes a disabled rule Corelight-update skips
			default:
				return nil, 0, false
			}
		}
		lines = append(lines, fmt.Sprintf("re:/%s/ %s:%s", escapeSlashes(pattern), headerKey[headerFields[idx]], quoteValue(newVal[ov])))
	}
	return lines, extra, true
}

func quoteValue(v string) string {
	if strings.ContainsAny(v, " \t") {
		return `"` + v + `"`
	}
	return v
}

// cuChange applies a Corelight-update option change the way
// Corelight-update does (values lose their quotes and a trailing ';').
func cuChange(opts, key, value string) string {
	v := strings.TrimSuffix(trimQuotes(value), ";")
	switch key {
	case "msg":
		return setOption(opts, "msg", `msg:"`+v+`";`)
	case "metadataappend":
		if old, ok := optionValue(opts, "metadata"); ok && old != "" {
			return setOption(opts, "metadata", "metadata:"+old+", "+v+";")
		}
		return setOption(opts, "metadata", "metadata:"+v+";")
	case "otherappend":
		return insertDetection(opts, withSemicolon(v))
	case "flowbitsnoalert":
		return toggleOption(opts, "flowbits:noalert;", v != "false")
	case "noalert":
		return toggleOption(opts, "noalert;", v != "false")
	}
	return setOption(opts, key, key+":"+v+";")
}

// toggleOption adds an exact option (before the trailer) or removes it.
func toggleOption(opts, text string, on bool) string {
	inner, spans := splitOptions(opts)
	for _, s := range spans {
		if strings.TrimSpace(inner[s.start:s.end]) == text {
			if on {
				return opts
			}
			return "(" + strings.TrimSpace(inner[:s.start]+strings.TrimLeft(inner[s.end:], " ")) + ")"
		}
	}
	if !on {
		return opts
	}
	return insertDetection(opts, text)
}

// loadRuleText gets the rules a conversion needs, as they are before the
// file applies. Fleet Manager's rules API gives the policy's rules after
// its current configuration files; rules those may have changed are read
// again from their file source. The rest (URL sources) are unresolved
// unless rules_file has them.
func (p *Plan) loadRuleText(ctx context.Context, api API, current []byte) (*ruleSet, error) {
	rs, err := p.fetchOriginalRules(ctx, api, current)
	if err != nil || p.req.RulesFile == "" {
		return rs, err
	}
	b, fi, err := readLocal(p.req.RulesFile)
	if err != nil {
		return nil, fmt.Errorf("rules_file: %w", err)
	}
	given := newRuleSet("")
	if parseRuleFile(b, filepath.Base(fi.Path), given) == 0 {
		return nil, fmt.Errorf("rules_file %s has no Suricata rules", fi.Path)
	}
	p.state = append(p.state, "rules="+fi.SHA256)
	used := 0
	for sid := range rs.unresolved {
		if o, ok := given.bySID[sid]; ok {
			r := rs.bySID[sid]
			file := r.File
			*r = *o
			r.File = file
			delete(rs.unresolved, sid)
			used++
		}
	}
	rs.from += fmt.Sprintf("; %d rule(s) from rules_file %s", used, fi.Path)
	return rs, nil
}

func (p *Plan) fetchOriginalRules(ctx context.Context, api API, current []byte) (*ruleSet, error) {
	spID := idOf(p.suricata["id"])
	rs, err := fetchRules(ctx, api, spID)
	if err != nil {
		return nil, err
	}
	rs.from = fmt.Sprintf("Fleet Manager's rules for Suricata policy %q", str(p.suricata["name"]))
	touched := touchedRules(rs, current)
	if p.suricata["useModifierFiles"] != true {
		// The rules manager's per-rule modifiers stop applying once the
		// policy uses configuration files.
		var mods []modifier
		if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d/modifiers", pathSuricata, spID), nil, &mods); err != nil {
			return nil, fmt.Errorf("listing rule modifiers: %w", err)
		}
		for _, m := range mods {
			if m.Action == "modify" && strings.EqualFold(m.Match.Key, "sid") {
				touched[m.Match.Value] = true
			}
		}
	}
	if len(touched) == 0 {
		return rs, nil
	}
	rs.from += " (rules the current modify.conf changes read from their file sources)"
	files := map[string]int64{}
	for _, s := range listOf(p.suricata["sources"]) {
		src := obj(s)
		if str(src["entityType"]) == "file" && idOf(src["fileId"]) > 0 {
			files[str(src["filename"])] = idOf(src["fileId"])
		}
	}
	byFile := map[string][]*rule{}
	for _, r := range rs.list {
		if touched[r.SID] {
			byFile[r.File] = append(byFile[r.File], r)
		}
	}
	for file, rules := range byFile {
		orig := newRuleSet("")
		if fid := files[file]; fid > 0 {
			b, err := download(ctx, api, fid)
			if err != nil {
				return nil, err
			}
			parseRuleFile(b, file, orig)
		}
		for _, r := range rules {
			if o, ok := orig.bySID[r.SID]; ok {
				*r = *o
				r.File = file
			} else {
				rs.unresolved[r.SID] = true
			}
		}
	}
	return rs, nil
}

// touchedRules returns the SIDs the current modify.conf may have changed:
// rules its matches select now, and rules that already carry a value it
// sets (a rule it changed may no longer match).
func touchedRules(rs *ruleSet, current []byte) map[string]bool {
	out := map[string]bool{}
	for i, raw := range strings.Split(string(stripFMPrefix(current)), "\n") {
		ml := parseModLine(SuricataModify, i+1, raw)
		if ml == nil {
			continue
		}
		m, err := compileMatch(ml.match)
		if err != nil {
			continue
		}
		v := trimQuotes(ml.value)
		for _, r := range rs.list {
			if m.matches(r) {
				out[r.SID] = true
				continue
			}
			switch {
			case m.unknown:
				out[r.SID] = true
			case ml.key == "ruleoptions":
				if r.Opts == strings.TrimSpace(ml.value) {
					out[r.SID] = true
				}
			case r.field(ml.key) != nil:
				if *r.field(ml.key) == v {
					out[r.SID] = true
				}
			}
		}
	}
	return out
}

// convertedPath is where the converted file is written: next to the
// user's file, with .fm before the extension (modify.conf → modify.fm.conf).
func convertedPath(path string) string {
	ext := filepath.Ext(path)
	return strings.TrimSuffix(path, ext) + ".fm" + ext
}

// planConversion looks for Corelight-update syntax in a configuration file
// and, when there is some, previews or applies the user's answer. current
// is the modify.conf Fleet Manager applies now (nil if none).
func (p *Plan) planConversion(ctx context.Context, api API, current []byte) error {
	count, needText := 0, false
	for i, raw := range strings.Split(string(p.content), "\n") {
		if ml := parseModLine(p.Kind, i+1, raw); ml != nil && ml.cu() {
			count++
			needText = needText || ml.needsText()
		}
	}
	if count == 0 {
		return nil
	}
	answer := strings.ToLower(strings.TrimSpace(p.req.CUModifiers))
	if answer != "" && answer != CUConvert && answer != CUCommentOut {
		return fmt.Errorf("cu_modifiers must be %q or %q", CUConvert, CUCommentOut)
	}
	conv := &Conversion{Answer: answer, Count: count}
	p.Conversion = conv
	// Reading every rule of the policy is slow (minutes for ET Pro), so it
	// happens only once the user has chosen convert.
	var rs *ruleSet
	if needText && answer == CUConvert {
		var err error
		if rs, err = p.loadRuleText(ctx, api, current); err != nil {
			return err
		}
		conv.RuleText = rs.from
	}
	out := convertModifier(p.Kind, p.content, answer, rs)
	conv.Lines, conv.FrozenSIDs, conv.NeedRulesFile = out.lines, out.frozen, out.needRulesFile
	p.Notes = append(p.Notes, out.notes...)
	p.Warnings = append(p.Warnings, out.warns...)
	if len(out.frozen) > 0 {
		p.warn("%d rule(s) get a RuleOptions line with their whole option text (frozen_sids): when the rule source updates them (a new rev), the old text stays until the file is converted again", len(out.frozen))
	}
	if len(out.needRulesFile) > 0 {
		p.warn("line(s) %s change rules whose original text fleet-mcp could not read (the current modify.conf changes them and they come from a URL source); they are commented out unless rules_file gives the source rules", joinInts(out.needRulesFile))
	}
	outPath := convertedPath(p.File.Path)
	if answer == "" {
		p.Decisions = append(p.Decisions, Decision{
			ID: "cu_modifiers",
			Question: fmt.Sprintf("%d line(s) of %s use Corelight-update syntax that Fleet Manager rejects (it refuses the whole file) or silently ignores; conversion.lines lists them. Convert them, comment them out, or stop? (Converting option changes and regex rewrites reads every rule of the Suricata policy, which can take a few minutes; the convert preview then shows the result before anything is pushed.)",
				count, p.fileNm),
			Resolve: map[string]string{
				CUConvert:    fmt.Sprintf(`preview again with cu_modifiers: "convert": fleet-mcp writes %s (each converted line keeps the original as a comment) and pushes it; %s is not changed`, outPath, p.fileNm),
				CUCommentOut: fmt.Sprintf(`preview again with cu_modifiers: "comment_out": those lines are commented out in %s, which is pushed`, outPath),
				"stop":       "do not push; edit the file by hand",
			},
		})
		return nil
	}
	if err := os.WriteFile(outPath, out.text, 0o644); err != nil {
		p.block("writing the converted file %s: %v", outPath, err)
		return nil
	}
	conv.Output, conv.OutputSHA256 = outPath, sha256Hex(out.text)
	p.content = out.text
	p.state = append(p.state, "cu="+answer, "conv="+conv.OutputSHA256)
	p.note("pushing the converted file %s; Fleet Manager stores it as %s", outPath, modifierFile[p.Kind])
	return nil
}

func joinInts(n []int) string {
	s := make([]string, len(n))
	for i, v := range n {
		s[i] = fmt.Sprint(v)
	}
	return strings.Join(sample(s, 10), ", ")
}
