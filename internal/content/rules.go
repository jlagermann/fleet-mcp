package content

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// rule is one Suricata rule split the way Fleet Manager's rules API does:
// the header fields and the option text in parentheses.
type rule struct {
	Action, Proto, Src, SrcPort, Dir, Dst, DstPort string
	Opts                                           string // "(msg:...; sid:1;)"
	SID                                            string
	File                                           string // the rule file it came from
	Disabled                                       bool
}

// text is the rule as one line, the text Fleet Manager tries a re: match
// against (enabled or not).
func (r *rule) text() string {
	return strings.Join([]string{r.Action, r.Proto, r.Src, r.SrcPort, r.Dir, r.Dst, r.DstPort, r.Opts}, " ")
}

// cuText is the text Corelight-update tries a regex against: a disabled
// rule starts with "#", so a regex anchored at "^alert" skips it.
func (r *rule) cuText() string {
	if r.Disabled {
		return "#" + r.text()
	}
	return r.text()
}

// headerFields are the header fields in rule order, by modifier key; the
// direction has no key.
var headerFields = []string{"action", "protocol", "srcaddress", "srcport", "", "destaddress", "destport"}

// headerKey is the modify.conf spelling of each header field.
var headerKey = map[string]string{"action": "Action", "protocol": "Protocol", "srcaddress": "SrcAddress", "srcport": "SrcPort",
	"destaddress": "DestAddress", "destport": "DestPort"}

func (r *rule) field(key string) *string {
	switch strings.ToLower(key) {
	case "action":
		return &r.Action
	case "protocol":
		return &r.Proto
	case "srcaddress":
		return &r.Src
	case "srcport":
		return &r.SrcPort
	case "destaddress":
		return &r.Dst
	case "destport":
		return &r.DstPort
	}
	return nil
}

func (r *rule) header() []string {
	return []string{r.Action, r.Proto, r.Src, r.SrcPort, r.Dir, r.Dst, r.DstPort}
}

var (
	ruleActions = map[string]bool{"alert": true, "pass": true, "drop": true, "reject": true, "rejectsrc": true, "rejectdst": true, "rejectboth": true}
	sidOption   = regexp.MustCompile(`(?:^|[(;\s])sid\s*:\s*(\d+)\s*;`)
)

// parseRule splits a rule line. A disabled rule ("# alert ...") parses too.
func parseRule(line string) (*rule, bool) {
	s := strings.TrimSpace(line)
	disabled := strings.HasPrefix(s, "#")
	s = strings.TrimSpace(strings.TrimLeft(s, "#"))
	var tok []string
	i := 0
	for len(tok) < 7 && i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		start, depth := i, 0
		for i < len(s) && (depth > 0 || s[i] != ' ') {
			switch s[i] {
			case '[':
				depth++
			case ']':
				depth--
			}
			i++
		}
		if i > start {
			tok = append(tok, s[start:i])
		}
	}
	opts := strings.TrimSpace(s[min(i, len(s)):])
	if len(tok) != 7 || !ruleActions[tok[0]] || !strings.HasPrefix(opts, "(") || !strings.HasSuffix(opts, ")") {
		return nil, false
	}
	r := &rule{Action: tok[0], Proto: tok[1], Src: tok[2], SrcPort: tok[3], Dir: tok[4], Dst: tok[5], DstPort: tok[6], Opts: opts, Disabled: disabled}
	if m := sidOption.FindStringSubmatch(opts); m != nil {
		r.SID = m[1]
	}
	return r, r.SID != ""
}

// optSpan is one option inside the parentheses: [start,end) covers
// "key:value;" in the inner text.
type optSpan struct {
	key        string
	start, end int
}

// splitOptions finds the options of an option text. A ';' inside quotes or
// after a backslash does not end an option.
func splitOptions(opts string) (inner string, spans []optSpan) {
	inner = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(opts), "("), ")")
	i := 0
	for i < len(inner) {
		for i < len(inner) && inner[i] == ' ' {
			i++
		}
		if i >= len(inner) {
			break
		}
		start, quoted := i, false
		for i < len(inner) {
			c := inner[i]
			if c == '\\' {
				i += 2
				continue
			}
			if c == '"' {
				quoted = !quoted
			}
			i++
			if c == ';' && !quoted {
				break
			}
		}
		end := min(i, len(inner))
		body := strings.TrimSuffix(inner[start:end], ";")
		key, _, _ := strings.Cut(body, ":")
		spans = append(spans, optSpan{key: strings.ToLower(strings.TrimSpace(key)), start: start, end: end})
	}
	return inner, spans
}

// optionValue returns the value of the first option with key.
func optionValue(opts, key string) (string, bool) {
	inner, spans := splitOptions(opts)
	for _, s := range spans {
		if s.key == key {
			body := strings.TrimSuffix(inner[s.start:s.end], ";")
			_, v, _ := strings.Cut(body, ":")
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

// trailerOptions are the options Corelight-update writes after a rule's
// detection options; a new one goes before sid, an appended detection
// option before the first of these.
var trailerOptions = map[string]bool{"metadata": true, "classtype": true, "sid": true, "rev": true, "gid": true, "priority": true, "target": true}

// setOption replaces the first option with key, or adds it before sid.
// An empty text removes the option.
func setOption(opts, key, text string) string {
	inner, spans := splitOptions(opts)
	for _, s := range spans {
		if s.key == key {
			if text == "" {
				return "(" + strings.TrimSpace(inner[:s.start]+strings.TrimLeft(inner[s.end:], " ")) + ")"
			}
			return "(" + inner[:s.start] + text + inner[s.end:] + ")"
		}
	}
	if text == "" {
		return opts
	}
	for _, s := range spans {
		if s.key == "sid" {
			return "(" + inner[:s.start] + text + " " + inner[s.start:] + ")"
		}
	}
	return "(" + appendOpt(inner, text) + ")"
}

// insertDetection adds option text after the last detection option, where
// Corelight-update's OtherAppend puts it.
func insertDetection(opts, text string) string {
	inner, spans := splitOptions(opts)
	at := -1
	for _, s := range spans {
		if !trailerOptions[s.key] && s.key != "msg" {
			at = s.end
		}
	}
	if at < 0 {
		for _, s := range spans {
			if trailerOptions[s.key] {
				return "(" + inner[:s.start] + text + " " + inner[s.start:] + ")"
			}
		}
		return "(" + appendOpt(inner, text) + ")"
	}
	return "(" + inner[:at] + " " + text + inner[at:] + ")"
}

func appendOpt(inner, text string) string {
	inner = strings.TrimRight(inner, " ")
	if inner != "" && !strings.HasSuffix(inner, ";") {
		inner += ";"
	}
	if inner == "" {
		return text
	}
	return inner + " " + text
}

// withSemicolon ends option text with ';'.
func withSemicolon(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, ";") {
		s += ";"
	}
	return s
}

// matcher decides which rules a modifier line's match selects.
type matcher struct {
	all      bool
	sids     map[string]bool
	re       *regexp.Regexp
	field    string // header field key or "classtype"
	value    string
	metadata string // Metadata: contains
	// unknown is set for match keys fleet-mcp cannot evaluate (Fleet
	// Manager's msg, filename, group, ...).
	unknown bool
	// cu tries a regex the way Corelight-update does (cuText).
	cu bool
}

func (m *matcher) matches(r *rule) bool {
	switch {
	case m.unknown:
		return false
	case m.all:
		return true
	case m.sids != nil:
		return m.sids[r.SID]
	case m.re != nil:
		if m.cu {
			return m.re.MatchString(r.cuText())
		}
		return m.re.MatchString(r.text())
	case m.metadata != "":
		v, _ := optionValue(r.Opts, "metadata")
		return strings.Contains(v, m.metadata)
	case m.field == "classtype":
		v, _ := optionValue(r.Opts, "classtype")
		return v == m.value
	case m.field != "":
		if p := r.field(m.field); p != nil {
			return *p == m.value
		}
	}
	return false
}

// compileMatch reads a match in Corelight-update or Fleet Manager syntax.
func compileMatch(match string) (*matcher, error) {
	match = strings.TrimSpace(match)
	if match == "*" {
		return &matcher{all: true}, nil
	}
	if sids, ok := sidList(match); ok {
		m := &matcher{sids: map[string]bool{}}
		for _, s := range sids {
			m.sids[s] = true
		}
		return m, nil
	}
	key, val, ok := strings.Cut(match, ":")
	if !ok {
		return nil, fmt.Errorf("no match key in %q", match)
	}
	key = strings.ToLower(strings.TrimSpace(key))
	switch key {
	case "re":
		re, err := regexp.Compile(regexOf(val))
		if err != nil {
			return nil, fmt.Errorf("regex %q: %w", val, err)
		}
		return &matcher{re: re}, nil
	case "sid":
		if sids, ok := sidList(trimQuotes(val)); ok {
			m := &matcher{sids: map[string]bool{}}
			for _, s := range sids {
				m.sids[s] = true
			}
			return m, nil
		}
		return nil, fmt.Errorf("bad SID %q", val)
	case "metadata":
		return &matcher{metadata: trimQuotes(val)}, nil
	case "classtype", "action", "protocol", "srcaddress", "srcport", "destaddress", "destport":
		return &matcher{field: key, value: strings.TrimSuffix(trimQuotes(val), ";")}, nil
	}
	return &matcher{unknown: true}, nil
}

// regexOf returns the regex of a re: match: /.../, "..." or bare.
func regexOf(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && strings.HasPrefix(v, "/") && strings.HasSuffix(v, "/") {
		return v[1 : len(v)-1]
	}
	return trimQuotes(v)
}

var sidItem = regexp.MustCompile(`^(?:(\d+):)?(\d+)$`)

// sidList reads "sid", "gid:sid" or a comma list of them, returning the
// SIDs (the GIDs are dropped).
func sidList(s string) ([]string, bool) {
	var out []string
	for _, part := range strings.Split(s, ",") {
		m := sidItem.FindStringSubmatch(strings.TrimSpace(part))
		if m == nil {
			return nil, false
		}
		out = append(out, m[2])
	}
	return out, len(out) > 0
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// ruleSet is the rules a conversion works on, in Fleet Manager's order.
type ruleSet struct {
	list  []*rule
	bySID map[string]*rule
	// unresolved holds SIDs whose original text is unknown: the current
	// modify.conf changes them and their source is not a downloadable file.
	unresolved map[string]bool
	from       string // where the text came from, for the preview
}

func newRuleSet(from string) *ruleSet {
	return &ruleSet{bySID: map[string]*rule{}, unresolved: map[string]bool{}, from: from}
}

func (rs *ruleSet) add(r *rule) {
	if old, ok := rs.bySID[r.SID]; ok {
		*old = *r
		return
	}
	rs.list = append(rs.list, r)
	rs.bySID[r.SID] = r
}

// parseRuleFile reads every rule of a rules file.
func parseRuleFile(b []byte, file string, rs *ruleSet) int {
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if r, ok := parseRule(line); ok {
			r.File = file
			rs.add(r)
			n++
		}
	}
	return n
}

// rulesPageSize is how many rules one rules-API page asks for.
var rulesPageSize = 5000

// fetchRules reads every rule of a Suricata policy from the rules API, as
// Fleet Manager has them now (after its current configuration files).
func fetchRules(ctx context.Context, api API, spID int64) (*ruleSet, error) {
	rs := newRuleSet("")
	for page := 0; ; page++ {
		var out struct {
			Items          []map[string]any `json:"items"`
			TotalPageCount int              `json:"totalPageCount"`
		}
		q := url.Values{"pageSize": {strconv.Itoa(rulesPageSize)}, "pageIndex": {strconv.Itoa(page)}}
		if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d/rules", pathSuricata, spID), q, &out); err != nil {
			return nil, fmt.Errorf("reading the rules of Suricata policy %d: %w", spID, err)
		}
		for _, it := range out.Items {
			r := &rule{Action: str(it["action"]), Proto: str(it["protocol"]), Src: str(it["srcAddress"]), SrcPort: str(it["srcPort"]),
				Dir: str(it["direction"]), Dst: str(it["destAddress"]), DstPort: str(it["destPort"]), Opts: str(it["rawOptions"]),
				SID: str(it["sid"]), File: str(it["filename"]), Disabled: it["disabled"] == true}
			if r.Dir == "" {
				r.Dir = "->"
			}
			if r.SID != "" {
				rs.add(r)
			}
		}
		if len(out.Items) == 0 || page+1 >= out.TotalPageCount {
			return rs, nil
		}
	}
}
