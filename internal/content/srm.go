package content

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
)

// Per-rule changes in Fleet Manager's Suricata rules manager (the
// "Recommended" mode of a Suricata policy with automation). Each change is
// a modifier: disable, enable or modify the rules a match selects.

// RuleChange is one per-rule change.
type RuleChange struct {
	SID         string `json:"sid,omitempty" jsonschema:"SID of the rule to change (shorthand for match_key sid)"`
	MatchKey    string `json:"match_key,omitempty" jsonschema:"match on another rule attribute instead of sid: re (match_value /regex/), classtype, msg, metadata, action, protocol, srcaddress, srcport, destaddress, destport, gid, rev, priority, reference, target, group or filename"`
	MatchValue  string `json:"match_value,omitempty" jsonschema:"value for match_key"`
	Action      string `json:"action" jsonschema:"disable, enable or modify"`
	ChangeKey   string `json:"change_key,omitempty" jsonschema:"modify only: action, srcaddress, srcport, destaddress, destport, protocol or ruleoptions (the whole rule option text in parentheses)"`
	ChangeValue string `json:"change_value,omitempty" jsonschema:"modify only: the new value"`
	Comment     string `json:"comment,omitempty" jsonschema:"why (kept with the modifier in Fleet Manager); default fleet-mcp"`
}

// SRMRequest is a set of rules-manager changes to one Suricata policy.
type SRMRequest struct {
	SuricataPolicy string       `json:"suricata_policy,omitempty" jsonschema:"Suricata policy id or exact name"`
	Policy         string       `json:"policy,omitempty" jsonschema:"sensor policy id or name, to use its Suricata policy when suricata_policy is not given"`
	Changes        []RuleChange `json:"changes,omitempty" jsonschema:"changes to add (an existing modifier for the same match is replaced or updated)"`
	Remove         []string     `json:"remove,omitempty" jsonschema:"modifiers to remove: a modifier id, or sid:<n> for every modifier matching that SID (the rule goes back to its state in the rule sources)"`
}

// modifier is Fleet Manager's representation of one change.
type modifier struct {
	ID      int64  `json:"id,omitempty"`
	Action  string `json:"action"`
	Match   kv     `json:"match"`
	Change  kv     `json:"change"`
	Comment string `json:"comment"`
}

type kv struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// RuleState is a rule's effective state in the rules manager.
type RuleState struct {
	SID      string `json:"sid"`
	Message  string `json:"msg"`
	Enabled  bool   `json:"enabled"`
	Action   string `json:"action"`
	Protocol string `json:"protocol"`
	Src      string `json:"src"`
	SrcPort  string `json:"src_port"`
	Dst      string `json:"dst"`
	DstPort  string `json:"dst_port"`
	Options  string `json:"options,omitempty"`
}

// SRMPlan is what a rules-manager change will do; the exported fields are
// the preview.
type SRMPlan struct {
	SuricataPolicy PolicyRef            `json:"suricata_policy"`
	Add            []modifier           `json:"add,omitempty"`
	Update         []modifier           `json:"update,omitempty"`
	Remove         []modifier           `json:"remove,omitempty"`
	Unchanged      []string             `json:"already_in_place,omitempty"`
	Rules          map[string]RuleState `json:"rules_now,omitempty"`
	Expected       map[string]string    `json:"expected_after,omitempty"`
	Validation     []string             `json:"validation,omitempty"`
	UsedBy         []string             `json:"used_by_sensor_policies,omitempty"`
	Steps          []string             `json:"steps"`
	Notes          []string             `json:"notes,omitempty"`
	Warnings       []string             `json:"warnings,omitempty"`
	Blockers       []string             `json:"blockers,omitempty"`

	expect map[string]func(RuleState) bool
	sids   []string
	state  []string
}

// Ready reports whether there is something to do and nothing blocks it.
func (p *SRMPlan) Ready() bool {
	return len(p.Blockers) == 0 && len(p.Add)+len(p.Update)+len(p.Remove) > 0
}

// State is what the plan was built from, for the confirm token.
func (p *SRMPlan) State() []string { return p.state }

var srmChangeKeys = map[string]string{"action": "action", "srcaddress": "srcAddress", "srcport": "srcPort",
	"destaddress": "destAddress", "destport": "destPort", "protocol": "protocol", "ruleoptions": ""}

// PrepareSRM builds the plan for rules-manager changes. It reads Fleet
// Manager and asks it to validate the new modifiers; it changes nothing.
func PrepareSRM(ctx context.Context, api API, req SRMRequest) (*SRMPlan, error) {
	if len(req.Changes) == 0 && len(req.Remove) == 0 {
		return nil, fmt.Errorf("give changes or remove")
	}
	tmp := &Plan{req: Request{Kind: SuricataRules, SuricataPolicy: req.SuricataPolicy, Policy: req.Policy}}
	if err := tmp.resolveSuricata(ctx, api); err != nil {
		return nil, err
	}
	sp := tmp.suricata
	id := idOf(sp["id"])
	p := &SRMPlan{SuricataPolicy: PolicyRef{ID: id, Name: str(sp["name"])}, UsedBy: tmp.UsedBy, Warnings: tmp.Warnings,
		Expected: map[string]string{}, expect: map[string]func(RuleState) bool{}}
	if sp["rulesAutomation"] != true {
		p.Blockers = append(p.Blockers, fmt.Sprintf("Suricata policy %q does not use Suricata automation; rules-manager changes apply only when Fleet Manager builds the ruleset from rule sources", p.SuricataPolicy.Name))
	}
	if sp["useModifierFiles"] == true {
		p.Blockers = append(p.Blockers, fmt.Sprintf("Suricata policy %q uses configuration files (disable.conf, enable.conf, modify.conf), so rules-manager changes do not apply; push those files with fm_content_push (suricata_disable, suricata_enable, suricata_modify) instead", p.SuricataPolicy.Name))
	}

	var existing []modifier
	if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d/modifiers", pathSuricata, id), nil, &existing); err != nil {
		return nil, fmt.Errorf("listing rule modifiers: %w", err)
	}
	removed := map[int64]bool{}
	removeMod := func(m modifier, why string) {
		if !removed[m.ID] {
			removed[m.ID] = true
			p.Remove = append(p.Remove, m)
			p.Steps = append(p.Steps, fmt.Sprintf("remove modifier %d (%s %s:%s%s): %s", m.ID, m.Action, m.Match.Key, m.Match.Value, describeChange(m.Change), why))
		}
	}
	sidSet := map[string]bool{}

	for _, r := range req.Remove {
		r = strings.TrimSpace(r)
		if sid, ok := strings.CutPrefix(strings.ToLower(r), "sid:"); ok {
			n := 0
			for _, m := range existing {
				if strings.EqualFold(m.Match.Key, "sid") && m.Match.Value == sid {
					removeMod(m, "requested")
					n++
				}
			}
			sidSet[sid] = true
			if n == 0 {
				p.Warnings = append(p.Warnings, fmt.Sprintf("no modifier matches SID %s", sid))
			}
			continue
		}
		mid, err := strconv.ParseInt(r, 10, 64)
		found := false
		for _, m := range existing {
			if err == nil && m.ID == mid {
				removeMod(m, "requested")
				if strings.EqualFold(m.Match.Key, "sid") {
					sidSet[m.Match.Value] = true
				}
				found = true
			}
		}
		if !found {
			p.Blockers = append(p.Blockers, fmt.Sprintf("no modifier %q on Suricata policy %q (remove takes a modifier id or sid:<n>)", r, p.SuricataPolicy.Name))
		}
	}

	var toValidate []modifier
	for i, c := range req.Changes {
		m, err := normalizeChange(c)
		if err != nil {
			p.Blockers = append(p.Blockers, fmt.Sprintf("change %d: %v", i+1, err))
			continue
		}
		if strings.EqualFold(m.Match.Key, "sid") {
			sidSet[m.Match.Value] = true
		}
		// Within this request: a repeat is skipped, a contradiction blocks.
		dup, clash := false, ""
		for _, x := range append(append([]modifier{}, p.Add...), p.Update...) {
			if !strings.EqualFold(x.Match.Key, m.Match.Key) || x.Match.Value != m.Match.Value {
				continue
			}
			switch {
			case x.Action == m.Action && strings.EqualFold(x.Change.Key, m.Change.Key) && x.Change.Value == m.Change.Value:
				dup = true
			case x.Action != "modify" && m.Action != "modify":
				clash = fmt.Sprintf("both %s and %s", x.Action, m.Action)
			case x.Action == "modify" && m.Action == "modify" && strings.EqualFold(x.Change.Key, m.Change.Key):
				clash = fmt.Sprintf("two values for %s", m.Change.Key)
			}
		}
		if clash != "" {
			p.Blockers = append(p.Blockers, fmt.Sprintf("change %d: %s requested for %s:%s", i+1, clash, m.Match.Key, m.Match.Value))
			continue
		}
		if dup {
			p.Notes = append(p.Notes, fmt.Sprintf("change %d repeats an earlier change and is skipped", i+1))
			continue
		}
		same := func(x modifier) bool {
			return strings.EqualFold(x.Match.Key, m.Match.Key) && x.Match.Value == m.Match.Value && !removed[x.ID]
		}
		handled := false
		for _, x := range existing {
			if !same(x) {
				continue
			}
			switch {
			case m.Action != "modify" && x.Action == m.Action:
				p.Unchanged = append(p.Unchanged, fmt.Sprintf("%s %s:%s (modifier %d)", m.Action, m.Match.Key, m.Match.Value, x.ID))
				handled = true
			case m.Action != "modify" && x.Action != "modify":
				removeMod(x, fmt.Sprintf("replaced by %s", m.Action))
			case m.Action == "modify" && x.Action == "modify" && strings.EqualFold(x.Change.Key, m.Change.Key):
				if x.Change.Value == m.Change.Value {
					p.Unchanged = append(p.Unchanged, fmt.Sprintf("modify %s:%s%s (modifier %d)", m.Match.Key, m.Match.Value, describeChange(m.Change), x.ID))
				} else {
					u := m
					u.ID = x.ID
					p.Update = append(p.Update, u)
					toValidate = append(toValidate, u)
					p.Steps = append(p.Steps, fmt.Sprintf("update modifier %d: %s:%s %s %q -> %q", x.ID, m.Match.Key, m.Match.Value, m.Change.Key, x.Change.Value, m.Change.Value))
				}
				handled = true
			}
			if handled {
				break
			}
		}
		if handled {
			p.planExpect(m)
			continue
		}
		p.Add = append(p.Add, m)
		toValidate = append(toValidate, m)
		p.Steps = append(p.Steps, fmt.Sprintf("add modifier: %s %s:%s%s (%s)", m.Action, m.Match.Key, m.Match.Value, describeChange(m.Change), m.Comment))
		p.planExpect(m)
	}

	if len(toValidate) > 0 {
		p.validate(ctx, api, toValidate)
	}
	for s := range sidSet {
		p.sids = append(p.sids, s)
	}
	sort.Strings(p.sids)
	if len(p.sids) > 0 {
		rules, err := rulesBySID(ctx, api, id, p.sids)
		if err != nil {
			return nil, err
		}
		p.Rules = rules
		for _, s := range p.sids {
			if _, ok := rules[s]; !ok {
				p.Warnings = append(p.Warnings, fmt.Sprintf("no rule with SID %s in the policy's rule sources; the modifier matches nothing until one arrives", s))
			}
		}
	}
	if len(p.Add)+len(p.Update)+len(p.Remove) > 0 {
		p.Steps = append(p.Steps, "Fleet Manager rebuilds the policy's ruleset and sends it to the sensors of the policies that use it")
	}
	if cfg := obj(sp["config"]); cfg["srmEnableFlowBits"] == true {
		p.Notes = append(p.Notes, "\"Enable flowbit dependencies\" is on: Fleet Manager re-enables a disabled rule that sets a flowbit an enabled rule checks, so disabling such a setter may not stick")
	}
	b, _ := json.Marshal(existing)
	p.state = append(p.state, strconv.FormatInt(id, 10), sha256Hex(b))
	return p, nil
}

func describeChange(c kv) string {
	if c.Key == "" {
		return ""
	}
	return fmt.Sprintf(" -> %s:%s", c.Key, clip(c.Value))
}

// normalizeChange turns a RuleChange into Fleet Manager's modifier form.
func normalizeChange(c RuleChange) (modifier, error) {
	m := modifier{Action: strings.ToLower(strings.TrimSpace(c.Action)), Comment: strings.TrimSpace(c.Comment)}
	if m.Comment == "" {
		m.Comment = DefaultSource
	}
	switch {
	case c.SID != "" && c.MatchKey == "":
		m.Match = kv{"sid", strings.TrimSpace(c.SID)}
	case c.MatchKey != "" && c.SID == "":
		m.Match = kv{strings.ToLower(strings.TrimSpace(c.MatchKey)), strings.TrimSpace(c.MatchValue)}
	default:
		return m, fmt.Errorf("give either sid or match_key with match_value")
	}
	if m.Match.Value == "" {
		return m, fmt.Errorf("the match has no value")
	}
	if m.Match.Key == "sid" {
		if _, err := strconv.ParseUint(m.Match.Value, 10, 64); err != nil {
			return m, fmt.Errorf("sid %q is not a number", m.Match.Value)
		}
	}
	if m.Match.Key == "re" && !(strings.HasPrefix(m.Match.Value, "/") && strings.HasSuffix(m.Match.Value, "/") && len(m.Match.Value) > 2) {
		return m, fmt.Errorf("a regex match value must be enclosed in slashes, e.g. /deployment SSLDecrypt/")
	}
	switch m.Action {
	case "disable", "enable":
		if c.ChangeKey != "" || c.ChangeValue != "" {
			return m, fmt.Errorf("%s takes no change_key or change_value", m.Action)
		}
		m.Change = kv{}
	case "modify":
		k := strings.ToLower(strings.TrimSpace(c.ChangeKey))
		if _, ok := srmChangeKeys[k]; !ok {
			return m, fmt.Errorf("change_key %q is not supported (action, srcaddress, srcport, destaddress, destport, protocol, ruleoptions)", c.ChangeKey)
		}
		if strings.TrimSpace(c.ChangeValue) == "" {
			return m, fmt.Errorf("modify needs change_value")
		}
		m.Change = kv{k, strings.TrimSpace(c.ChangeValue)}
	default:
		return m, fmt.Errorf("action must be disable, enable or modify")
	}
	return m, nil
}

// planExpect records what a SID-matched change should look like after the
// rebuild, for the preview and the verification.
func (p *SRMPlan) planExpect(m modifier) {
	if m.Match.Key != "sid" {
		return
	}
	sid := m.Match.Value
	switch m.Action {
	case "disable":
		p.Expected[sid] = "disabled"
		p.expect[sid+"|enabled"] = func(r RuleState) bool { return !r.Enabled }
	case "enable":
		p.Expected[sid] = "enabled"
		p.expect[sid+"|enabled"] = func(r RuleState) bool { return r.Enabled }
	case "modify":
		key, want := m.Change.Key, m.Change.Value
		p.Expected[sid+" "+key] = clip(want)
		p.expect[sid+"|"+key] = func(r RuleState) bool {
			switch key {
			case "action":
				return r.Action == want
			case "srcaddress":
				return r.Src == want
			case "srcport":
				return r.SrcPort == want
			case "destaddress":
				return r.Dst == want
			case "destport":
				return r.DstPort == want
			case "protocol":
				return r.Protocol == want
			case "ruleoptions":
				return strings.Join(strings.Fields(r.Options), " ") == strings.Join(strings.Fields(want), " ")
			}
			return true
		}
	}
}

// validate asks Fleet Manager to check the new and updated modifiers.
func (p *SRMPlan) validate(ctx context.Context, api API, mods []modifier) {
	body := make([]modifier, len(mods))
	for i, m := range mods {
		body[i] = m
		body[i].ID = 0
	}
	resp, err := api.Do(ctx, http.MethodPost, pathSuricata+"/validate/modifiers", nil, jsonBody(body), "application/json")
	var msgs []string
	switch {
	case err == nil:
		_ = json.Unmarshal(resp.Body, &msgs)
	default:
		var apiErr *fleet.APIError
		if errors.As(err, &apiErr) {
			_ = json.Unmarshal([]byte(apiErr.Body), &msgs)
		}
		if len(msgs) == 0 {
			p.Blockers = append(p.Blockers, fmt.Sprintf("Fleet Manager rejected the modifiers: %v", err))
			return
		}
	}
	for i, msg := range msgs {
		if msg != "" && i < len(mods) {
			m := mods[i]
			p.Blockers = append(p.Blockers, fmt.Sprintf("%s %s:%s%s: %s", m.Action, m.Match.Key, m.Match.Value, describeChange(m.Change), msg))
		}
	}
	p.Validation = []string{fmt.Sprintf("Fleet Manager checked %d modifier(s): %d problem(s)", len(mods), len(p.Blockers))}
}

// rulesBySID returns the effective state of rules in the rules manager.
func rulesBySID(ctx context.Context, api API, id int64, sids []string) (map[string]RuleState, error) {
	q, _ := json.Marshal(map[string]any{"sid": sids})
	var out struct {
		Items []map[string]any `json:"items"`
	}
	vals := url.Values{"searchParams": {string(q)}, "pageSize": {strconv.Itoa(len(sids) + 10)}}
	if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d/rules", pathSuricata, id), vals, &out); err != nil {
		return nil, fmt.Errorf("reading rules: %w", err)
	}
	rules := map[string]RuleState{}
	for _, it := range out.Items {
		r := RuleState{SID: str(it["sid"]), Message: strings.Trim(str(it["message"]), "\""), Enabled: it["disabled"] != true,
			Action: str(it["action"]), Protocol: str(it["protocol"]), Src: str(it["srcAddress"]), SrcPort: str(it["srcPort"]),
			Dst: str(it["destAddress"]), DstPort: str(it["destPort"]), Options: str(it["rawOptions"])}
		rules[r.SID] = r
	}
	return rules, nil
}

// SRMResult is what a rules-manager change did.
type SRMResult struct {
	Done         []string             `json:"done"`
	RulesAfter   map[string]RuleState `json:"rules_after,omitempty"`
	Verification []string             `json:"verification,omitempty"`
}

// ApplySRM carries out a ready plan: removals first, then updates, then
// additions; it then waits for the rebuild and checks the rules.
func ApplySRM(ctx context.Context, api API, p *SRMPlan) (*SRMResult, error) {
	if !p.Ready() {
		return nil, fmt.Errorf("nothing to do or blocked: %v", p.Blockers)
	}
	res := &SRMResult{}
	path := fmt.Sprintf("%s/%d/modifiers", pathSuricata, p.SuricataPolicy.ID)
	if len(p.Remove) > 0 {
		ids := make([]int64, len(p.Remove))
		for i, m := range p.Remove {
			ids[i] = m.ID
		}
		if _, err := api.Do(ctx, http.MethodDelete, path, nil, jsonBody(map[string]any{"modifications": ids}), "application/json"); err != nil {
			return res, fmt.Errorf("removing modifiers %v: %w", ids, err)
		}
		res.Done = append(res.Done, fmt.Sprintf("removed modifier(s) %v", ids))
	}
	for _, m := range p.Update {
		if _, err := api.Do(ctx, http.MethodPut, path, nil, jsonBody(m), "application/json"); err != nil {
			return res, fmt.Errorf("updating modifier %d: %w", m.ID, err)
		}
		res.Done = append(res.Done, fmt.Sprintf("updated modifier %d", m.ID))
	}
	if len(p.Add) > 0 {
		if _, err := api.Do(ctx, http.MethodPost, path, nil, jsonBody(map[string]any{"modifications": p.Add}), "application/json"); err != nil {
			return res, fmt.Errorf("adding modifiers: %w", err)
		}
		res.Done = append(res.Done, fmt.Sprintf("added %d modifier(s)", len(p.Add)))
	}
	done, problem := WaitRuleset(ctx, api, p.SuricataPolicy.ID)
	if done != "" {
		res.Done = append(res.Done, done)
	}
	if problem != "" {
		res.Verification = append(res.Verification, problem)
	}
	if len(p.sids) > 0 {
		after, err := rulesBySID(ctx, api, p.SuricataPolicy.ID, p.sids)
		if err != nil {
			res.Verification = append(res.Verification, err.Error())
			return res, nil
		}
		res.RulesAfter = after
		keys := make([]string, 0, len(p.expect))
		for k := range p.expect {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sid, what, _ := strings.Cut(k, "|")
			r, ok := after[sid]
			if ok && !p.expect[k](r) {
				res.Verification = append(res.Verification, fmt.Sprintf("SID %s: %s is not as expected after the rebuild (%+v)", sid, what, r))
			}
		}
	}
	return res, nil
}
