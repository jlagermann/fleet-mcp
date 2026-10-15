package content

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Suricata configuration (modifier) file kinds: disable.conf, enable.conf
// and modify.conf of a Suricata policy that uses rules automation with
// "Use configuration files".
const (
	SuricataDisable Kind = "suricata_disable"
	SuricataEnable  Kind = "suricata_enable"
	SuricataModify  Kind = "suricata_modify"
)

var modifierFile = map[Kind]string{SuricataDisable: "disable.conf", SuricataEnable: "enable.conf", SuricataModify: "modify.conf"}

const modifierStore = "suricata-configuration-files"

// rulesetSettle is how long to wait before the first ruleset status check.
var rulesetSettle = 3 * time.Second

// Keys Fleet Manager's rules processor accepts (from its file templates,
// and checked against Fleet Manager 29.2).
var (
	fmMatchKeys = map[string]bool{"sid": true, "re": true, "action": true, "classtype": true, "destaddress": true, "destport": true,
		"filename": true, "gid": true, "group": true, "msg": true, "metadata": true, "priority": true, "protocol": true,
		"reference": true, "rev": true, "srcaddress": true, "srcport": true, "target": true}
	fmChangeKeys = map[string]bool{"action": true, "destaddress": true, "destport": true, "protocol": true,
		"srcaddress": true, "srcport": true, "ruleoptions": true}
	bareSID = regexp.MustCompile(`^(\d+:)?\d+$`)
)

// lintModifier finds lines Fleet Manager rejects (it rejects the whole file
// at upload) or handles differently from Corelight-update.
func lintModifier(kind Kind, b []byte) (errs, warns []string) {
	for i, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if j := strings.Index(line, " #"); j > 0 && !strings.Contains(line[:j], "\"") {
			line = strings.TrimSpace(line[:j]) // trailing comment
		}
		n := i + 1
		match, change := splitModifier(line)
		if strings.HasPrefix(strings.ToLower(match), "re:") {
			if !strings.HasPrefix(match[3:], "/") {
				errs = append(errs, fmt.Sprintf("line %d: Fleet Manager needs a regex enclosed in slashes (re:/.../): %s", n, clip(line)))
				continue
			}
		} else if !bareSID.MatchString(match) {
			key, _, ok := strings.Cut(match, ":")
			if !ok || !fmMatchKeys[strings.ToLower(key)] {
				errs = append(errs, fmt.Sprintf("line %d: unknown match key %q: %s", n, key, clip(line)))
				continue
			}
			if strings.EqualFold(key, "metadata") {
				warns = append(warns, fmt.Sprintf("line %d: a Metadata: match did not match rules in Fleet Manager 29.2 testing; re:/<text>/ does (for example re:/deployment SSLDecrypt/): %s", n, clip(line)))
			}
		}
		if kind != SuricataModify {
			if change != "" {
				errs = append(errs, fmt.Sprintf("line %d: unexpected text after the match: %s", n, clip(line)))
			}
			continue
		}
		if change == "" {
			errs = append(errs, fmt.Sprintf("line %d: no change (<matchKey>:<value> <changeKey>:<value>): %s", n, clip(line)))
			continue
		}
		if strings.HasPrefix(change, "\"") {
			errs = append(errs, fmt.Sprintf("line %d: Corelight-update's regex rewrite (re:<regex> \"<from>\" \"<to>\") is not supported by Fleet Manager: %s", n, clip(line)))
			continue
		}
		key, _, _ := strings.Cut(change, ":")
		if !fmChangeKeys[strings.ToLower(strings.TrimSpace(key))] {
			errs = append(errs, fmt.Sprintf("line %d: change key %q is not supported by Fleet Manager (it accepts Action, SrcAddress, SrcPort, DestAddress, DestPort, Protocol and RuleOptions): %s", n, key, clip(line)))
		}
	}
	return errs, warns
}

// splitModifier splits a line into its match and the rest (the change).
// A regex match runs to its closing slash; a quoted value to its quote.
func splitModifier(line string) (match, change string) {
	if strings.HasPrefix(strings.ToLower(line), "re:/") {
		if j := strings.Index(line[4:], "/"); j >= 0 {
			end := 4 + j + 1
			return line[:end], strings.TrimSpace(line[end:])
		}
	}
	if k := strings.Index(line, ":\""); k > 0 && !strings.ContainsAny(line[:k], " \t") {
		if j := strings.Index(line[k+2:], "\""); j >= 0 {
			end := k + 2 + j + 1
			return line[:end], strings.TrimSpace(line[end:])
		}
	}
	m, c, _ := strings.Cut(line, " ")
	return m, strings.TrimSpace(c)
}

func (p *Plan) planSuricataModifier(ctx context.Context, api API) error {
	if err := p.resolveSuricata(ctx, api); err != nil {
		return err
	}
	name := modifierFile[p.Kind]
	sp := p.suricata
	spName, spID := str(sp["name"]), idOf(sp["id"])
	p.Target = Target{Object: fmt.Sprintf("%s of Suricata policy %q (%d)", name, spName, spID), Name: name, ID: spID}
	if sp["rulesAutomation"] != true {
		p.block("Suricata policy %q does not use Suricata automation; configuration files only apply when Fleet Manager builds the ruleset from rule sources", spName)
	}
	if sp["useModifierFiles"] != true {
		p.warn("Suricata policy %q uses the Suricata rules manager, not configuration files: the push switches it to \"Use configuration files\", so the rule modifiers made in the rules manager stop applying", spName)
		p.step("switch Suricata policy %q to \"Use configuration files\"", spName)
		p.state = append(p.state, "mode=srm")
	}
	var old []byte
	for _, m := range listOf(sp["modifierFiles"]) {
		mf := obj(m)
		if str(mf["name"]) != name {
			continue
		}
		if fid := idOf(mf["fileId"]); fid > 0 {
			p.Target.Exists = true
			var err error
			if old, err = download(ctx, api, fid); err != nil {
				return err
			}
			p.Target.CurrentSHA256, p.Target.CurrentSize = sha256Hex(old), int64(len(old))
			p.Unchanged = normModifier(old) == normModifier(p.content) && mf["enabled"] == true && sp["useModifierFiles"] == true
		}
	}
	// Fleet Manager stores each entry with a "- ", "+ " or "~ " prefix (disable,
	// enable, modify); compare without it.
	p.Diff = diffLines(stripFMPrefix(old), stripFMPrefix(p.content), old != nil)
	errs, warns := lintModifier(p.Kind, p.content)
	p.Blockers = append(p.Blockers, errs...)
	if len(errs) > 0 {
		p.note("Fleet Manager rejects the whole file at upload if any line is invalid; comment out or rewrite the lines listed in blockers")
	}
	p.Warnings = append(p.Warnings, warns...)
	cfg := obj(sp["config"])
	p.Validation = map[string]any{"by": "fleet-mcp check of Fleet Manager's configuration-file syntax (Fleet Manager checks again at upload)",
		"problems": len(errs), "flowbit_dependencies": cfg["srmEnableFlowBits"] == true, "delete_disabled_rules": cfg["srmDeleteDisabledRules"] == true}
	if cfg["srmEnableFlowBits"] == true {
		p.note("\"Enable flowbit dependencies\" is on: Fleet Manager re-enables disabled rules that set a flowbit an enabled rule checks, even rules disable.conf turned off")
	}
	p.step("upload %s and enable it on Suricata policy %q", name, spName)
	p.step("Fleet Manager rebuilds the policy's ruleset (about a minute for 100 MB of rules) and sends it to the sensors")
	p.state = append(p.state, fmt.Sprintf("suricata=%d", spID))
	return nil
}

func (a *applier) suricataModifier(ctx context.Context) error {
	name := modifierFile[a.p.Kind]
	fid, err := a.upload(ctx, modifierStore, name)
	if err != nil {
		return fmt.Errorf("%w (Fleet Manager checks every line at upload; nothing else was changed)", err)
	}
	// The web interface sends name, fileId and enabled for each file.
	var files []map[string]any
	found := false
	for _, m := range listOf(a.p.suricata["modifierFiles"]) {
		mf := obj(m)
		e := map[string]any{"name": mf["name"], "fileId": idOf(mf["fileId"]), "enabled": mf["enabled"] == true}
		if str(mf["name"]) == name {
			e["fileId"], e["enabled"], found = fid, true, true
		}
		files = append(files, e)
	}
	if !found {
		files = append(files, map[string]any{"name": name, "fileId": fid, "enabled": true})
	}
	body := map[string]any{"modifierFiles": files}
	if a.p.suricata["useModifierFiles"] != true {
		body["useModifierFiles"] = true
	}
	if err := a.putSuricata(ctx, body); err != nil {
		return err
	}
	a.did("set %s on Suricata policy %q and enabled it", name, str(a.p.suricata["name"]))
	if body["useModifierFiles"] == true {
		a.did("switched Suricata policy %q to \"Use configuration files\"", str(a.p.suricata["name"]))
	}
	return nil
}

// waitRuleset waits (up to two minutes) for Fleet Manager to finish
// rebuilding a Suricata policy's ruleset and reports the outcome.
func (a *applier) waitRuleset(ctx context.Context, bad func(string, ...any)) {
	id := idOf(a.p.suricata["id"])
	deadline := time.Now().Add(2 * time.Minute)
	time.Sleep(rulesetSettle)
	for {
		var st map[string]any
		if err := a.api.GetJSON(ctx, fmt.Sprintf("%s/%d/status", pathSuricata, id), nil, &st); err != nil {
			bad("could not read the ruleset build status: %v", err)
			return
		}
		if st["processing"] != true {
			errs := obj(st["errors"])
			var msgs []string
			for _, k := range []string{"sources", "modifiers"} {
				for f, e := range obj(errs[k]) {
					msgs = append(msgs, fmt.Sprintf("%s %s: %v", k, f, e))
				}
			}
			if out := errs["output"]; out != nil && fmt.Sprint(out) != "[]" {
				msgs = append(msgs, fmt.Sprintf("output: %v", out))
			}
			if len(msgs) > 0 {
				bad("Fleet Manager reports ruleset build errors: %s", strings.Join(msgs, "; "))
			} else {
				a.did("Fleet Manager rebuilt the ruleset without errors")
			}
			return
		}
		if time.Now().After(deadline) {
			a.did("Fleet Manager was still rebuilding the ruleset after 2 minutes; check fm_suricata_policy_get later")
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (a *applier) verifyModifier(ctx context.Context, sp map[string]any, bad func(string, ...any)) {
	name := modifierFile[a.p.Kind]
	for _, m := range listOf(sp["modifierFiles"]) {
		mf := obj(m)
		if str(mf["name"]) == name {
			if idOf(mf["fileId"]) != a.res.FileID || mf["enabled"] != true {
				bad("%s on the Suricata policy is file %d (enabled %v), not the uploaded file %d", name, idOf(mf["fileId"]), mf["enabled"], a.res.FileID)
			}
		}
	}
	if sp["useModifierFiles"] != true {
		bad("the Suricata policy does not use configuration files")
	}
	a.waitRuleset(ctx, bad)
}

var fmPrefix = regexp.MustCompile(`(?m)^[-+~] `)

// stripFMPrefix removes the "- ", "+ " or "~ " Fleet Manager puts before
// each entry of a stored configuration file.
func stripFMPrefix(b []byte) []byte { return fmPrefix.ReplaceAll(b, nil) }

// normModifier is a configuration file without Fleet Manager's prefixes,
// carriage returns and trailing blanks, for comparing a local file with
// the copy Fleet Manager stores.
func normModifier(b []byte) string {
	lines := strings.Split(strings.ReplaceAll(string(stripFMPrefix(b)), "\r", ""), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
