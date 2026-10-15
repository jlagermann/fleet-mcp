package content

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// SuricataPolicy finds a Suricata policy by id or name, or through a
// sensor policy, and returns it with the sensor policies that use it.
func SuricataPolicy(ctx context.Context, api API, suricataRef, policyRef string) (map[string]any, []string, error) {
	tmp := &Plan{req: Request{Kind: SuricataRules, SuricataPolicy: suricataRef, Policy: policyRef}}
	if err := tmp.resolveSuricata(ctx, api); err != nil {
		return nil, nil, err
	}
	return tmp.suricata, tmp.UsedBy, nil
}

// GeneratedRuleset downloads the ruleset Fleet Manager sends for a Suricata
// policy (with automation, the one it built from the sources and tuning).
func GeneratedRuleset(ctx context.Context, api API, sp map[string]any) ([]byte, error) {
	fi := obj(obj(sp["fileInfo"])["suricata-file-id"])
	id := idOf(fi["id"])
	if id == 0 {
		return nil, fmt.Errorf("the Suricata policy %q has no ruleset yet", str(sp["name"]))
	}
	return download(ctx, api, id)
}

// SuricataVars returns a Suricata policy's address and port groups as
// "address-groups.NAME"/"port-groups.NAME" -> value: the policy settings,
// overridden by groups in its suricata.yaml snippet, and HOME_NET when the
// policy sets one. notes say where they came from.
func SuricataVars(ctx context.Context, api API, sp map[string]any) (map[string]string, []string, error) {
	vars := map[string]string{}
	var notes []string
	for k, v := range obj(sp["settings"]) {
		s, ok := v.(string)
		if !ok || s == "" {
			continue
		}
		for prefix, group := range map[string]string{"suricata.address_groups.": "address-groups.", "suricata.port_groups.": "port-groups."} {
			if name, ok := strings.CutPrefix(k, prefix); ok {
				vars[group+strings.ToUpper(name)] = s
			}
		}
	}
	if len(vars) > 0 {
		notes = append(notes, fmt.Sprintf("%d address and port groups from the Suricata policy's settings", len(vars)))
	}
	if h := strings.TrimSpace(str(sp["homeNet"])); h != "" {
		vars["address-groups.HOME_NET"] = h
	} else {
		notes = append(notes, "the policy sets no HOME_NET (sensors use their own local networks); the test uses Suricata's default")
	}
	if fid := idOf(obj(obj(sp["fileInfo"])["suricata-yaml-file-id"])["id"]); fid > 0 {
		b, err := download(ctx, api, fid)
		if err != nil {
			return nil, nil, err
		}
		snip := snippetVars(string(b))
		for k, v := range snip {
			vars[k] = v
		}
		notes = append(notes, fmt.Sprintf("%d groups from the policy's suricata.yaml snippet", len(snip)))
	}
	return vars, notes, nil
}

var (
	snipSection = regexp.MustCompile(`^(\s*)"?(address-groups|port-groups)"?\s*:\s*(#.*)?$`)
	snipEntry   = regexp.MustCompile(`^(\s*)"?([A-Za-z0-9_]+)"?\s*:\s*(.+?)\s*$`)
)

// snippetVars reads vars.address-groups and vars.port-groups from a
// suricata.yaml snippet (the simple block form Fleet Manager uses).
func snippetVars(y string) map[string]string {
	out := map[string]string{}
	section, indent := "", -1
	inVars := false
	for _, line := range strings.Split(strings.ReplaceAll(y, "\r", ""), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "%") || t == "---" {
			continue
		}
		lead := len(line) - len(strings.TrimLeft(line, " \t"))
		if lead == 0 {
			inVars = strings.HasPrefix(t, "vars:") || strings.HasPrefix(t, `"vars":`)
			section = ""
			continue
		}
		if !inVars {
			continue
		}
		if m := snipSection.FindStringSubmatch(line); m != nil {
			section, indent = m[2], len(m[1])
			continue
		}
		if section == "" {
			continue
		}
		if lead <= indent {
			section = ""
			continue
		}
		if m := snipEntry.FindStringSubmatch(line); m != nil {
			v := m[3]
			if q := v[0]; q == '"' || q == '\'' {
				if j := strings.IndexByte(v[1:], q); j >= 0 {
					v = v[1 : j+1]
				}
			} else if i := strings.Index(v, " #"); i >= 0 {
				v = strings.TrimSpace(v[:i])
			}
			out[section+"."+m[2]] = v
		}
	}
	return out
}
