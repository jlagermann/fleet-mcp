package content

import (
	"strings"
	"testing"
)

const testRules = `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"MODTEST 1 exploit ext"; flow:established,to_server; content:"modtest1"; metadata:tag Exploit, created_at 2026_10_30; classtype:web-application-attack; sid:9000001; rev:1;)
alert http any any -> $HOME_NET any (msg:"MODTEST 2 exploit any"; flow:established,to_server; content:"modtest2"; metadata:tag Exploit; classtype:web-application-attack; sid:9000002; rev:1;)
alert tcp [10.0.0.0/8,192.168.0.0/16] any -> $HOME_NET 80 (msg:"MODTEST 3 bracket src"; flow:established,to_server; content:"modtest3"; metadata:mitre_technique_id T1190; classtype:attempted-admin; sid:9000003; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"MODTEST 4 no tag"; flow:established,to_server; content:"modtest4"; metadata:created_at 2026_10_30; classtype:trojan-activity; sid:9000004; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"MODTEST 5 for append"; flow:established,to_server; content:"modtest5"; metadata:created_at 2026_10_30; classtype:misc-activity; sid:9000005; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MODTEST 6 multi line"; flow:established,to_server; content:"modtest6"; classtype:misc-activity; sid:9000006; rev:1;)
# alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MODTEST 7 path/slash"; flow:established,to_server; content:"/modtest7/"; classtype:misc-activity; sid:9000007; rev:1;)
alert dns $HOME_NET any -> any any (msg:"MODTEST 8 comma list a"; dns.query; content:"modtest8"; classtype:misc-activity; sid:9000008; rev:1;)
alert dns $HOME_NET any -> any any (msg:"MODTEST 9 comma list b"; dns.query; content:"modtest9"; classtype:misc-activity; sid:9000009; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"MODTEST 10 metadata match"; flow:established,to_server; content:"modtest10"; metadata:deployment Perimeter, signature_severity Major; classtype:misc-activity; sid:9000010; rev:1;)
# alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"MODTEST 11 disabled exploit"; content:"modtest11"; metadata:tag Exploit; classtype:web-application-attack; sid:9000011; rev:1;)
`

func testRuleSet(t *testing.T) *ruleSet {
	t.Helper()
	rs := newRuleSet("test")
	if n := parseRuleFile([]byte(testRules), "test.rules", rs); n != 11 {
		t.Fatalf("parsed %d rules", n)
	}
	return rs
}

// fmApply applies a file Fleet Manager accepts the way Fleet Manager does:
// line by line, in order.
func fmApply(t *testing.T, rs *ruleSet, b []byte) {
	t.Helper()
	for i, raw := range strings.Split(string(b), "\n") {
		ml := parseModLine(SuricataModify, i+1, raw)
		if ml == nil {
			continue
		}
		if ml.cu() {
			t.Fatalf("converted file still has Corelight-update syntax on line %d: %s (%s)", i+1, raw, ml.reason)
		}
		m, err := compileMatch(ml.match)
		if err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		applyNative(rs, m, ml.key, ml.value)
	}
}

func TestConvertModifier(t *testing.T) {
	modify := strings.Join([]string{
		"# tuning",
		`9000005 MetadataAppend:followup watch`,
		`re:(mitre_technique_id\sT1190|tag\sExploit\b|followup\swatch) "^(alert \S+) (\$\w+|\[[^\]]*\]|![^ ]+) " "$1 [$2,!$$SCANNERS] "`,
		`re:(mitre_technique_id\sT1190|tag\sExploit\b|followup\swatch) "^(alert \S+) any " "$1 !$$SCANNERS "`,
		`9000001 Msg:"New msg"`,
		`9000008,9000009 SrcAddress:10.1.1.1`,
		`1:9000006 DestPort:81`,
		`Metadata:"deployment Perimeter" Action:drop`,
		`re:path/slash Classtype:bad-unknown`,
		`9000004 Other:content:"x";`,
		`9000004 Priority:2`,
		`9000006 RuleOptions:(msg:"MODTEST 6 changed"; content:"modtest6"; sid:9000006; rev:2;)`,
		`9000005 MetadataAppend:followup watch`,
		`9000002 OtherAppend:reference:url,example.com`,
	}, "\n") + "\n"

	cuRules := testRuleSet(t)
	out := convertModifier(SuricataModify, []byte(modify), CUConvert, cuRules)
	got := string(out.text)
	for _, want := range []string{
		`9000005 RuleOptions:(msg:"MODTEST 5 for append"; flow:established,to_server; content:"modtest5"; metadata:created_at 2026_10_30, followup watch; classtype:misc-activity; sid:9000005; rev:1;)`,
		`re:/^\S+ \S+ \$EXTERNAL_NET .*(?:(mitre_technique_id\sT1190|tag\sExploit\b|followup\swatch))/ SrcAddress:[$EXTERNAL_NET,!$SCANNERS]`,
		`re:/^\S+ \S+ \[10\.0\.0\.0\/8,192\.168\.0\.0\/16\] .*(?:(mitre_technique_id\sT1190|tag\sExploit\b|followup\swatch))/ SrcAddress:[[10.0.0.0/8,192.168.0.0/16],!$SCANNERS]`,
		`re:/^\S+ \S+ any .*(?:(mitre_technique_id\sT1190|tag\sExploit\b|followup\swatch))/ SrcAddress:!$SCANNERS`,
		`9000001 RuleOptions:(msg:"New msg";`,
		"9000008 SrcAddress:10.1.1.1\n9000009 SrcAddress:10.1.1.1\n",
		"9000006 DestPort:81\n",
		`re:/metadata:[^;]*deployment Perimeter/ Action:drop`,
		`9000007 RuleOptions:(msg:"MODTEST 7 path/slash"; flow:established,to_server; content:"/modtest7/"; classtype:bad-unknown; sid:9000007; rev:1;)`,
		`# fleet-mcp: commented out (Fleet Manager rejects Other:`,
		`# fleet-mcp: commented out (a repeat of an earlier line`,
		`9000002 RuleOptions:(msg:"MODTEST 2 exploit any"; flow:established,to_server; content:"modtest2"; reference:url,example.com; metadata:tag Exploit;`,
		"9000004 Priority:2\n",
		"# fleet-mcp: converted from Corelight-update syntax (Fleet Manager rejects the change key MetadataAppend): 9000005 MetadataAppend:followup watch\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("converted file lacks\n  %s\n%s", want, got)
		}
	}
	if out.count != 11 {
		t.Errorf("count %d, want 11", out.count)
	}
	if strings.Join(out.frozen, ",") != "9000001,9000002,9000005,9000007" {
		t.Errorf("frozen %v", out.frozen)
	}
	if errs, _ := lintModifier(SuricataModify, out.text); len(errs) > 0 {
		t.Errorf("Fleet Manager would reject the converted file: %v", errs)
	}

	// Fleet Manager applying the converted file must give the rules
	// Corelight-update gives with the original (the CU simulation).
	fmRules := testRuleSet(t)
	fmApply(t, fmRules, out.text)
	for _, r := range cuRules.list {
		if r.Disabled {
			continue // Fleet Manager also changes disabled rules (see the note)
		}
		if f := fmRules.bySID[r.SID]; f == nil || f.text() != r.text() {
			t.Errorf("SID %s differs:\n  CU: %s\n  FM: %v", r.SID, r.text(), f)
		}
	}
	if r := cuRules.bySID["9000003"]; r.Src != "[[10.0.0.0/8,192.168.0.0/16],!$SCANNERS]" {
		t.Errorf("9000003 src %s", r.Src)
	}

	// comment_out leaves Fleet Manager's own lines and comments out the rest.
	out = convertModifier(SuricataModify, []byte(modify), CUCommentOut, nil)
	if n := strings.Count(string(out.text), "# fleet-mcp: commented out"); n != 11 {
		t.Errorf("%d commented out:\n%s", n, out.text)
	}
	if !strings.Contains(string(out.text), "\n9000004 Priority:2\n") {
		t.Errorf("native line changed:\n%s", out.text)
	}
}

func TestConvertDisable(t *testing.T) {
	in := "2033683 # keep\n1:2035465\n2000001,2000002\nMetadata:\"deployment SSL/Decrypt\"\nre:emerging\\sexploit\nsid:2053281\n"
	out := convertModifier(SuricataDisable, []byte(in), CUConvert, nil)
	want := "2033683 # keep\n" +
		"# fleet-mcp: converted from Corelight-update syntax (Fleet Manager accepts gid:sid but it matches no rule): 1:2035465\n2035465\n" +
		"# fleet-mcp: converted from Corelight-update syntax (Fleet Manager does not accept a list of SIDs on one line): 2000001,2000002\n2000001\n2000002\n" +
		"# fleet-mcp: converted from Corelight-update syntax (a Metadata: match matches no rule in Fleet Manager): Metadata:\"deployment SSL/Decrypt\"\nre:/metadata:[^;]*deployment SSL\\/Decrypt/\n" +
		"# fleet-mcp: converted from Corelight-update syntax (Fleet Manager needs the regex enclosed in slashes (re:/.../)): re:emerging\\sexploit\nre:/emerging\\sexploit/\n" +
		"sid:2053281\n"
	if string(out.text) != want {
		t.Errorf("got\n%s\nwant\n%s", out.text, want)
	}
	if errs, _ := lintModifier(SuricataDisable, out.text); len(errs) > 0 {
		t.Errorf("lint: %v", errs)
	}
}

func TestOptionEditing(t *testing.T) {
	o := `(msg:"a; b"; content:"x\;y"; metadata:k v; sid:1; rev:2;)`
	if v, _ := optionValue(o, "content"); v != `"x\;y"` {
		t.Errorf("content %q", v)
	}
	if got := setOption(o, "classtype", "classtype:c;"); got != `(msg:"a; b"; content:"x\;y"; metadata:k v; classtype:c; sid:1; rev:2;)` {
		t.Errorf("add: %s", got)
	}
	if got := cuChange(o, "rev", "3"); got != `(msg:"a; b"; content:"x\;y"; metadata:k v; sid:1; rev:3;)` {
		t.Errorf("rev: %s", got)
	}
	if got := cuChange(o, "flowbitsnoalert", "true"); got != `(msg:"a; b"; content:"x\;y"; flowbits:noalert; metadata:k v; sid:1; rev:2;)` {
		t.Errorf("noalert: %s", got)
	}
	if got := cuChange(cuChange(o, "flowbitsnoalert", "true"), "flowbitsnoalert", "false"); got != o {
		t.Errorf("noalert off: %s", got)
	}
}

func TestConvertDisabledRules(t *testing.T) {
	rs := testRuleSet(t)
	in := `re:(tag\sExploit\b) "^(alert \S+) (\$\w+) " "$1 [$2,!$$SCANNERS] "` + "\n"
	out := convertModifier(SuricataModify, []byte(in), CUConvert, rs)
	if r := rs.bySID["9000011"]; !r.Disabled || r.Src != "$EXTERNAL_NET" {
		t.Errorf("Corelight-update leaves a commented-out rule alone: %+v", r)
	}
	if !strings.Contains(string(out.text), `re:/^\S+ \S+ \$EXTERNAL_NET .*(?:(tag\sExploit\b))/ SrcAddress:[$EXTERNAL_NET,!$SCANNERS]`) {
		t.Errorf("not grouped:\n%s", out.text)
	}
	if len(out.notes) != 1 || !strings.Contains(out.notes[0], "also change 1 disabled rule") {
		t.Errorf("notes: %v", out.notes)
	}
}
