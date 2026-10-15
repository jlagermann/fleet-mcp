package suritest

import (
	"strings"
	"testing"
)

const sample = `This is Suricata version 8.0.7 RELEASE
exit=1
Notice: suricata: This is Suricata version 8.0.7 RELEASE running in SYSTEM mode
Error: rule-vars: Variable "SCANNERS" is not defined in configuration file
Error: detect: error parsing signature "alert tcp !$SCANNERS any -> any any (msg:"x"; sid:2000001; rev:1;)" from file /tmp/t/test.rules at line 3
Error: detect-parse: unknown rule keyword 'nosuchkeyword'.
Error: detect: error parsing signature "alert http any any -> any any (msg:"broken"; nosuchkeyword; sid:9199999; rev:1;)" from file /tmp/t/test.rules at line 44
Error: rule-vars: Variable "SCANNERS" is not defined in configuration file
Error: detect: error parsing signature "alert http [$EXTERNAL_NET,!$SCANNERS] any -> any any (msg:"y"; sid: 2000002; rev:1;)" from file /tmp/t/test.rules at line 9
Info: detect: 1 rule files processed. 14 rules successfully loaded, 3 rules failed, 0 rules skipped
Error: suricata: Loading signatures failed.
`

func TestParse(t *testing.T) {
	r := &Report{}
	parse(r, sample)
	if r.OK || r.ExitCode != 1 || r.Loaded != 14 || r.Failed != 3 || r.RuleFiles != 1 {
		t.Fatalf("counts: %+v", r)
	}
	if strings.Join(r.FailedSIDs, ",") != "2000001,2000002,9199999" {
		t.Errorf("failed sids: %v", r.FailedSIDs)
	}
	if strings.Join(r.UndefinedVars, ",") != "SCANNERS" {
		t.Errorf("undefined: %v", r.UndefinedVars)
	}
	if r.Reasons[`Variable "SCANNERS" is not defined in configuration file`] != 2 || r.Reasons[`unknown rule keyword "...".`] != 1 {
		t.Errorf("reasons: %v", r.Reasons)
	}
	if r.Version != "Suricata version 8.0.7 RELEASE" {
		t.Errorf("version: %q", r.Version)
	}

	ok := &Report{}
	parse(ok, "This is Suricata version 8.0.7 RELEASE\nexit=0\nInfo: detect: 1 rule files processed. 135602 rules successfully loaded, 0 rules failed, 0 rules skipped\n")
	if !ok.OK || ok.Loaded != 135602 || len(ok.FailedSIDs) != 0 {
		t.Errorf("ok: %+v", ok)
	}
}

func TestQuote(t *testing.T) {
	if got := quote(`it's`); got != `'it'\''s'` {
		t.Errorf("quote: %s", got)
	}
}
