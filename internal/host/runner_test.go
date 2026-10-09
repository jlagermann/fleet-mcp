package host

import (
	"strings"
	"testing"
)

func TestNewSSHValidates(t *testing.T) {
	for _, c := range []struct{ host, user string }{
		{"-oProxyCommand=evil", ""}, {"host name", ""}, {"h", "-l root"}, {"h", "Bad User"}, {"", ""},
	} {
		if _, err := NewSSH(c.host, c.user, 0); err == nil {
			t.Errorf("accepted %q %q", c.host, c.user)
		}
	}
	s, err := NewSSH("192.168.10.21", "james", 2222)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(s.Args(), " ")
	if !strings.Contains(args, "BatchMode=yes") || !strings.Contains(args, "-p 2222 -l james -- 192.168.10.21 sudo -n bash -s") {
		t.Fatalf("args = %s", args)
	}
}

func TestMaskAndHeredoc(t *testing.T) {
	if got := Mask("token=s3cr3tvalue here s3cr3tvalue", "s3cr3tvalue", "", "ab"); got != "token=[REDACTED] here [REDACTED]" {
		t.Fatalf("Mask = %q", got)
	}
	h := Heredoc("line with FLEET_MCP_EOF inside")
	if !strings.HasPrefix(h, "cat <<'FLEET_MCP_EOF_0'\n") || !strings.HasSuffix(h, "\nFLEET_MCP_EOF_0\n") {
		t.Fatalf("Heredoc = %q", h)
	}
	if Quote("it's") != `'it'"'"'s'` {
		t.Fatalf("Quote = %s", Quote("it's"))
	}
}
