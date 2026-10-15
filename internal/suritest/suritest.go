// Package suritest tests a Suricata ruleset with a real Suricata
// (suricata -T) on a host the user names, over SSH. Fleet Manager only
// parses rules; this loads them the way a sensor does.
//
// It uses the system ssh client (the user's keys, agent, ssh_config and
// known_hosts apply) and runs Suricata as the login user; root is used only
// to read the host's stock configuration when it is not world-readable
// (sudo -n). Everything goes into a temporary directory that is removed
// afterwards.
package suritest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Options say where and how to test.
type Options struct {
	Host string
	User string // empty: ssh_config default
	// SSHBinary is the ssh executable; empty means "ssh".
	SSHBinary string
	// Suricata is the binary on the host; empty means "suricata".
	Suricata string
	// Config is a suricata.yaml to use; nil means the host's
	// /etc/suricata/suricata.yaml (with its classification, reference and
	// threshold files).
	Config []byte
	// Vars are address and port groups, as "address-groups.NAME" or
	// "port-groups.NAME" -> value, set with --set vars.<key>=<value>.
	Vars map[string]string
	// Timeout for the whole test; 0 means 15 minutes.
	Timeout time.Duration
}

// Report is the outcome of a test.
type Report struct {
	Host          string            `json:"host"`
	Version       string            `json:"suricata_version"`
	Config        string            `json:"config"`
	OK            bool              `json:"ok"`
	ExitCode      int               `json:"exit_code"`
	RuleFiles     int               `json:"rule_files"`
	Loaded        int               `json:"rules_loaded"`
	Failed        int               `json:"rules_failed"`
	Skipped       int               `json:"rules_skipped"`
	FailedSIDs    []string          `json:"failed_sids,omitempty"`
	Reasons       map[string]int    `json:"failure_reasons,omitempty"`
	UndefinedVars []string          `json:"undefined_vars,omitempty"`
	Errors        []string          `json:"error_sample,omitempty"`
	VarsSet       map[string]string `json:"vars_set,omitempty"`
	Seconds       float64           `json:"seconds"`
}

var (
	hostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:-]*$`)
	userPattern = regexp.MustCompile(`^[a-z_][a-z0-9_.-]*$`)
	binPattern  = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
	varPattern  = regexp.MustCompile(`^(address|port)-groups\.[A-Za-z0-9_]+$`)
)

type session struct {
	o   Options
	bin string
}

// run executes a bash script on the host; stdin (if any) follows nothing,
// the script is passed as the remote command.
func (s *session) run(ctx context.Context, script string, stdin io.Reader) (string, string, int, error) {
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=30"}
	if s.o.User != "" {
		args = append(args, "-l", s.o.User)
	}
	args = append(args, "--", s.o.Host, "bash -c "+quote(script))
	cmd := exec.CommandContext(ctx, s.bin, args...)
	cmd.Stdin = stdin
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return out.String(), errb.String(), -1, fmt.Errorf("running ssh: %w", err)
		}
		code = ee.ExitCode()
		if code == 255 {
			return out.String(), errb.String(), code, fmt.Errorf("ssh to %s failed: %s", s.o.Host, strings.TrimSpace(errb.String()))
		}
	}
	return out.String(), errb.String(), code, nil
}

// Test loads rules with suricata -T on the host and reports the result.
func Test(ctx context.Context, o Options, rules []byte) (*Report, error) {
	if !hostPattern.MatchString(o.Host) {
		return nil, fmt.Errorf("bad test host %q", o.Host)
	}
	if o.User != "" && !userPattern.MatchString(o.User) {
		return nil, fmt.Errorf("bad ssh user %q", o.User)
	}
	if o.Suricata == "" {
		o.Suricata = "suricata"
	}
	if !binPattern.MatchString(o.Suricata) {
		return nil, fmt.Errorf("bad suricata path %q", o.Suricata)
	}
	for k := range o.Vars {
		if !varPattern.MatchString(k) {
			return nil, fmt.Errorf("bad variable %q (want address-groups.NAME or port-groups.NAME)", k)
		}
	}
	if len(bytes.TrimSpace(rules)) == 0 {
		return nil, errors.New("the ruleset is empty")
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	s := &session{o: o, bin: o.SSHBinary}
	if s.bin == "" {
		s.bin = "ssh"
	}
	start := time.Now()

	out, errOut, code, err := s.run(ctx, `d=$(mktemp -d /tmp/fleet-mcp-suritest.XXXXXX) && echo "$d"`, nil)
	if err != nil {
		return nil, err
	}
	dir := strings.TrimSpace(out)
	if code != 0 || !strings.HasPrefix(dir, "/tmp/fleet-mcp-suritest.") {
		return nil, fmt.Errorf("creating a temporary directory on %s failed: %s", o.Host, strings.TrimSpace(errOut))
	}
	defer func() {
		_, _, _, _ = s.run(context.WithoutCancel(ctx), "rm -rf "+quote(dir), nil)
	}()
	if _, errOut, code, err := s.run(ctx, "cat > "+quote(dir+"/test.rules"), bytes.NewReader(rules)); err != nil || code != 0 {
		return nil, fmt.Errorf("copying the rules to %s failed: %v %s", o.Host, err, strings.TrimSpace(errOut))
	}
	r := &Report{Host: o.Host, VarsSet: o.Vars}
	var sb strings.Builder
	sb.WriteString("cd " + quote(dir) + " || exit 90\n")
	if o.Config != nil {
		if _, errOut, code, err := s.run(ctx, "cat > "+quote(dir+"/suricata.yaml"), bytes.NewReader(o.Config)); err != nil || code != 0 {
			return nil, fmt.Errorf("copying the configuration to %s failed: %v %s", o.Host, err, strings.TrimSpace(errOut))
		}
		r.Config = "the given suricata.yaml"
	} else {
		// The stock files, read as the user or, if they are root-only, with sudo -n.
		sb.WriteString("for f in suricata.yaml classification.config reference.config threshold.config; do\n" +
			"  cat /etc/suricata/$f > $f 2>/dev/null || sudo -n cat /etc/suricata/$f > $f 2>/dev/null || { [ $f = suricata.yaml ] && { echo 'cannot read /etc/suricata/suricata.yaml (missing, or root-only and no passwordless sudo); give config' >&2; exit 92; }; true; }\n" +
			"done\n")
		r.Config = "the host's /etc/suricata/suricata.yaml"
	}
	sb.WriteString(o.Suricata + " -V 2>&1 | head -1\n")
	sb.WriteString(o.Suricata + " -T -v -c suricata.yaml -S \"$PWD/test.rules\" -l \"$PWD\"")
	if o.Config == nil {
		sb.WriteString(` --set classification-file="$PWD/classification.config" --set reference-config-file="$PWD/reference.config" --set threshold-file="$PWD/threshold.config"`)
	}
	keys := make([]string, 0, len(o.Vars))
	for k := range o.Vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteString(" --set " + quote("vars."+k+"="+o.Vars[k]))
	}
	sb.WriteString(" > out.txt 2>&1; echo \"exit=$?\"; cat out.txt\n")
	out, errOut, code, err = s.run(ctx, sb.String(), nil)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("testing on %s failed (%d): %s", o.Host, code, strings.TrimSpace(errOut))
	}
	parse(r, out)
	r.Seconds = time.Since(start).Round(100 * time.Millisecond).Seconds()
	if r.Version == "" || !strings.Contains(r.Version, "Suricata") {
		return r, fmt.Errorf("%s did not run on %s: %s", o.Suricata, o.Host, firstLine(out))
	}
	return r, nil
}

var (
	summaryRe = regexp.MustCompile(`(\d+) rule files processed\. (\d+) rules successfully loaded, (\d+) rules failed(?:, (\d+) rules skipped)?`)
	sidRe     = regexp.MustCompile(`[;(\s]sid\s*:\s*(\d+)\s*;`)
	undefRe   = regexp.MustCompile(`Variable "([^"]+)" is not defined`)
	reasonRe  = regexp.MustCompile(`^(?:Error|E): (detect-[a-z-]+|rule-vars|[a-z-]+): (.*)$`)
)

func parse(r *Report, out string) {
	failed := map[string]bool{}
	undef := map[string]bool{}
	r.Reasons = map[string]int{}
	lastReason := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "exit="):
			r.ExitCode, _ = strconv.Atoi(strings.TrimPrefix(line, "exit="))
		case strings.HasPrefix(line, "This is Suricata version"):
			r.Version = strings.TrimPrefix(line, "This is ")
		}
		if m := summaryRe.FindStringSubmatch(line); m != nil {
			r.RuleFiles, _ = strconv.Atoi(m[1])
			r.Loaded, _ = strconv.Atoi(m[2])
			r.Failed, _ = strconv.Atoi(m[3])
			r.Skipped, _ = strconv.Atoi(m[4])
		}
		if m := undefRe.FindStringSubmatch(line); m != nil {
			undef[m[1]] = true
		}
		if strings.Contains(line, "error parsing signature") {
			if m := sidRe.FindStringSubmatch(line); m != nil {
				failed[m[1]] = true
			}
			if lastReason == "" {
				lastReason = "unspecified"
			}
			r.Reasons[lastReason]++
			lastReason = ""
			if len(r.Errors) < 20 {
				r.Errors = append(r.Errors, clip(line, 300))
			}
			continue
		}
		if m := reasonRe.FindStringSubmatch(line); m != nil && !strings.Contains(line, "Loading signatures failed") {
			lastReason = clip(normalizeReason(m[2]), 160)
		}
	}
	for s := range failed {
		r.FailedSIDs = append(r.FailedSIDs, s)
	}
	sort.Slice(r.FailedSIDs, func(i, j int) bool {
		a, _ := strconv.Atoi(r.FailedSIDs[i])
		b, _ := strconv.Atoi(r.FailedSIDs[j])
		return a < b
	})
	for v := range undef {
		r.UndefinedVars = append(r.UndefinedVars, v)
	}
	sort.Strings(r.UndefinedVars)
	if len(r.Reasons) == 0 {
		r.Reasons = nil
	}
	r.OK = r.ExitCode == 0 && r.Failed == 0 && r.RuleFiles > 0
	if r.RuleFiles == 0 {
		// No summary: show the end of Suricata's output instead.
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) > 15 {
			lines = lines[len(lines)-15:]
		}
		for _, l := range lines {
			r.Errors = append(r.Errors, clip(strings.TrimRight(l, "\r"), 300))
		}
	}
}

var quotedRe = regexp.MustCompile(`"[^"]*"|'[^']*'`)

// normalizeReason groups failure messages that differ only in the name
// they quote (Variable "X" is not defined).
func normalizeReason(s string) string {
	if undefRe.MatchString(s) {
		return s
	}
	return quotedRe.ReplaceAllString(s, `"..."`)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}

// quote single-quotes s for bash.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
