// Package host runs scripts on a Fleet Manager host over SSH.
//
// It uses the system ssh client, so the user's keys, agent, ssh_config and
// known_hosts apply. Scripts are sent on stdin to "sudo -n bash -s", which
// keeps their contents (including secrets) out of process listings.
package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Result is the outcome of a script.
type Result struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

// OK reports a zero exit status.
func (r *Result) OK() bool { return r.ExitCode == 0 }

// Runner runs bash scripts as root on one host.
type Runner interface {
	// Run executes script. Every occurrence of a value in secrets is masked
	// in the returned output.
	Run(ctx context.Context, script string, secrets ...string) (*Result, error)
	// Name identifies the host.
	Name() string
}

var (
	hostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:-]*$`)
	userPattern = regexp.MustCompile(`^[a-z_][a-z0-9_.-]*$`)
)

// SSH runs scripts with the ssh command.
type SSH struct {
	Host string
	User string // empty: ssh_config default
	Port int    // 0: default
	// Binary is the ssh executable; empty means "ssh".
	Binary string
	// Timeout per script; 0 means 30 minutes (package installs are slow).
	Timeout time.Duration
}

// NewSSH validates the target and returns a runner.
func NewSSH(host, user string, port int) (*SSH, error) {
	if !hostPattern.MatchString(host) {
		return nil, fmt.Errorf("bad host %q", host)
	}
	if user != "" && !userPattern.MatchString(user) {
		return nil, fmt.Errorf("bad ssh user %q", user)
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("bad port %d", port)
	}
	return &SSH{Host: host, User: user, Port: port}, nil
}

// Name returns user@host.
func (s *SSH) Name() string {
	if s.User != "" {
		return s.User + "@" + s.Host
	}
	return s.Host
}

// Args are the ssh arguments (exported for tests).
func (s *SSH) Args() []string {
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=30"}
	if s.Port != 0 {
		args = append(args, "-p", strconv.Itoa(s.Port))
	}
	if s.User != "" {
		args = append(args, "-l", s.User)
	}
	return append(args, "--", s.Host, "sudo -n bash -s")
}

// Run executes script as root on the host.
func (s *SSH) Run(ctx context.Context, script string, secrets ...string) (*Result, error) {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	bin := s.Binary
	if bin == "" {
		bin = "ssh"
	}
	cmd := exec.CommandContext(ctx, bin, s.Args()...)
	// Windows editors and heredocs must not leave carriage returns.
	cmd.Stdin = strings.NewReader("set -o pipefail\n" + strings.ReplaceAll(script, "\r\n", "\n"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := &Result{Stdout: Mask(stdout.String(), secrets...), Stderr: Mask(stderr.String(), secrets...)}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			// 255 is ssh's own failure (connection, authentication).
			if res.ExitCode == 255 {
				return res, fmt.Errorf("ssh to %s failed: %s", s.Name(), strings.TrimSpace(res.Stderr))
			}
			if strings.Contains(res.Stderr, "sudo: a password is required") {
				return res, fmt.Errorf("%s: passwordless sudo is required for %s", s.Name(), s.User)
			}
			return res, nil
		}
		if ctx.Err() != nil {
			return res, fmt.Errorf("ssh to %s: timed out after %s", s.Name(), timeout)
		}
		return res, fmt.Errorf("running ssh: %w", err)
	}
	return res, nil
}

// Mask replaces each non-empty secret in s.
func Mask(s string, secrets ...string) string {
	for _, v := range secrets {
		if len(v) >= 4 {
			s = strings.ReplaceAll(s, v, "[REDACTED]")
		}
	}
	return s
}

// Quote returns s as a single-quoted shell word.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// Heredoc returns a shell fragment that writes content to stdout without
// any expansion, using a delimiter that does not occur in content.
func Heredoc(content string) string {
	delim := "FLEET_MCP_EOF"
	for i := 0; strings.Contains(content, delim); i++ {
		delim = fmt.Sprintf("FLEET_MCP_EOF_%d", i)
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return "cat <<'" + delim + "'\n" + content + delim + "\n"
}
