// Package sensorssh runs commands on a Corelight Sensor over SSH with a
// password, as its diag-shell user. Host keys are pinned in fleet-mcp's own
// known_hosts file: the first contact reports the key's fingerprint for the
// user to approve, and later contacts must present the same key.
package sensorssh

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// User is the sensor account used for diagnostics and fleet changes.
const User = "diag-shell"

// HostKey describes a sensor's SSH host key.
type HostKey struct {
	Fingerprint string `json:"fingerprint"` // SHA256:...
	Type        string `json:"type"`
	// Known is set when the key is already pinned for this host.
	Known bool `json:"known"`
	// Changed is set when a different key is pinned: possibly a reinstalled
	// sensor, possibly an attack. Connecting is refused.
	Changed bool `json:"changed,omitempty"`
}

// Pins is a known_hosts-style file: "host fingerprint" per line.
type Pins struct{ Path string }

func (p Pins) load() (map[string]string, error) {
	out := map[string]string{}
	f, err := os.Open(p.Path)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if host, fp, ok := strings.Cut(strings.TrimSpace(sc.Text()), " "); ok && !strings.HasPrefix(host, "#") {
			out[host] = strings.TrimSpace(fp)
		}
	}
	return out, sc.Err()
}

// Pin records host's key fingerprint.
func (p Pins) Pin(host, fingerprint string) error {
	pins, err := p.load()
	if err != nil {
		return err
	}
	if pins[host] == fingerprint {
		return nil
	}
	pins[host] = fingerprint
	if err := os.MkdirAll(filepath.Dir(p.Path), 0o700); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# Corelight Sensor SSH host keys pinned by fleet-mcp\n")
	for h, fp := range pins {
		fmt.Fprintf(&b, "%s %s\n", h, fp)
	}
	return os.WriteFile(p.Path, []byte(b.String()), 0o600)
}

func addr(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "22")
}

// ScanHostKey connects without authenticating and returns the host key.
func ScanHostKey(ctx context.Context, host string, pins Pins) (*HostKey, error) {
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: User,
		Auth: []ssh.AuthMethod{},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errors.New("host key captured")
		},
		Timeout: 15 * time.Second,
	}
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr(host))
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", host, err)
	}
	defer conn.Close()
	_, _, _, _ = ssh.NewClientConn(conn, addr(host), cfg)
	if got == nil {
		return nil, fmt.Errorf("%s did not present an SSH host key", host)
	}
	hk := &HostKey{Fingerprint: ssh.FingerprintSHA256(got), Type: got.Type()}
	pinned, err := pins.load()
	if err != nil {
		return nil, err
	}
	switch fp, ok := pinned[host]; {
	case ok && fp == hk.Fingerprint:
		hk.Known = true
	case ok:
		hk.Changed = true
	}
	return hk, nil
}

// Run logs in as diag-shell with password and runs command. The host key
// must match fingerprint, which is then pinned. Every secret is masked in
// the returned output.
func Run(ctx context.Context, host, password, fingerprint, command string, pins Pins, secrets ...string) (string, error) {
	cfg := &ssh.ClientConfig{
		User: User,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			// Some sensors offer keyboard-interactive instead of password.
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if got := ssh.FingerprintSHA256(key); got != fingerprint {
				return fmt.Errorf("host key %s does not match the approved %s", got, fingerprint)
			}
			return nil
		},
		Timeout: 20 * time.Second,
	}
	d := net.Dialer{Timeout: 20 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr(host))
	if err != nil {
		return "", fmt.Errorf("connecting to %s: %w", host, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr(host), cfg)
	if err != nil {
		conn.Close()
		return "", fmt.Errorf("SSH login to %s as %s: %w", host, User, err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	if err := pins.Pin(host, fingerprint); err != nil {
		return "", err
	}
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out := &lockedBuffer{}
	sess.Stdout, sess.Stderr = out, out
	done := make(chan error, 1)
	go func() { done <- sess.Run(command) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(2 * time.Minute):
		return mask(out.String(), secrets), errors.New("the command did not finish within 2 minutes")
	}
	text := mask(out.String(), secrets)
	if err != nil {
		return text, fmt.Errorf("on %s: %w", host, err)
	}
	return text, nil
}

func mask(s string, secrets []string) string {
	for _, v := range secrets {
		if v != "" {
			s = strings.ReplaceAll(s, v, "[REDACTED]")
		}
	}
	return s
}

// lockedBuffer is written by the stdout and stderr copiers at once.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
