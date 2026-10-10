// Package sensorssh runs commands on a Corelight Sensor over SSH with a
// password, as its diag-shell user. Host keys are pinned in fleet-mcp's own
// known_hosts file: the first contact reports the key's fingerprint for the
// user to approve, and later contacts must present the same key.
package sensorssh

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
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
func Run(ctx context.Context, host string, auth Auth, fingerprint, command string, pins Pins, secrets ...string) (string, error) {
	methods, err := auth.methods()
	if err != nil {
		return "", err
	}
	cfg := &ssh.ClientConfig{
		User: User,
		Auth: methods,
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

// Auth is how fleet-mcp logs in as diag-shell: with its own key (installed
// on the sensor as security.user.admin.ssh_public_key), with the admin
// password, or with the key first and the password as a fallback.
type Auth struct {
	// KeyPath is an OpenSSH private key file without a passphrase.
	KeyPath  string
	Password string
}

func (a Auth) methods() ([]ssh.AuthMethod, error) {
	var m []ssh.AuthMethod
	if a.KeyPath != "" {
		b, err := os.ReadFile(a.KeyPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err == nil {
			signer, err := ssh.ParsePrivateKey(b)
			if err != nil {
				return nil, fmt.Errorf("SSH key %s: %w", a.KeyPath, err)
			}
			m = append(m, ssh.PublicKeys(signer))
		}
	}
	if a.Password != "" {
		pw := a.Password
		m = append(m, ssh.Password(pw),
			// Some sensors offer keyboard-interactive instead of password.
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			}))
	}
	if len(m) == 0 {
		return nil, errors.New("no SSH key or password to log in to the sensor with")
	}
	return m, nil
}

// NewKey creates an ed25519 key pair for fleet-mcp and writes the private
// key (OpenSSH format, no passphrase, mode 0600) to path. It returns the
// public key line.
func NewKey(path, comment string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + comment
	return line, os.WriteFile(path+".pub", []byte(line+"\n"), 0o644)
}

// PublicKey returns the public key line for the private key at path.
func PublicKey(path string) (string, error) {
	if b, err := os.ReadFile(path + ".pub"); err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}
