package sensorssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeSensor is an SSH server that accepts diag-shell with one password
// and echoes each command it is asked to run.
func fakeSensor(t *testing.T, password string, authorized ...ssh.PublicKey) (addr string, fingerprint string, commands chan string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if c.User() == User && string(p) == password {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.PublicKeyCallback = func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		for _, a := range authorized {
			if c.User() == User && bytes.Equal(a.Marshal(), k.Marshal()) {
				return nil, nil
			}
		}
		return nil, errors.New("denied")
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	commands = make(chan string, 4)
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					ch, creqs, _ := nch.Accept()
					go func() {
						for r := range creqs {
							if r.Type == "exec" {
								cmd := string(r.Payload[4:])
								commands <- cmd
								r.Reply(true, nil)
								ch.Write([]byte("updated " + cmd + "\n"))
								ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								ch.Close()
								return
							}
							r.Reply(false, nil)
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey()), commands
}

func TestMoveCommandFlow(t *testing.T) {
	addr, fp, commands := fakeSensor(t, "pw-123")
	pins := Pins{Path: filepath.Join(t.TempDir(), "known")}
	ctx := context.Background()

	hk, err := ScanHostKey(ctx, addr, pins)
	if err != nil || hk.Fingerprint != fp || hk.Known {
		t.Fatalf("scan: %+v %v", hk, err)
	}
	out, err := Run(ctx, addr, Auth{Password: "pw-123"}, fp, "corelight-client configuration update --fleet.community_string='CS-SECRET'", pins, "CS-SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "CS-SECRET") || !strings.Contains(out, "[REDACTED]") {
		t.Errorf("output not masked: %q", out)
	}
	if got := <-commands; !strings.Contains(got, "CS-SECRET") {
		t.Errorf("command %q", got)
	}
	// Pinned now.
	if hk, _ := ScanHostKey(ctx, addr, pins); !hk.Known {
		t.Error("host key not pinned")
	}
	// Wrong password and wrong fingerprint are refused.
	if _, err := Run(ctx, addr, Auth{Password: "wrong"}, fp, "true", pins); err == nil {
		t.Error("wrong password accepted")
	}
	if _, err := Run(ctx, addr, Auth{Password: "pw-123"}, "SHA256:other", "true", pins); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("wrong host key: %v", err)
	}
	// A different pinned key is reported as changed.
	if err := pins.Pin(addr, "SHA256:old"); err != nil {
		t.Fatal(err)
	}
	if hk, _ := ScanHostKey(ctx, addr, pins); !hk.Changed {
		t.Error("changed key not reported")
	}
}

func TestKeyLogin(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "sensor-ssh-key")
	line, err := NewKey(keyPath, "fleet-mcp@test")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := PublicKey(keyPath); got != line {
		t.Errorf("PublicKey %q, want %q", got, line)
	}
	addr, fp, _ := fakeSensor(t, "pw-123", pub)
	pins := Pins{Path: filepath.Join(t.TempDir(), "known")}
	ctx := context.Background()
	// The key alone is enough.
	if _, err := Run(ctx, addr, Auth{KeyPath: keyPath}, fp, "true", pins); err != nil {
		t.Fatalf("key login: %v", err)
	}
	// A key the sensor does not know falls back to the password.
	other := filepath.Join(t.TempDir(), "other")
	if _, err := NewKey(other, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx, addr, Auth{KeyPath: other, Password: "pw-123"}, fp, "true", pins); err != nil {
		t.Fatalf("password fallback: %v", err)
	}
	if _, err := Run(ctx, addr, Auth{KeyPath: other}, fp, "true", pins); err == nil {
		t.Error("unknown key accepted")
	}
	if _, err := Run(ctx, addr, Auth{}, fp, "true", pins); err == nil {
		t.Error("no credentials accepted")
	}
}
