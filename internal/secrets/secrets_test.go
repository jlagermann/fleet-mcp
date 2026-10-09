package secrets

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestStore(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("", RepoToken); err == nil || !strings.Contains(err.Error(), "fleet-mcp secret set repo-token") {
		t.Fatalf("missing secret err = %v", err)
	}
	if err := s.Set("", RepoToken, []byte("abcdef0123456789abcdef\n")); err != nil {
		t.Fatal(err)
	}
	if v, err := s.GetString("", RepoToken); err != nil || v != "abcdef0123456789abcdef" {
		t.Fatalf("got %q %v", v, err)
	}
	if err := s.Set("h1", CommunityString, []byte("c")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("", CommunityString); err == nil {
		t.Fatal("host secret readable without a host")
	}
	if _, err := s.Path("../x", CommunityString); err == nil {
		t.Fatal("path traversal host accepted")
	}
	if _, err := s.Path("", "nope"); err == nil {
		t.Fatal("unknown secret accepted")
	}
	list := s.List("h1")
	present := map[string]bool{}
	for _, st := range list {
		present[st.Name] = st.Present
		if st.Present && st.Fingerprint == "" {
			t.Errorf("%s has no fingerprint", st.Name)
		}
	}
	if !present[RepoToken] || !present[CommunityString] || present[IdentityCert] {
		t.Fatalf("list = %+v", list)
	}
}

func selfSigned(t *testing.T, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fleet.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, DNSNames: []string{"fleet.test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func TestValidateIdentityCert(t *testing.T) {
	c, k := selfSigned(t, time.Now().Add(365*24*time.Hour))
	sum, err := ValidateIdentityCert(append(c, k...))
	if err != nil || !sum.KeyMatches || sum.Subject != "CN=fleet.test" || sum.DaysLeft < 360 {
		t.Fatalf("%+v %v", sum, err)
	}
	if _, err := ValidateIdentityCert(c); err == nil || !strings.Contains(err.Error(), "no private key") {
		t.Fatalf("cert only: %v", err)
	}
	_, k2 := selfSigned(t, time.Now().Add(time.Hour))
	if _, err := ValidateIdentityCert(append(c, k2...)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong key: %v", err)
	}
	old, oldKey := selfSigned(t, time.Now().Add(-time.Hour))
	if _, err := ValidateIdentityCert(append(old, oldKey...)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: %v", err)
	}
	if _, err := ValidateIdentityCert([]byte("junk")); err == nil {
		t.Fatal("junk accepted")
	}
}

func TestValidateRepoToken(t *testing.T) {
	if err := ValidateRepoToken("a6d18e958feea5bc9b07f1d8b377492c2ca4e9656b2140cc"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"short", "has space in it 1234", "abc$(rm -rf)1234567890", strings.Repeat("a", 200)} {
		if ValidateRepoToken(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
