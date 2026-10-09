package secrets

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// CertSummary describes a certificate without exposing its key.
type CertSummary struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	DNSNames    []string  `json:"dns_names,omitempty"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DaysLeft    int       `json:"days_left"`
	SHA256      string    `json:"sha256"`
	HasKey      bool      `json:"has_private_key"`
	KeyMatches  bool      `json:"key_matches_certificate"`
	Certificates int      `json:"certificates_in_file"`
}

// InspectPEM summarizes the first certificate in b and checks for a
// matching private key.
func InspectPEM(b []byte) (*CertSummary, error) {
	var certs []*x509.Certificate
	hasKey := false
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch {
		case blk.Type == "CERTIFICATE":
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing certificate: %w", err)
			}
			certs = append(certs, c)
		case strings.HasSuffix(blk.Type, "PRIVATE KEY"):
			if strings.Contains(blk.Type, "ENCRYPTED") {
				return nil, errors.New("the private key is encrypted; Fleet Manager needs an unencrypted key")
			}
			hasKey = true
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM certificate found")
	}
	c := certs[0]
	sum := sha256.Sum256(c.Raw)
	s := &CertSummary{
		Subject: c.Subject.String(), Issuer: c.Issuer.String(), DNSNames: c.DNSNames,
		NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(),
		DaysLeft:     int(time.Until(c.NotAfter).Hours() / 24),
		SHA256:       hex.EncodeToString(sum[:]),
		HasKey:       hasKey,
		Certificates: len(certs),
	}
	if hasKey {
		_, err := tls.X509KeyPair(b, b)
		s.KeyMatches = err == nil
	}
	return s, nil
}

// ValidateIdentityCert checks a Fleet Manager product identity certificate.
func ValidateIdentityCert(b []byte) (*CertSummary, error) {
	s, err := InspectPEM(b)
	if err != nil {
		return nil, err
	}
	switch {
	case !s.HasKey:
		return s, errors.New("the file has no private key; the product identity certificate (.pem) from Corelight contains both")
	case !s.KeyMatches:
		return s, errors.New("the private key does not match the certificate")
	case time.Now().After(s.NotAfter):
		return s, fmt.Errorf("the certificate expired on %s", s.NotAfter.Format("2006-01-02"))
	}
	return s, nil
}

var repoToken = regexp.MustCompile(`^[A-Za-z0-9]{16,128}$`)

// ValidateRepoToken checks the shape of a package repository token.
func ValidateRepoToken(t string) error {
	if !repoToken.MatchString(t) {
		return errors.New("a repository token is 16-128 letters and digits")
	}
	return nil
}

// ValidateCommunityString applies the documented rules: at least one
// character and no quote characters. Whitespace and control characters are
// also refused.
func ValidateCommunityString(s string) error {
	if s == "" {
		return errors.New("the community string must not be empty")
	}
	for _, r := range s {
		if r == '"' || r == '\'' || r <= ' ' || r == 0x7f {
			return errors.New("the community string must not contain quotes, spaces or control characters")
		}
	}
	return nil
}

// Validate checks a value before it is stored.
func Validate(name string, b []byte) (any, error) {
	switch name {
	case IdentityCert:
		return ValidateIdentityCert(b)
	case RepoToken:
		return nil, ValidateRepoToken(strings.TrimSpace(string(b)))
	case CommunityString:
		return nil, ValidateCommunityString(strings.TrimSpace(string(b)))
	case SensorLicense:
		if len(strings.TrimSpace(string(b))) == 0 {
			return nil, errors.New("the license file is empty")
		}
		return map[string]any{"bytes": len(b)}, nil
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, errors.New("empty value")
	}
	return nil, nil
}
