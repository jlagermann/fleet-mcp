// Package config reads fleet-mcp settings from the environment.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Environment variable names.
const (
	EnvURL          = "FLEET_MCP_URL"
	EnvUsername     = "FLEET_MCP_USERNAME"
	EnvPasswordFile = "FLEET_MCP_PASSWORD_FILE"
	EnvCAFile       = "FLEET_MCP_CA_FILE"
	EnvInsecure     = "FLEET_MCP_INSECURE_SKIP_VERIFY"
	EnvSpecDir      = "FLEET_MCP_SPEC_DIR"
	EnvMaxBytes     = "FLEET_MCP_MAX_RESPONSE_BYTES"
	EnvTimeout      = "FLEET_MCP_TIMEOUT"
	EnvLogLevel     = "FLEET_MCP_LOG_LEVEL"
	EnvWrites       = "FLEET_MCP_ENABLE_WRITES"
	EnvAuditLog     = "FLEET_MCP_AUDIT_LOG"
	EnvCertSHA256   = "FLEET_MCP_CERT_SHA256"
	EnvProfile      = "FLEET_MCP_PROFILE"
	EnvSecretsDir   = "FLEET_MCP_SECRETS_DIR"
	EnvSSHUser      = "FLEET_MCP_SSH_USER"
	EnvSSHBinary    = "FLEET_MCP_SSH"
	EnvFleetsFile   = "FLEET_MCP_FLEETS_FILE"
	EnvDefaultFleet = "FLEET_MCP_DEFAULT_FLEET"
	EnvPackagesDir  = "FLEET_MCP_PACKAGES_DIR"
	EnvDemoMetrics  = "FLEET_MCP_DEMO_METRICS"
)

// Config holds fleet-mcp settings.
type Config struct {
	URL                string
	Username           string
	PasswordFile       string
	CAFile             string
	InsecureSkipVerify bool
	SpecDir            string
	MaxResponseBytes   int
	Timeout            time.Duration
	LogLevel           string
	EnableWrites       bool
	AuditLog           string
	// CertSHA256 pins the Fleet Manager certificate instead of verifying a chain.
	CertSHA256 string
	// Profile names a host whose installer-written profile supplies URL,
	// username, password file and pinned certificate.
	Profile    string
	SecretsDir string
	SSHUser    string
	SSHBinary  string
	// FleetsFile lists Fleet Managers fleet-mcp did not install.
	FleetsFile string
	// DefaultFleet names the Fleet Manager tools use when none is given.
	DefaultFleet string
	// PackagesDir holds exported policy packages.
	PackagesDir string
	// DemoMetrics appends timing and size metrics to every tool result.
	DemoMetrics bool
}

// FleetConfigured reports whether a Fleet Manager API connection is set up.
func (c Config) FleetConfigured() bool { return c.URL != "" }

// DataDir is the per-user fleet-mcp directory: ~/.local/share/fleet-mcp.
func DataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "fleet-mcp")
}

// FromEnv reads the configuration. Unset optional values get defaults.
func FromEnv() (Config, error) {
	c := Config{
		URL:          strings.TrimSpace(os.Getenv(EnvURL)),
		Username:     strings.TrimSpace(os.Getenv(EnvUsername)),
		PasswordFile: os.Getenv(EnvPasswordFile),
		CAFile:       os.Getenv(EnvCAFile),
		SpecDir:      os.Getenv(EnvSpecDir),
		LogLevel:     os.Getenv(EnvLogLevel),
		Timeout:      60 * time.Second,
		CertSHA256:   strings.TrimSpace(os.Getenv(EnvCertSHA256)),
		Profile:      strings.TrimSpace(os.Getenv(EnvProfile)),
		SecretsDir:   os.Getenv(EnvSecretsDir),
		SSHUser:      strings.TrimSpace(os.Getenv(EnvSSHUser)),
		SSHBinary:    os.Getenv(EnvSSHBinary),
	}
	var errs []error
	// Without a URL or profile the server runs with host and secret tools only.
	if c.URL != "" && c.Username == "" {
		errs = append(errs, fmt.Errorf("%s is required with %s (a local Fleet Manager user without 2FA)", EnvUsername, EnvURL))
	}
	if c.URL != "" && c.Profile != "" {
		errs = append(errs, fmt.Errorf("set %s or %s, not both", EnvURL, EnvProfile))
	}
	c.FleetsFile = os.Getenv(EnvFleetsFile)
	c.DefaultFleet = strings.TrimSpace(os.Getenv(EnvDefaultFleet))
	if c.FleetsFile == "" {
		if d := DataDir(); d != "" {
			c.FleetsFile = filepath.Join(d, "fleets.json")
		}
	}
	if c.SecretsDir == "" {
		if d := DataDir(); d != "" {
			c.SecretsDir = filepath.Join(d, "secrets")
		}
	}
	if c.PasswordFile == "" {
		if d := DataDir(); d != "" {
			c.PasswordFile = filepath.Join(d, "fm-password.txt")
		}
	}
	if c.SpecDir == "" {
		if d := DataDir(); d != "" {
			c.SpecDir = filepath.Join(d, "spec")
		}
	}
	c.PackagesDir = os.Getenv(EnvPackagesDir)
	if c.PackagesDir == "" {
		if d := DataDir(); d != "" {
			c.PackagesDir = filepath.Join(d, "packages")
		}
	}
	c.AuditLog = os.Getenv(EnvAuditLog)
	if c.AuditLog == "" {
		if d := DataDir(); d != "" {
			c.AuditLog = filepath.Join(d, "audit.jsonl")
		}
	}
	for name, dst := range map[string]*bool{EnvInsecure: &c.InsecureSkipVerify, EnvWrites: &c.EnableWrites, EnvDemoMetrics: &c.DemoMetrics} {
		if v := os.Getenv(name); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
			}
			*dst = b
		}
	}
	if v := os.Getenv(EnvMaxBytes); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			errs = append(errs, fmt.Errorf("%s must be a positive integer", EnvMaxBytes))
		}
		c.MaxResponseBytes = n
	}
	if v := os.Getenv(EnvTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvTimeout, err))
		}
		c.Timeout = d
	}
	return c, errors.Join(errs...)
}
