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
}

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
	}
	var errs []error
	if c.URL == "" {
		errs = append(errs, fmt.Errorf("%s is required (e.g. https://fleet.example.com)", EnvURL))
	}
	if c.Username == "" {
		errs = append(errs, fmt.Errorf("%s is required (a local Fleet Manager user without 2FA)", EnvUsername))
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
	if v := os.Getenv(EnvInsecure); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvInsecure, err))
		}
		c.InsecureSkipVerify = b
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
