package config

import (
	"strings"
	"testing"
	"time"
)

func TestFromEnvRequired(t *testing.T) {
	// No Fleet Manager at all is valid: host and secret tools only.
	t.Setenv(EnvURL, "")
	t.Setenv(EnvUsername, "")
	t.Setenv(EnvProfile, "")
	c, err := FromEnv()
	if err != nil || c.FleetConfigured() {
		t.Fatalf("no URL: %+v, %v", c, err)
	}
	// A URL needs a username.
	t.Setenv(EnvURL, "fleet.example.com")
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), EnvUsername) {
		t.Fatalf("err = %v", err)
	}
	// URL and profile are exclusive.
	t.Setenv(EnvUsername, "u")
	t.Setenv(EnvProfile, "h")
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), EnvProfile) {
		t.Fatalf("err = %v", err)
	}
}

func TestFromEnvDefaultsAndOverrides(t *testing.T) {
	t.Setenv(EnvURL, "fleet.example.com")
	t.Setenv(EnvUsername, "mcp")
	t.Setenv(EnvPasswordFile, "")
	t.Setenv(EnvSpecDir, "")
	t.Setenv(EnvInsecure, "true")
	t.Setenv(EnvMaxBytes, "1234")
	t.Setenv(EnvTimeout, "5s")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(c.PasswordFile, "fm-password.txt") || !strings.HasSuffix(c.SpecDir, "spec") {
		t.Errorf("defaults: %+v", c)
	}
	if !c.InsecureSkipVerify || c.MaxResponseBytes != 1234 || c.Timeout != 5*time.Second {
		t.Errorf("overrides: %+v", c)
	}
}

func TestFromEnvBadValues(t *testing.T) {
	t.Setenv(EnvURL, "x")
	t.Setenv(EnvUsername, "y")
	t.Setenv(EnvInsecure, "maybe")
	t.Setenv(EnvTimeout, "soon")
	if _, err := FromEnv(); err == nil {
		t.Fatal("bad values accepted")
	}
}
