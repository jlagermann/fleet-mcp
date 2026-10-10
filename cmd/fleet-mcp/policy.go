package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/term"

	"github.com/jlagermann/fleet-mcp/internal/config"
	"github.com/jlagermann/fleet-mcp/internal/migrate"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
)

// policyCmd handles "fleet-mcp policy ...".
func policyCmd(args []string) error {
	if len(args) < 2 || args[0] != "tokens" {
		return errors.New("usage: fleet-mcp policy tokens <package> [-all]")
	}
	fs := flag.NewFlagSet("policy tokens", flag.ContinueOnError)
	all := fs.Bool("all", false, "ask for every secret, also those already entered")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	return policyTokens(args[1], *all)
}

// policyTokens asks, at a hidden prompt, for the secrets (exporter tokens)
// a policy package needs, and stores them in the package's secrets file.
func policyTokens(pkg string, all bool) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("run this in a terminal: the tokens are typed at a hidden prompt")
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if !migrate.ValidPackageName(pkg) {
		return fmt.Errorf("invalid package name %q", pkg)
	}
	dir := filepath.Join(cfg.PackagesDir, pkg)
	m, _, err := migrate.ReadManifest(dir)
	if err != nil {
		return err
	}
	need := m.Secrets()
	if !all {
		if need, err = migrate.MissingSecrets(dir, m); err != nil {
			return err
		}
	}
	if len(need) == 0 {
		fmt.Fprintln(os.Stderr, "Every secret this package needs is already entered (use -all to enter them again).")
		return nil
	}
	fmt.Fprintf(os.Stderr, "Policy %q from %s needs %d secrets that Fleet Manager's API never returns.\nPress Enter on an empty prompt to skip one.\n\n", m.Policy.Name, m.Source.Fleet, len(need))
	stored := 0
	for _, s := range need {
		v, err := readSecret(secrets.Spec{Name: s.Key, Description: s.Label})
		if err != nil {
			return fmt.Errorf("%s: %w", s.Label, err)
		}
		if v == "" {
			fmt.Fprintln(os.Stderr, "skipped")
			continue
		}
		if err := migrate.AddSecrets(dir, map[string]string{s.Key: v}); err != nil {
			return err
		}
		stored++
		fmt.Fprintln(os.Stderr, "stored")
	}
	fmt.Fprintf(os.Stderr, "\n%d of %d stored in %s (readable only by you; deleted after the import).\n", stored, len(need), filepath.Join(dir, migrate.SecretsFile))
	return nil
}
