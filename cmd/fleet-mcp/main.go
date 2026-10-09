// Command fleet-mcp is an MCP server for Corelight Fleet Manager.
//
//	fleet-mcp [serve]                       run the MCP server on stdio (default)
//	fleet-mcp get <path>                    GET a REST path and print redacted JSON
//	fleet-mcp gql <query>                   run a read-only GraphQL query
//	fleet-mcp spec [-out dir]               download the REST spec and GraphQL schema
//	fleet-mcp secret list [host]            show stored secrets (never values)
//	fleet-mcp secret set <name>             set a token or password at a hidden prompt
//	fleet-mcp secret import <name> <file>   import a certificate or license file
//	fleet-mcp host check <host>             check a host's readiness for Fleet Manager
//	fleet-mcp host install <host> [flags]   preview, or with -execute run, an installation
//	fleet-mcp version
//
// Settings come from FLEET_MCP_* environment variables; see the README.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/term"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/config"
	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/host"
	"github.com/jlagermann/fleet-mcp/internal/install"
	"github.com/jlagermann/fleet-mcp/internal/redact"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
	"github.com/jlagermann/fleet-mcp/internal/spec"
	"github.com/jlagermann/fleet-mcp/internal/tools"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "get":
		err = get(args)
	case "gql":
		err = gql(args)
	case "spec":
		err = pullSpec(args)
	case "secret":
		err = secretCmd(args)
	case "host":
		err = hostCmd(args)
	case "version", "-version", "--version":
		fmt.Println("fleet-mcp", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fleet-mcp:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  fleet-mcp [serve]                       run the MCP server on stdio
  fleet-mcp get <path>                    GET a REST path, print redacted JSON
  fleet-mcp gql <query>                   run a read-only GraphQL query
  fleet-mcp spec [-out dir]               download the REST spec and GraphQL schema
  fleet-mcp secret list [host]            show stored secrets (never values)
  fleet-mcp secret set <name>             set a token or password at a hidden prompt
  fleet-mcp secret import <name> <file>   import a certificate or license file
  fleet-mcp host check <host>             check a host's readiness for Fleet Manager
  fleet-mcp host install <host> [flags]   preview an installation; add -execute to run it
  fleet-mcp version
`)
}

type env struct {
	cfg     config.Config
	client  *fleet.Client // nil when no Fleet Manager is configured
	secrets *secrets.Store
}

// setup reads the configuration. needFleet requires a Fleet Manager.
func setup(needFleet bool) (*env, error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return nil, err
	}
	level := slog.LevelInfo
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	// stdout carries the MCP protocol; log to stderr only.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	e := &env{cfg: cfg}
	if cfg.SecretsDir != "" {
		if e.secrets, err = secrets.Open(cfg.SecretsDir); err != nil {
			return nil, err
		}
	}
	if cfg.Profile != "" {
		if e.secrets == nil {
			return nil, errors.New("a profile needs the secret store")
		}
		p, err := install.ReadProfile(e.secrets, cfg.Profile)
		if err != nil {
			return nil, fmt.Errorf("%s=%s: %w", config.EnvProfile, cfg.Profile, err)
		}
		e.cfg.URL, e.cfg.Username, e.cfg.PasswordFile = p.URL, p.Username, p.PasswordFile
		if e.cfg.CertSHA256 == "" && e.cfg.CAFile == "" {
			e.cfg.CertSHA256 = p.CertSHA256
		}
	}
	if !e.cfg.FleetConfigured() {
		if needFleet {
			return nil, fmt.Errorf("set %s and %s, or %s", config.EnvURL, config.EnvUsername, config.EnvProfile)
		}
		return e, nil
	}
	e.client, err = fleet.New(fleet.Options{
		BaseURL: e.cfg.URL, Username: e.cfg.Username, PasswordFile: e.cfg.PasswordFile,
		CAFile: e.cfg.CAFile, InsecureSkipVerify: e.cfg.InsecureSkipVerify, PinSHA256: e.cfg.CertSHA256,
		Timeout: e.cfg.Timeout, UserAgent: "fleet-mcp/" + version,
	})
	return e, err
}

func (e *env) logout() {
	if e.client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.client.Logout(ctx); err != nil {
		slog.Debug("logout failed", "err", err)
	}
}

func serve() error {
	e, err := setup(false)
	if err != nil {
		return err
	}
	defer e.logout()
	cfg := e.cfg
	if cfg.InsecureSkipVerify {
		slog.Warn("TLS certificate verification is disabled")
	}
	deps := &tools.Deps{
		Client: e.client, MaxBytes: cfg.MaxResponseBytes, EnableWrites: cfg.EnableWrites, User: cfg.Username,
		Secrets: e.secrets, SSHUser: cfg.SSHUser, SSHBinary: cfg.SSHBinary,
	}
	if e.client != nil {
		deps.Specs = spec.NewStore(cfg.SpecDir, e.client)
	}
	if cfg.EnableWrites {
		if cfg.AuditLog == "" {
			return fmt.Errorf("%s needs an audit log path (%s)", config.EnvWrites, config.EnvAuditLog)
		}
		if deps.Audit, err = audit.Open(cfg.AuditLog); err != nil {
			return fmt.Errorf("opening audit log: %w", err)
		}
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "fleet-mcp", Version: version}, &mcp.ServerOptions{
		Instructions: tools.Instructions(cfg.EnableWrites, e.client != nil),
	})
	tools.Register(s, deps)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fleetHost := "(none)"
	if e.client != nil {
		fleetHost = e.client.Host()
	}
	slog.Info("fleet-mcp starting", "version", version, "fleet", fleetHost, "writes", cfg.EnableWrites, "audit_log", deps.Audit.Path())
	return s.Run(ctx, &mcp.StdioTransport{})
}

func printJSON(body []byte) error {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		os.Stdout.Write(body)
		return nil
	}
	b, err := json.MarshalIndent(redact.Value(v), "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func get(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: fleet-mcp get <path>")
	}
	if err := tools.CheckGetPath(args[0]); err != nil {
		return err
	}
	e, err := setup(true)
	if err != nil {
		return err
	}
	defer e.logout()
	resp, err := e.client.Get(context.Background(), args[0], nil)
	if err != nil {
		return err
	}
	return printJSON(resp.Body)
}

func gql(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: fleet-mcp gql <query>")
	}
	if err := tools.CheckReadOnlyGraphQL(args[0]); err != nil {
		return err
	}
	e, err := setup(true)
	if err != nil {
		return err
	}
	defer e.logout()
	resp, err := e.client.GraphQL(context.Background(), args[0], nil)
	if err != nil {
		return err
	}
	return printJSON(resp.Body)
}

func pullSpec(args []string) error {
	fs := flag.NewFlagSet("spec", flag.ContinueOnError)
	out := fs.String("out", "", "directory to write to (default FLEET_MCP_SPEC_DIR or ~/.local/share/fleet-mcp/spec)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, err := setup(true)
	if err != nil {
		return err
	}
	defer e.logout()
	dir := *out
	if dir == "" {
		dir = e.cfg.SpecDir
	}
	files, err := spec.Pull(context.Background(), e.client, dir)
	for _, f := range files {
		fmt.Println("wrote", f)
	}
	return err
}

func secretCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: fleet-mcp secret list [host] | set <name> | import <name> <file>")
	}
	e, err := setup(false)
	if err != nil {
		return err
	}
	if e.secrets == nil {
		return errors.New("no secret store directory")
	}
	switch args[0] {
	case "list":
		h := ""
		if len(args) > 1 {
			h = args[1]
		}
		b, _ := json.MarshalIndent(e.secrets.List(h), "", "  ")
		fmt.Println(string(b))
		return nil
	case "set":
		if len(args) != 2 {
			return errors.New("usage: fleet-mcp secret set <name>")
		}
		spec, ok := secrets.Lookup(args[1])
		if !ok || spec.Kind != secrets.Prompt {
			return fmt.Errorf("%q cannot be set at a prompt; prompt secrets are: %s", args[1], promptNames())
		}
		v, err := readSecret(spec)
		if err != nil {
			return err
		}
		if _, err := secrets.Validate(spec.Name, []byte(v)); err != nil {
			return err
		}
		if err := e.secrets.Set("", spec.Name, []byte(v)); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "stored %s\n", spec.Name)
		return nil
	case "import":
		if len(args) != 3 {
			return errors.New("usage: fleet-mcp secret import <name> <file>")
		}
		summary, err := tools.ImportFile(e.secrets, args[1], args[2])
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Printf("stored %s\n%s\n", args[1], b)
		return nil
	}
	return fmt.Errorf("unknown secret command %q", args[0])
}

func promptNames() string {
	var n []string
	for _, s := range secrets.Known {
		if s.Kind == secrets.Prompt {
			n = append(n, s.Name)
		}
	}
	return strings.Join(n, ", ")
}

// readSecret prompts twice without echo when stdin is a terminal, or reads
// one line from stdin otherwise.
func readSecret(spec secrets.Spec) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	fmt.Fprintf(os.Stderr, "%s\n%s: ", spec.Description, spec.Name)
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "again: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", errors.New("the values did not match; nothing stored")
	}
	return strings.TrimSpace(string(a)), nil
}

func hostCmd(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: fleet-mcp host check <host> | install <host> [-ssh-user u] [-version v] [-expose-swagger] [-mcp-user u] [-execute]")
	}
	sub, target := args[0], args[1]
	fs := flag.NewFlagSet("host "+sub, flag.ContinueOnError)
	sshUser := fs.String("ssh-user", "", "SSH user with passwordless sudo")
	sshPort := fs.Int("ssh-port", 0, "SSH port")
	ver := fs.String("version", "", "corelight-fleet version (default newest)")
	swagger := fs.Bool("expose-swagger", false, "set expose-swagger: true")
	mcpUser := fs.String("mcp-user", "", "Fleet Manager user to create for fleet-mcp (default fleet-mcp)")
	url := fs.String("url", "", "URL to reach Fleet Manager (default https://<host>)")
	execute := fs.Bool("execute", false, "run the installation (default: preview only)")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	e, err := setup(false)
	if err != nil {
		return err
	}
	user := *sshUser
	if user == "" {
		user = e.cfg.SSHUser
	}
	r, err := host.NewSSH(target, user, *sshPort)
	if err != nil {
		return err
	}
	r.Binary = e.cfg.SSHBinary
	ctx := context.Background()
	switch sub {
	case "check":
		rep, err := install.Check(ctx, r)
		if err != nil {
			return err
		}
		for _, f := range rep.Findings {
			fmt.Printf("%-5s %-17s %s\n", f.Level, f.Check, f.Detail)
		}
		fmt.Printf("ready: %v\n", rep.Ready)
		return nil
	case "install":
		if e.secrets == nil {
			return errors.New("no secret store directory")
		}
		opts := install.Options{Version: *ver, MCPUser: *mcpUser, URL: *url}
		if *swagger {
			opts.ExposeSwagger = swagger
		}
		in := &install.Installer{R: r, Secrets: e.secrets, Host: target, Opts: opts, Bootstrap: &install.APIBootstrap{UserAgent: "fleet-mcp/" + version}}
		var steps []install.StepStatus
		var runErr error
		if *execute {
			steps, runErr = in.Execute(ctx)
			if e.cfg.AuditLog != "" {
				if log, err := audit.Open(e.cfg.AuditLog); err == nil {
					rec := audit.Record{Fleet: target, User: r.Name(), Tool: "cli host install", Body: map[string]any{"options": opts, "steps": steps}}
					if runErr != nil {
						rec.Error = runErr.Error()
					}
					if err := log.Write(rec); err != nil {
						fmt.Fprintln(os.Stderr, "warning: audit log:", err)
					}
				}
			}
		} else {
			steps, runErr = in.Plan(ctx)
		}
		for _, s := range steps {
			fmt.Printf("%-8s %-14s %s", s.State, s.Step, s.What)
			if s.Detail != "" {
				fmt.Printf("\n%25s%s", "", s.Detail)
			}
			fmt.Println()
		}
		if runErr == nil && *execute {
			if p, err := install.ReadProfile(e.secrets, target); err == nil {
				fmt.Printf("\nprofile: %s user %s (manage it with %s=%s)\n", p.URL, p.Username, config.EnvProfile, target)
			}
		}
		return runErr
	}
	return fmt.Errorf("unknown host command %q", sub)
}
