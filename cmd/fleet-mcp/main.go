// Command fleet-mcp is an MCP server for Corelight Fleet Manager.
//
//	fleet-mcp [serve]          run the MCP server on stdio (default)
//	fleet-mcp get <path>       GET a REST path and print redacted JSON
//	fleet-mcp gql <query>      run a read-only GraphQL query
//	fleet-mcp spec [-out dir]  download the REST spec and GraphQL schema
//	fleet-mcp version
//
// Settings come from FLEET_MCP_* environment variables; see the README.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/config"
	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/redact"
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
  fleet-mcp [serve]          run the MCP server on stdio
  fleet-mcp get <path>       GET a REST path, print redacted JSON
  fleet-mcp gql <query>      run a read-only GraphQL query
  fleet-mcp spec [-out dir]  download the REST spec and GraphQL schema
  fleet-mcp version
`)
}

func setup() (config.Config, *fleet.Client, error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return cfg, nil, err
	}
	level := slog.LevelInfo
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	// stdout carries the MCP protocol; log to stderr only.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	c, err := fleet.New(fleet.Options{
		BaseURL: cfg.URL, Username: cfg.Username, PasswordFile: cfg.PasswordFile,
		CAFile: cfg.CAFile, InsecureSkipVerify: cfg.InsecureSkipVerify,
		Timeout: cfg.Timeout, UserAgent: "fleet-mcp/" + version,
	})
	return cfg, c, err
}

func logout(c *fleet.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Logout(ctx); err != nil {
		slog.Debug("logout failed", "err", err)
	}
}

func serve() error {
	cfg, c, err := setup()
	if err != nil {
		return err
	}
	defer logout(c)
	if cfg.InsecureSkipVerify {
		slog.Warn("TLS certificate verification is disabled")
	}
	deps := &tools.Deps{
		Client: c, Specs: spec.NewStore(cfg.SpecDir, c), MaxBytes: cfg.MaxResponseBytes,
		EnableWrites: cfg.EnableWrites, User: cfg.Username,
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
		Instructions: tools.Instructions(cfg.EnableWrites),
	})
	tools.Register(s, deps)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	slog.Info("fleet-mcp starting", "version", version, "fleet", c.Host(), "writes", cfg.EnableWrites, "audit_log", deps.Audit.Path())
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
	_, c, err := setup()
	if err != nil {
		return err
	}
	defer logout(c)
	resp, err := c.Get(context.Background(), args[0], nil)
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
	_, c, err := setup()
	if err != nil {
		return err
	}
	defer logout(c)
	resp, err := c.GraphQL(context.Background(), args[0], nil)
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
	cfg, c, err := setup()
	if err != nil {
		return err
	}
	defer logout(c)
	dir := *out
	if dir == "" {
		dir = cfg.SpecDir
	}
	files, err := spec.Pull(context.Background(), c, dir)
	for _, f := range files {
		fmt.Println("wrote", f)
	}
	return err
}
