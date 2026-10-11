// Command fleet-mcp is an MCP server for Corelight Fleet Manager.
//
//	fleet-mcp [stdio]                       run the MCP server on stdio, for local MCP clients (default; "serve" also works)
//	fleet-mcp get <path>                    GET a REST path and print redacted JSON
//	fleet-mcp gql <query>                   run a read-only GraphQL query
//	fleet-mcp spec [-out dir]               download the REST spec and GraphQL schema
//	fleet-mcp secret list [host]            show stored secrets (never values)
//	fleet-mcp secret set <name> [-host h]   set a token or community string at a hidden prompt
//	fleet-mcp secret show <name> -host h    print a community string in your terminal (-copy: clipboard)
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
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/term"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/config"
	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/fleets"
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
	cmd := "stdio"
	args := os.Args[1:]
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "stdio", "serve": // serve: earlier name, kept for existing registrations
		err = serve()
	case "get":
		err = get(args)
	case "gql":
		err = gql(args)
	case "spec":
		err = pullSpec(args)
	case "fleets":
		err = fleetsCmd(args)
	case "secret":
		err = secretCmd(args)
	case "host":
		err = hostCmd(args)
	case "policy":
		err = policyCmd(args)
	case "report":
		err = reportCmd(args)
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
  fleet-mcp [stdio]                       run the MCP server on stdio for a local MCP client (default)
  fleet-mcp fleets [-check]               list the Fleet Managers this server can manage
  fleet-mcp get [-fleet n] <path>         GET a REST path, print redacted JSON
  fleet-mcp gql [-fleet n] <query>        run a read-only GraphQL query
  fleet-mcp spec [-fleet n] [-out dir]    download the REST spec and GraphQL schema
  fleet-mcp secret list [host]            show stored secrets (never values)
  fleet-mcp secret set <name> [-host h]   set a token or community string at a hidden prompt
  fleet-mcp secret show <name> -host h    print a community string in your terminal (-copy: clipboard)
  fleet-mcp secret import <name> <file>   import a certificate or license file
  fleet-mcp secret set-setting <name>    store a write-only policy setting (proxy password, S3 key, exporter token) for fm_policy_create
  fleet-mcp host checklist <host>         everything to provide before an install, with status
  fleet-mcp host check <host>             check a host's readiness for Fleet Manager
  fleet-mcp host install <host> [flags]   preview an installation; add -execute to run it
  fleet-mcp policy tokens <package>       enter exporter tokens a policy package needs, at a hidden prompt
  fleet-mcp report [-timeline] <session.jsonl>   per fleet-mcp tool call: time and AI tokens, from a Claude Code transcript
  fleet-mcp version
`)
}

type env struct {
	cfg     config.Config
	fleets  *fleets.Registry
	secrets *secrets.Store
}

// setup reads the configuration and builds the Fleet Manager registry.
func setup() (*env, error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return nil, err
	}
	level := slog.LevelInfo
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	// stdout carries the MCP protocol; log to stderr only.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	e := &env{cfg: cfg}
	opts := fleets.Options{
		FleetsFile: cfg.FleetsFile, SpecDir: cfg.SpecDir, DefaultName: cfg.DefaultFleet,
		Timeout: cfg.Timeout, UserAgent: "fleet-mcp/" + version,
	}
	if cfg.SecretsDir != "" {
		if e.secrets, err = secrets.Open(cfg.SecretsDir); err != nil {
			return nil, err
		}
		opts.ProfilesDir = filepath.Join(e.secrets.Dir(), "hosts")
	}
	switch {
	case cfg.Profile != "":
		// The installed profile is found by the registry; make it the default.
		if opts.DefaultName == "" {
			opts.DefaultName = strings.ToLower(cfg.Profile)
		}
	case cfg.URL != "":
		u, err := fleet.ParseBaseURL(cfg.URL)
		if err != nil {
			return nil, err
		}
		opts.Env = &fleets.Fleet{
			Name: u.Hostname(), URL: cfg.URL, Username: cfg.Username, PasswordFile: cfg.PasswordFile,
			CertSHA256: cfg.CertSHA256, CAFile: cfg.CAFile, InsecureSkipVerify: cfg.InsecureSkipVerify,
		}
	}
	e.fleets = fleets.New(opts)
	return e, nil
}

func (e *env) logout() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, c := range e.fleets.Conns() {
		if err := c.Client.Logout(ctx); err != nil {
			slog.Debug("logout failed", "fleet", c.Name, "err", err)
		}
	}
}

func serve() error {
	e, err := setup()
	if err != nil {
		return err
	}
	defer e.logout()
	cfg := e.cfg
	if cfg.InsecureSkipVerify {
		slog.Warn("TLS certificate verification is disabled")
	}
	deps := &tools.Deps{
		Fleets: e.fleets, MaxBytes: cfg.MaxResponseBytes, EnableWrites: cfg.EnableWrites,
		Secrets: e.secrets, SSHUser: cfg.SSHUser, SSHBinary: cfg.SSHBinary, PackagesDir: cfg.PackagesDir,
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
	if cfg.DemoMetrics {
		s.AddReceivingMiddleware(tools.DemoMetrics())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	list, warns := e.fleets.List()
	names := make([]string, len(list))
	for i, f := range list {
		names[i] = f.Name
	}
	for _, w := range warns {
		slog.Warn("fleet configuration", "problem", w)
	}
	slog.Info("fleet-mcp starting", "version", version, "fleets", strings.Join(names, ","), "writes", cfg.EnableWrites, "audit_log", deps.Audit.Path())
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

// fleetCmd parses "-fleet name" and returns the remaining arguments and
// the chosen Fleet Manager.
func fleetCmd(name string, args []string, wantArgs int, usageLine string) (*env, *fleets.Conn, []string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fleetName := fs.String("fleet", "", "Fleet Manager to use (see fleet-mcp fleets); default: the default one")
	out := fs.String("out", "", "spec only: directory to write to")
	if err := fs.Parse(args); err != nil {
		return nil, nil, nil, err
	}
	rest := fs.Args()
	if wantArgs >= 0 && len(rest) != wantArgs {
		return nil, nil, nil, errors.New("usage: " + usageLine)
	}
	if *out != "" {
		rest = append(rest, *out)
	}
	e, err := setup()
	if err != nil {
		return nil, nil, nil, err
	}
	c, err := e.fleets.Get(*fleetName)
	if err != nil {
		return nil, nil, nil, err
	}
	return e, c, rest, nil
}

func get(args []string) error {
	e, c, rest, err := fleetCmd("get", args, 1, "fleet-mcp get [-fleet name] <path>")
	if err != nil {
		return err
	}
	defer e.logout()
	if err := tools.CheckGetPath(rest[0]); err != nil {
		return err
	}
	resp, err := c.Client.Get(context.Background(), rest[0], nil)
	if err != nil {
		return err
	}
	return printJSON(resp.Body)
}

func gql(args []string) error {
	e, c, rest, err := fleetCmd("gql", args, 1, "fleet-mcp gql [-fleet name] <query>")
	if err != nil {
		return err
	}
	defer e.logout()
	if err := tools.CheckReadOnlyGraphQL(rest[0]); err != nil {
		return err
	}
	resp, err := c.Client.GraphQL(context.Background(), rest[0], nil)
	if err != nil {
		return err
	}
	return printJSON(resp.Body)
}

func pullSpec(args []string) error {
	e, c, rest, err := fleetCmd("spec", args, 0, "fleet-mcp spec [-fleet name] [-out dir]")
	if err != nil {
		return err
	}
	defer e.logout()
	dir := e.cfg.SpecDir
	if len(rest) == 1 {
		dir = rest[0]
	}
	files, err := spec.Pull(context.Background(), c.Client, dir)
	for _, f := range files {
		fmt.Println("wrote", f)
	}
	return err
}

func fleetsCmd(args []string) error {
	fs := flag.NewFlagSet("fleets", flag.ContinueOnError)
	check := fs.Bool("check", false, "log in to each and show its version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, err := setup()
	if err != nil {
		return err
	}
	defer e.logout()
	list, warns := e.fleets.List()
	if len(list) == 0 {
		fmt.Println("no Fleet Managers configured")
	}
	for _, f := range list {
		flags := []string{}
		if f.Default {
			flags = append(flags, "default")
		}
		if f.ReadOnly {
			flags = append(flags, "read-only")
		}
		status := ""
		if *check {
			if c, err := e.fleets.Get(f.Name); err != nil {
				status = "error: " + err.Error()
			} else if v, err := spec.Version(context.Background(), c.Client); err != nil {
				status = "unreachable: " + err.Error()
			} else {
				status = "ok " + v
			}
		}
		fmt.Printf("%-18s %-34s %-10s %-18s %s  [%s]\n", f.Name, f.URL, f.Username, strings.Join(flags, ","), status, f.Source)
	}
	for _, w := range warns {
		fmt.Println("warning:", w)
	}
	return nil
}

func secretCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: fleet-mcp secret list [host] | set <name> | import <name> <file>")
	}
	e, err := setup()
	if err != nil {
		return err
	}
	if e.secrets == nil {
		return errors.New("no secret store directory")
	}
	switch args[0] {
	case "set-setting":
		// A write-only policy setting for fm_policy_create: proxy password,
		// S3 secret key, or exporter:<exporter name>:<field>.
		if len(args) != 2 {
			return errors.New("usage: fleet-mcp secret set-setting <name>   (e.g. network.management.proxy.password, or \"exporter:<exporter name>:hec_token\")")
		}
		v, err := readSecret(secrets.Spec{Name: args[1], Description: "Value for the sensor policy setting " + args[1] + " (used by fm_policy_create, then deleted)"})
		if err != nil {
			return err
		}
		if v == "" {
			return errors.New("nothing stored: the value is empty")
		}
		if err := e.secrets.SetSetting(args[1], v); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "stored "+args[1])
		return nil
	case "list":
		h := ""
		if len(args) > 1 {
			h = args[1]
		}
		b, _ := json.MarshalIndent(e.secrets.List(h), "", "  ")
		fmt.Println(string(b))
		return nil
	case "set":
		if len(args) < 2 {
			return errors.New("usage: fleet-mcp secret set <name> [-host <fleet manager host>]")
		}
		fs := flag.NewFlagSet("secret set", flag.ContinueOnError)
		hostFlag := fs.String("host", "", "Fleet Manager host, for per-host secrets such as community-string")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		spec, ok := secrets.Lookup(args[1])
		if !ok || !(spec.Kind == secrets.Prompt || spec.Settable) {
			return fmt.Errorf("%q cannot be set at a prompt; settable secrets are: %s", args[1], promptNames())
		}
		if spec.Scope == secrets.Host && *hostFlag == "" {
			return fmt.Errorf("%s belongs to one Fleet Manager: add -host <host>", spec.Name)
		}
		if p, err := e.secrets.Path(*hostFlag, spec.Name); err == nil {
			if _, err := os.Stat(p); err == nil {
				fmt.Fprintf(os.Stderr, "note: replacing the stored %s\n", spec.Name)
			}
		}
		v, err := readSecret(spec)
		if err != nil {
			return err
		}
		if _, err := secrets.Validate(spec.Name, []byte(v)); err != nil {
			return fmt.Errorf("%s NOT stored: %w", spec.Name, err)
		}
		if err := e.secrets.Set(*hostFlag, spec.Name, []byte(v)); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "stored %s\n", spec.Name)
		if spec.Name == secrets.CommunityString {
			fmt.Fprintln(os.Stderr, "fm_host_install will use it; on an existing Fleet Manager, sensors must be re-paired after the config changes")
		}
		return nil
	case "show":
		if len(args) < 2 {
			return errors.New("usage: fleet-mcp secret show <name> -host <host> [-copy]")
		}
		fs := flag.NewFlagSet("secret show", flag.ContinueOnError)
		hostFlag := fs.String("host", "", "Fleet Manager host")
		copyFlag := fs.Bool("copy", false, "copy to the clipboard instead of printing")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		spec, ok := secrets.Lookup(args[1])
		if !ok || !spec.Showable {
			return fmt.Errorf("%q cannot be shown; only values users need to type elsewhere can (community-string)", args[1])
		}
		v, err := e.secrets.GetString(*hostFlag, spec.Name)
		if err != nil {
			return err
		}
		if *copyFlag {
			if err := copyToClipboard(v); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "copied %s for %s to the clipboard\n", spec.Name, *hostFlag)
			return nil
		}
		if !term.IsTerminal(int(os.Stdout.Fd())) {
			return errors.New("refusing to print a secret to a pipe or file; run this in a terminal, or use -copy")
		}
		fmt.Println(v)
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
		if s.Kind == secrets.Prompt || s.Settable {
			n = append(n, s.Name)
		}
	}
	return strings.Join(n, ", ")
}

// copyToClipboard uses the platform's clipboard command.
func copyToClipboard(v string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("clip.exe")
	case "darwin":
		cmd = exec.Command("pbcopy")
	default:
		if _, err := exec.LookPath("wl-copy"); err == nil {
			cmd = exec.Command("wl-copy")
		} else {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		}
	}
	cmd.Stdin = strings.NewReader(v)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("copying to the clipboard: %v %s", err, out)
	}
	return nil
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
		return secrets.Clean(line), nil
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
	if secrets.Clean(string(a)) != secrets.Clean(string(b)) {
		return "", errors.New("not stored: the two entries did not match")
	}
	return secrets.Clean(string(a)), nil
}

func hostCmd(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: fleet-mcp host check <host> | install <host> [-ssh-user u] [-version v] [-no-expose-swagger] [-agent-user u] [-execute]")
	}
	sub, target := args[0], args[1]
	fs := flag.NewFlagSet("host "+sub, flag.ContinueOnError)
	sshUser := fs.String("ssh-user", "", "SSH user with passwordless sudo")
	sshPort := fs.Int("ssh-port", 0, "SSH port")
	ver := fs.String("version", "", "corelight-fleet version (default newest)")
	noSwagger := fs.Bool("no-expose-swagger", false, "leave expose-swagger off (default: on, so the REST API spec is served)")
	mcpUser := fs.String("agent-user", "", "Fleet Manager user to create for the agent (default claude)")
	url := fs.String("url", "", "URL to reach Fleet Manager (default https://<host>)")
	execute := fs.Bool("execute", false, "run the installation (default: preview only)")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	e, err := setup()
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
	case "checklist":
		items, err := install.Checklist(ctx, e.secrets, target, r)
		if err != nil {
			return err
		}
		fmt.Print(install.RenderChecklist(items))
		return nil
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
		if *noSwagger {
			off := false
			opts.ExposeSwagger = &off
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
		if in.AdminTempPassword != "" {
			fmt.Printf("\nadmin temporary password: %s\nlog in at %s as admin; Fleet Manager will require a new password.\n", in.AdminTempPassword, in.URL())
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
