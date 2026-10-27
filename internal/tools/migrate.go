package tools

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/audit"
	"github.com/jlagermann/fleet-mcp/internal/fleets"
	"github.com/jlagermann/fleet-mcp/internal/metrics"
	"github.com/jlagermann/fleet-mcp/internal/migrate"
)

type exportArgs struct {
	target
	Policy   string `json:"policy" jsonschema:"sensor policy ID or exact name on the source Fleet Manager"`
	Snapshot bool   `json:"snapshot_connector_sources,omitempty" jsonschema:"also export the latest file of collection sources fed by a connector (CrowdStrike, Corelight, ...) as static uploaded sources; default false lists them for follow-up instead"`
	Package  string `json:"package,omitempty" jsonschema:"name for the package directory (letters, digits, . _ -); default <fleet>-<policy>-<time>"`
}

type importArgs struct {
	target
	Package string `json:"package" jsonschema:"package name from fm_policy_export or fm_policy_packages"`
	importOptions
}

// importOptions are shared by fm_policy_import and fm_policy_copy.
type importOptions struct {
	Name           string            `json:"name,omitempty" jsonschema:"name for the new sensor policy (default: the exported name)"`
	NameSuffix     string            `json:"name_suffix,omitempty" jsonschema:"appended to the name of every object created, e.g. \" (copy)\", to avoid name clashes"`
	Exclude        []string          `json:"exclude,omitempty" jsonschema:"parts to leave out: bundle, suricata, yara, exporters, input, intel, resource, ca_bundles"`
	ExporterTokens string            `json:"exporter_tokens,omitempty" jsonschema:"how secrets the API never returns (exporter tokens) are supplied, as the user chose when the preview asked: database (read from the source Fleet Manager's database over SSH, read-only) or prompt (the user runs fleet-mcp policy tokens <package> in a terminal)"`
	SourceSSHHost  string            `json:"source_ssh_host,omitempty" jsonschema:"with exporter_tokens database: SSH host of the source Fleet Manager (default: the host in its URL)"`
	SSHUser        string            `json:"ssh_user,omitempty" jsonschema:"with exporter_tokens database: SSH user with passwordless sudo (default: FLEET_MCP_SSH_USER)"`
	Resolve        map[string]string `json:"resolve,omitempty" jsonschema:"the user's answers to conflict questions in plan.decisions, keyed by decision id (conflict:<kind>:<name>): use_existing (link the existing object unchanged), rename (create the migrated one as '<name> (from <source fleet>)'), rename:<new name>, or for the sensor policy update_existing"`
	Complete       bool              `json:"complete,omitempty" jsonschema:"finish an earlier import of this package into this Fleet Manager that left the exporters out: add them to the policy it created (needs a sensor attached to the target; name, name_suffix and exclude do not apply)"`
	ConfirmToken   string            `json:"confirm_token,omitempty" jsonschema:"the confirm_token from this import's preview; when it matches, the import runs"`
}

func (a importOptions) options() migrate.ImportOptions {
	return migrate.ImportOptions{Name: a.Name, NameSuffix: a.NameSuffix, Exclude: a.Exclude, Complete: a.Complete, ExporterTokens: a.ExporterTokens, Resolve: a.Resolve}
}

func (d *Deps) packageDir(name string) (string, error) {
	if !migrate.ValidPackageName(name) {
		return "", fmt.Errorf("invalid package name %q (letters, digits, . _ - only)", name)
	}
	return filepath.Join(d.PackagesDir, name), nil
}

// manifestSummary is a compact view of a package.
func manifestSummary(name string, m *migrate.Manifest) map[string]any {
	out := map[string]any{
		"package": name, "source_fleet": m.Source.Fleet, "source_version": m.Source.Version,
		"policy": m.Policy.Name, "policy_id": m.Source.PolicyID, "exported_at": m.ExportedAt,
		"settings": len(m.Policy.Configuration), "features": m.Features, "total_bytes": m.TotalBytes(),
		"omitted": m.Omitted,
	}
	if m.Bundle != nil {
		out["bundle"] = m.Bundle.Name
	}
	if s := m.Suricata; s != nil {
		out["suricata_policy"] = map[string]any{"name": s.Name, "sources": len(s.Sources), "modifier_files": len(s.ModifierFiles), "config_files": len(s.Files)}
	}
	if y := m.Yara; y != nil {
		out["yara_ruleset"] = map[string]any{"name": y.Name, "sources": len(y.Sources)}
	}
	if len(m.Collections) > 0 {
		cs := map[string]any{}
		for role, c := range m.Collections {
			cs[role] = map[string]any{"name": c.Name, "sources": len(c.Sources)}
		}
		out["collections"] = cs
	}
	return out
}

func registerMigrate(s *mcp.Server, d *Deps) {
	f := false
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_policy_export",
		Description: "Export a sensor policy and everything it uses (Zeek package bundle, Suricata policy with its rule, configuration and modifier files, YARA ruleset, input/intel/resource/CA bundle collections) from a Fleet Manager into a local package for fm_policy_import. Changes nothing on Fleet Manager. " +
			"Secrets are left out and listed under omitted: exporter tokens, password settings, licensed rule-feed URLs and connector credentials. Generated files (the compiled Suricata rule set and YARA ruleset) are not exported; the target builds its own.",
		Annotations: &mcp.ToolAnnotations{Title: "Export sensor policy", DestructiveHint: &f, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a exportArgs) (*mcp.CallToolResult, any, error) {
		c, err := d.conn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		name, m, err := d.export(ctx, c, a)
		if err != nil {
			return nil, nil, err
		}
		out := manifestSummary(name, m)
		out["next"] = "Import it with fm_policy_import (package " + name + ", fleet <target>)."
		r, err := jsonResult(out)
		return r, nil, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_policy_packages",
		Description: "List exported policy packages available to fm_policy_import.",
		Annotations: readOnly("List policy packages"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		entries, err := os.ReadDir(d.PackagesDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, nil, err
		}
		rows := []any{}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			m, _, err := migrate.ReadManifest(filepath.Join(d.PackagesDir, e.Name()))
			if err != nil {
				continue
			}
			row := map[string]any{"package": e.Name(), "source_fleet": m.Source.Fleet, "source_version": m.Source.Version,
				"policy": m.Policy.Name, "exported_at": m.ExportedAt, "total_bytes": m.TotalBytes(), "omitted": len(m.Omitted)}
			if recs, err := migrate.ReadImports(filepath.Join(d.PackagesDir, e.Name())); err == nil && len(recs) > 0 {
				row["imports"] = recs
			}
			rows = append(rows, row)
		}
		sort.Slice(rows, func(i, j int) bool {
			return rows[i].(map[string]any)["package"].(string) < rows[j].(map[string]any)["package"].(string)
		})
		r, err := jsonResult(rows)
		return r, nil, err
	})
}

func (d *Deps) export(ctx context.Context, c *fleets.Conn, a exportArgs) (string, *migrate.Manifest, error) {
	name := a.Package
	if name == "" {
		name = migrate.PackageName(fmt.Sprintf("%s-%s-%s", c.Name, a.Policy, time.Now().UTC().Format("20060102-150405")))
	}
	dir, err := d.packageDir(name)
	if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(d.PackagesDir, 0o700); err != nil {
		return "", nil, err
	}
	m, err := migrate.Export(ctx, c.Client, migrate.ExportOptions{Fleet: c.Name, Policy: a.Policy, Dir: dir, SnapshotConnectorSources: a.Snapshot})
	return name, m, err
}

func registerMigrateWrite(s *mcp.Server, d *Deps) {
	t, f := true, false
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_policy_import",
		Description: guideFirst("copy-sensor-policy") + "Import a policy package (from fm_policy_export) into a Fleet Manager as a new sensor policy with new Suricata policy, YARA ruleset, collections and bundle. Never changes existing objects; identical file sources already on the target are reused. " +
			"The preview checks that Fleet Manager versions match on major.minor, that the target knows every setting and exporter type, and that no names clash. It also reports, for information, how many target sensors are licensed for the features the policy enables; sensors never block an import. " +
			"Two steps: call without confirm_token for the preview; after the user approves, call again with the same arguments plus confirm_token. If a step fails, everything created is deleted again.",
		Annotations: &mcp.ToolAnnotations{Title: "Import sensor policy", DestructiveHint: &f, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a importArgs) (*mcp.CallToolResult, any, error) {
		return d.importPackage(ctx, a.Fleet, a.Package, a.importOptions, "fm_policy_import")
	})

	type copyArgs struct {
		target
		Package string `json:"package,omitempty" jsonschema:"package name returned by the preview; required with confirm_token"`
		importOptions
		SourceFleet string `json:"source_fleet" jsonschema:"Fleet Manager to copy from (see fm_fleets); it may be read-only"`
		Policy      string `json:"policy,omitempty" jsonschema:"sensor policy ID or exact name on the source; needed when package is not given"`
		Snapshot    bool   `json:"snapshot_connector_sources,omitempty" jsonschema:"also copy the latest file of collection sources fed by a connector, as static sources"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_policy_copy",
		Description: guideFirst("copy-sensor-policy") + "Copy a sensor policy and everything it uses from one Fleet Manager (source_fleet) to another (fleet). The first call exports the policy to a package and returns the import preview with the package name and a confirm_token; after the user approves, call again with the same arguments plus package and confirm_token. " +
			"Same checks and secret handling as fm_policy_export and fm_policy_import.",
		Annotations: &mcp.ToolAnnotations{Title: "Copy sensor policy", DestructiveHint: &f, OpenWorldHint: &t},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a copyArgs) (*mcp.CallToolResult, any, error) {
		if a.Package == "" {
			if a.Complete {
				return nil, nil, errors.New("to finish an earlier copy, call fm_policy_import with complete: true and that copy's package (fm_policy_packages shows imports with deferred parts)")
			}
			if a.ConfirmToken != "" {
				return nil, nil, errors.New("confirm_token needs the package from the preview")
			}
			if a.Policy == "" || a.SourceFleet == "" {
				return nil, nil, errors.New("source_fleet and policy are required")
			}
			src, err := d.conn(a.SourceFleet)
			if err != nil {
				return nil, nil, err
			}
			tgt, err := d.writeConn(a.Fleet)
			if err != nil {
				return nil, nil, err
			}
			if src.Name == tgt.Name {
				return nil, nil, errors.New("source and target are the same Fleet Manager")
			}
			name, _, err := d.export(ctx, src, exportArgs{target: target{Fleet: a.SourceFleet}, Policy: a.Policy, Snapshot: a.Snapshot})
			if err != nil {
				return nil, nil, fmt.Errorf("export from %s: %w", src.Name, err)
			}
			a.Package = name
		}
		return d.importPackage(ctx, a.Fleet, a.Package, a.importOptions, "fm_policy_copy")
	})
}

func (d *Deps) importPackage(ctx context.Context, fleet, pkg string, a importOptions, tool string) (*mcp.CallToolResult, any, error) {
	c, err := d.writeConn(fleet)
	if err != nil {
		return nil, nil, err
	}
	dir, err := d.packageDir(pkg)
	if err != nil {
		return nil, nil, err
	}
	m, digest, err := migrate.ReadManifest(dir)
	if err != nil {
		return nil, nil, err
	}
	opts := a.options()
	var fromDB int
	if opts.ExporterTokens == "database" {
		if fromDB, err = d.secretsFromDatabase(ctx, dir, m, a); err != nil {
			return nil, nil, fmt.Errorf("reading tokens from %s's database: %w", m.Source.Fleet, err)
		}
	}
	plan, err := migrate.BuildPlan(ctx, c.Client, c.Name, dir, m, opts)
	if err != nil {
		return nil, nil, err
	}
	// The import tools share one token so a copy can be confirmed with
	// either tool.
	token := ConfirmToken(c.Client.Host(), "fm_policy_import", c.Name, pkg, digest, opts)

	if a.ConfirmToken == "" {
		out := map[string]any{
			"preview": true, "fleet": c.Name, "package": manifestSummary(pkg, m), "plan": plan, "ready": plan.Ready(),
		}
		if fromDB > 0 {
			out["tokens_read_from_database"] = fromDB
		}
		if plan.Ready() {
			out["confirm_token"] = issueToken(token)
			out["next"] = fmt.Sprintf("Show the plan, warnings and follow_up items to the user. After they approve importing into %s, call %s again with the same arguments plus package %q and confirm_token.", c.Name, tool, pkg)
		} else if len(plan.Blockers) == 0 {
			out["next"] = "Ask the user each question in plan.decisions, in your own words, and wait for the answer. Then preview again with the arguments its resolve entry gives for that answer (for exporters, \"yes\" means adding exclude [\"exporters\"]). Do not choose for the user."
		} else {
			out["next"] = "Resolve the blockers (or use name_suffix or exclude where they apply) and preview again. If plan.decisions is not empty, ask the user those questions too."
		}
		r, err := jsonResult(out)
		return r, nil, err
	}
	if a.ConfirmToken != token {
		return nil, nil, errors.New("confirm_token does not match these arguments or this package; preview again")
	}
	if err := redeemToken(token); err != nil {
		return nil, nil, err
	}
	if !plan.Ready() {
		return nil, nil, fmt.Errorf("the target changed since the preview and the import is now blocked: %v", plan.Blockers)
	}
	res, runErr := migrate.Apply(ctx, c.Client, dir, m, plan, opts)
	rec := audit.Record{Fleet: c.Name, User: c.Username, Tool: tool, Token: token,
		Body: map[string]any{"package": pkg, "digest": digest, "options": opts, "result": res}}
	if runErr != nil {
		rec.Error = runErr.Error()
	}
	auditErr := d.Audit.Write(rec)
	out := map[string]any{"executed": true, "fleet": c.Name, "result": res}
	var notes []string
	if auditErr != nil {
		notes = append(notes, "WARNING: audit log write failed: "+auditErr.Error())
	}
	if runErr != nil {
		out["error"] = runErr.Error()
		if res != nil && res.RolledBack {
			out["next"] = "The import failed and everything it created was deleted. Fix the cause and preview again."
		} else {
			out["next"] = "The import failed and the clean-up did not finish; list result.created and rollback_errors to the user."
		}
	} else {
		done := fmt.Sprintf("Sensor policy %d was created on %s.", res.PolicyID, c.Name)
		if opts.Complete {
			done = fmt.Sprintf("The exporters were added to sensor policy %d on %s.", res.PolicyID, c.Name)
		}
		out["next"] = fmt.Sprintf("%s Tell the user about result.follow_up (secrets and parts to finish by hand) and any verification differences. Assign it to sensor groups separately.", done)
	}
	r, err := jsonResult(out, notes...)
	if runErr != nil && r != nil {
		r.IsError = true
	}
	return r, nil, err
}

// secretsFromDatabase reads the secrets a package still lacks from the
// source Fleet Manager's database over SSH and stores them in the package.
// It returns how many it found; values are never returned.
func (d *Deps) secretsFromDatabase(ctx context.Context, dir string, m *migrate.Manifest, a importOptions) (int, error) {
	missing, err := migrate.MissingSecrets(dir, m)
	if err != nil || len(missing) == 0 {
		return 0, err
	}
	sshHost := a.SourceSSHHost
	if sshHost == "" {
		src, err := d.conn(m.Source.Fleet)
		if err != nil {
			return 0, fmt.Errorf("%w; give source_ssh_host", err)
		}
		u, err := url.Parse(src.URL)
		if err != nil || u.Hostname() == "" {
			return 0, fmt.Errorf("cannot tell the SSH host from %q; give source_ssh_host", src.URL)
		}
		sshHost = u.Hostname()
	}
	r, err := d.runner(hostArgs{Host: sshHost, SSHUser: a.SSHUser})
	if err != nil {
		return 0, err
	}
	keys := make([]string, len(missing))
	for i, s := range missing {
		keys[i] = s.Key
	}
	done := metrics.Step(ctx, "read %d tokens from %s's database over SSH", len(keys), m.Source.Fleet)
	vals, err := migrate.ReadDatabaseSecrets(ctx, r, m.Source.PolicyID, keys)
	done()
	if err != nil {
		return 0, fmt.Errorf("%w (if SSH knows the host by another name or its IP, give that as source_ssh_host)", err)
	}
	if err := migrate.AddSecrets(dir, vals); err != nil {
		return 0, err
	}
	return len(vals), nil
}
