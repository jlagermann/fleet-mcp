package tools

import (
	"context"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/spec"
)

func registerFleets(s *mcp.Server, d *Deps) {
	type fleetsArgs struct {
		Check bool `json:"check,omitempty" jsonschema:"also log in to each Fleet Manager and report whether it is reachable and its version"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_fleets",
		Description: "List the Fleet Managers this server can manage: name (pass it as the fleet argument of other tools), URL, user, where the entry comes from, whether it is the default and whether it is read-only. " +
			"Entries come from FLEET_MCP_URL/FLEET_MCP_PROFILE, fleets.json, and Fleet Managers installed by fm_host_install (picked up automatically).",
		Annotations: readOnly("List Fleet Managers"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a fleetsArgs) (*mcp.CallToolResult, any, error) {
		d.Fleets.Reload()
		list, warns := d.Fleets.List()
		rows := make([]map[string]any, len(list))
		for i, f := range list {
			rows[i] = map[string]any{
				"name": f.Name, "url": f.URL, "username": f.Username, "source": f.Source,
				"default": f.Default, "read_only": f.ReadOnly,
			}
		}
		if a.Check {
			var wg sync.WaitGroup
			for i, f := range list {
				wg.Add(1)
				go func(i int, name string) {
					defer wg.Done()
					cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
					defer cancel()
					c, err := d.Fleets.Get(name)
					if err == nil {
						var v string
						if v, err = spec.Version(cctx, c.Client); err == nil {
							rows[i]["reachable"], rows[i]["version"] = true, v
							return
						}
					}
					rows[i]["reachable"], rows[i]["error"] = false, err.Error()
				}(i, f.Name)
			}
			wg.Wait()
		}
		out := map[string]any{"fleets": rows}
		if len(list) == 0 {
			out["hint"] = "No Fleet Manager is configured. Install one with fm_host_install, or add existing ones to fleets.json (see the README)."
		}
		if len(warns) > 0 {
			out["warnings"] = warns
		}
		r, err := jsonResult(out)
		return r, nil, err
	})
}
