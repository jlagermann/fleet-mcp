package tools

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/policydiff"
)

func registerPolicyDiff(s *mcp.Server, d *Deps) {
	type diffArgs struct {
		Fleet         string `json:"fleet,omitempty" jsonschema:"Fleet Manager of the first policy (see fm_fleets); omit for the default"`
		Policy        string `json:"policy" jsonschema:"first sensor policy, id or exact name"`
		CompareFleet  string `json:"compare_fleet,omitempty" jsonschema:"Fleet Manager of the second policy (default: the same as fleet)"`
		ComparePolicy string `json:"compare_policy,omitempty" jsonschema:"second sensor policy, id or exact name (default: the same name as policy, for comparing across Fleet Managers)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_policy_diff",
		Description: "Compare two sensor policies, on the same or on different Fleet Managers (for drift after a copy, or between environments): settings (at their default when not set; secrets only as set or not), " +
			"custom bundle packages (enabled, version, git revision), linked objects by name, the linked Suricata policies (automation, configuration, settings, rule sources with license codes masked, configuration files, rule modifiers), " +
			"and the sources of the linked YARA ruleset and collections by file hash. Read-only; works with read-only Fleet Managers.",
		Annotations: readOnly("Compare sensor policies"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a diffArgs) (*mcp.CallToolResult, any, error) {
		if a.Policy == "" {
			return nil, nil, errors.New("policy is required")
		}
		ca, err := d.conn(a.Fleet)
		if err != nil {
			return nil, nil, err
		}
		cb := ca
		if a.CompareFleet != "" {
			if cb, err = d.conn(a.CompareFleet); err != nil {
				return nil, nil, err
			}
		}
		other := a.ComparePolicy
		if other == "" {
			if cb.Name == ca.Name {
				return nil, nil, errors.New("give compare_policy, or compare_fleet to compare the same policy name on another Fleet Manager")
			}
			other = a.Policy
		}
		res, err := policydiff.Compare(ctx, policydiff.Side{API: ca.Client, Fleet: ca.Name, Policy: a.Policy}, policydiff.Side{API: cb.Client, Fleet: cb.Name, Policy: other})
		if err != nil {
			return nil, nil, err
		}
		r, err := jsonResult(res)
		return r, nil, err
	})
}
