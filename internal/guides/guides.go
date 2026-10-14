// Package guides holds fleet-mcp's workflow guides: step-by-step
// instructions for multi-step tasks. The agent loads one with the fm_guide
// tool, and the user can start one as an MCP prompt. They are kept out of
// the server instructions, which MCP clients truncate.
package guides

import (
	"embed"
	"strings"
)

//go:embed *.md
var files embed.FS

// Guide is one workflow guide.
type Guide struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	// When says which request or tool the guide is for.
	When string `json:"when"`
}

var all = []Guide{
	{"install-fleet-manager", "Install Fleet Manager",
		"Install and set up Fleet Manager on an Ubuntu host: checklist, secrets, readiness check, install.",
		"before fm_install_checklist or fm_host_install"},
	{"create-sensor-policy", "Create a sensor policy",
		"Interview the user and create a sensor policy from scratch with fm_policy_create.",
		"before fm_policy_create"},
	{"change-sensor-policy", "Change a policy",
		"Change an existing sensor or Suricata policy, with the enrichment chain check.",
		"before changing a sensor or Suricata policy with fm_api_write or fm_graphql_mutate"},
	{"delete-sensor-policy", "Delete a sensor policy",
		"Delete a sensor policy and, if the user wants, the objects only it uses.",
		"before deleting a sensor policy"},
	{"copy-sensor-policy", "Copy a sensor policy",
		"Copy or migrate a sensor policy to another Fleet Manager: decisions, exporters, conflicts, secrets.",
		"before fm_policy_copy or fm_policy_import"},
	{"troubleshoot-sensor", "Troubleshoot a sensor",
		"Find why a sensor is unhealthy or an upgrade failed, and fix it.",
		"when a sensor is unhealthy, disconnected or failed an upgrade, and before fm_sensor_action or fm_sensor_support_access"},
	{"move-sensor", "Move a sensor",
		"Move a sensor from one Fleet Manager to another.",
		"before fm_sensor_move"},
}

// All returns every guide, in a fixed order.
func All() []Guide { return append([]Guide(nil), all...) }

// Names returns the guide names.
func Names() []string {
	n := make([]string, len(all))
	for i, g := range all {
		n[i] = g.Name
	}
	return n
}

// Get returns a guide and its markdown text.
func Get(name string) (Guide, string, bool) {
	name = strings.TrimSpace(strings.ToLower(name))
	for _, g := range all {
		if g.Name == name {
			b, err := files.ReadFile(g.Name + ".md")
			if err != nil {
				return Guide{}, "", false
			}
			return g, string(b), true
		}
	}
	return Guide{}, "", false
}
