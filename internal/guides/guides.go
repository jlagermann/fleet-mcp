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
		"Change a sensor policy (settings, packages, linked content) or which sensors use it (groups), with the enrichment chain and license checks.",
		"before fm_policy_update or fm_group_manage, or changing a policy any other way"},
	{"delete-sensor-policy", "Delete a sensor policy",
		"Delete a sensor policy and, if the user wants, the objects only it uses.",
		"before fm_policy_delete"},
	{"copy-sensor-policy", "Copy a sensor policy",
		"Copy or migrate a sensor policy to another Fleet Manager: decisions, exporters, conflicts, secrets.",
		"before fm_policy_copy or fm_policy_import"},
	{"troubleshoot-sensor", "Troubleshoot a sensor",
		"Find why a sensor is unhealthy or an upgrade failed, and fix it.",
		"when a sensor is unhealthy, disconnected or failed an upgrade, and before fm_sensor_action or fm_sensor_support_access"},
	{"push-content", "Push content",
		"Push an intel, input, YARA, Suricata or bundle file to Fleet Manager as it is, with a diff, validation and optional policy linking.",
		"before fm_content_push"},
	{"tune-suricata", "Tune Suricata rules",
		"Disable, enable or change Suricata rules (rules manager or configuration files) and test the ruleset with a real Suricata.",
		"before fm_suricata_modify or fm_suricata_test, or when the user wants to tune or test Suricata rules"},
	{"build-package-bundle", "Build a package bundle",
		"Build a Zeek package bundle with zkg from a manifest, push it to a sensor policy and enable new packages.",
		"when the user wants to build or update a Zeek package bundle"},
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
