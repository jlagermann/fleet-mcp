package tools

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/jsonview"
	"github.com/jlagermann/fleet-mcp/internal/spec"
)

// fleetHealth is one Fleet Manager's summary.
type fleetHealth struct {
	Name          string         `json:"name"`
	Reachable     bool           `json:"reachable"`
	Error         string         `json:"error,omitempty"`
	Version       string         `json:"version,omitempty"`
	ReadOnly      bool           `json:"read_only,omitempty"`
	Sensors       int            `json:"sensors"`
	Health        map[string]int `json:"health,omitempty"`
	Disconnected  []string       `json:"disconnected,omitempty"`
	Unhealthy     []string       `json:"unhealthy,omitempty"`
	ApplyFailed   []string       `json:"config_apply_not_ok,omitempty"`
	FailedSvc     []string       `json:"failed_services,omitempty"`
	LicenseIssues []string       `json:"license_issues,omitempty"`
	Versions      map[string]int `json:"sensor_versions,omitempty"`
	Notifications map[string]int `json:"open_notifications,omitempty"`
	Backups       string         `json:"automatic_backups,omitempty"`
	Policies      int            `json:"sensor_policies"`
	Groups        int            `json:"sensor_groups"`
	Attention     []string       `json:"attention"`
}

func registerFleetHealth(s *mcp.Server, d *Deps) {
	type healthArgs struct {
		Fleets []string `json:"fleets,omitempty" jsonschema:"names of the Fleet Managers to check (default: all, see fm_fleets)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_fleet_health",
		Description: "One read-only overview of every Fleet Manager (or the ones named), checked in parallel: reachability and version, sensors by health, disconnected and unhealthy sensors, " +
			"configuration applies that did not succeed, failed services, license warnings, sensor software versions, open (undismissed) notifications by type, whether automatic backups are on, and the number of policies and groups, " +
			"with a list of what needs attention. Use fm_sensor_diagnose to dig into a sensor.",
		Annotations: readOnly("Fleet health"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a healthArgs) (*mcp.CallToolResult, any, error) {
		d.Fleets.Reload()
		list, _ := d.Fleets.List()
		want := map[string]bool{}
		for _, n := range a.Fleets {
			want[n] = true
		}
		var names []string
		for _, f := range list {
			if len(want) == 0 || want[f.Name] {
				names = append(names, f.Name)
			}
		}
		for n := range want {
			found := false
			for _, x := range names {
				found = found || x == n
			}
			if !found {
				return nil, nil, fmt.Errorf("no Fleet Manager %q (see fm_fleets)", n)
			}
		}
		out := make([]*fleetHealth, len(names))
		var wg sync.WaitGroup
		for i, n := range names {
			wg.Add(1)
			go func(i int, name string) {
				defer wg.Done()
				cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
				defer cancel()
				out[i] = d.fleetHealth(cctx, name)
			}(i, n)
		}
		wg.Wait()
		total := 0
		for _, h := range out {
			total += len(h.Attention)
		}
		r, err := jsonResult(map[string]any{"fleets": out, "attention_items": total, "checked_at": time.Now().UTC().Format(time.RFC3339)})
		return r, nil, err
	})
}

func (d *Deps) fleetHealth(ctx context.Context, name string) *fleetHealth {
	h := &fleetHealth{Name: name, Health: map[string]int{}, Versions: map[string]int{}, Notifications: map[string]int{}, Attention: []string{}}
	c, err := d.Fleets.Get(name)
	if err != nil {
		h.Error = err.Error()
		h.Attention = append(h.Attention, "cannot connect: "+err.Error())
		return h
	}
	h.ReadOnly = c.ReadOnly
	if h.Version, err = spec.Version(ctx, c.Client); err != nil {
		h.Error = err.Error()
		h.Attention = append(h.Attention, "not reachable: "+err.Error())
		return h
	}
	h.Reachable = true
	attn := func(f string, a ...any) { h.Attention = append(h.Attention, fmt.Sprintf(f, a...)) }

	if cat, err := d.catalog(ctx, c); err != nil {
		attn("sensor catalog: %v", err)
	} else {
		h.Sensors = len(cat)
		for _, s := range cat {
			sum := sensorSummary(s)
			nm := fmt.Sprint(sum["name"])
			hs := fmt.Sprint(sum["health"])
			h.Health[hs]++
			if sum["connected"] != true {
				h.Disconnected = append(h.Disconnected, nm)
			} else if hs != "healthy" && hs != "<nil>" {
				h.Unhealthy = append(h.Unhealthy, nm+" ("+hs+")")
			}
			if st := fmt.Sprint(sum["config_apply"]); st != "success" && st != "<nil>" && st != "" {
				h.ApplyFailed = append(h.ApplyFailed, nm+" ("+st+")")
			}
			if n, _ := sum["failed_services"].(int); n > 0 {
				h.FailedSvc = append(h.FailedSvc, fmt.Sprintf("%s (%d)", nm, n))
			}
			if truthyAny(sum["licenses_ended"]) {
				h.LicenseIssues = append(h.LicenseIssues, nm+": a license has ended")
			} else if truthyAny(sum["licenses_warning"]) {
				h.LicenseIssues = append(h.LicenseIssues, nm+": a license ends soon")
			}
			if v := jsonview.Lookup(s["extendedinformation.status"], "/os.version"); v != nil {
				h.Versions[fmt.Sprint(v)]++
			}
		}
	}
	if v, err := d.getDecoded(ctx, c, pathNotifications, nil); err == nil {
		for _, n := range asList(v) {
			m, _ := n.(map[string]any)
			if m["dismissed"] == true {
				continue
			}
			h.Notifications[fmt.Sprintf("%v (%v)", m["type"], m["severity"])]++
		}
	}
	if v, err := d.getDecoded(ctx, c, pathBackupSchedule, nil); err == nil {
		if m, ok := v.(map[string]any); ok {
			if m["enable"] == true {
				h.Backups = fmt.Sprintf("on (%v)", m["schedule"])
			} else {
				h.Backups = "off"
			}
		}
	}
	if v, err := d.getDecoded(ctx, c, "/fleet/v1/sensor/policy/list", nil); err == nil {
		h.Policies = count(v)
	}
	if v, err := d.getDecoded(ctx, c, "/fleet/v1/sensor/group/list", nil); err == nil {
		for _, g := range asList(v) {
			// Group 0 is Fleet Manager's built-in UNASSIGNED group.
			if m, _ := g.(map[string]any); fmt.Sprint(m["id"]) != "0" {
				h.Groups++
			}
		}
	}

	if len(h.Disconnected) > 0 {
		attn("%d sensor(s) not connected: %s", len(h.Disconnected), strings.Join(h.Disconnected, ", "))
	}
	if len(h.Unhealthy) > 0 {
		attn("%d connected sensor(s) not healthy: %s", len(h.Unhealthy), strings.Join(h.Unhealthy, ", "))
	}
	if len(h.ApplyFailed) > 0 {
		attn("configuration apply not successful on: %s", strings.Join(h.ApplyFailed, ", "))
	}
	if len(h.FailedSvc) > 0 {
		attn("failed services on: %s", strings.Join(h.FailedSvc, ", "))
	}
	if len(h.LicenseIssues) > 0 {
		attn("licenses: %s", strings.Join(h.LicenseIssues, "; "))
	}
	if len(h.Versions) > 1 {
		var vs []string
		for v, n := range h.Versions {
			vs = append(vs, fmt.Sprintf("%s ×%d", v, n))
		}
		sort.Strings(vs)
		attn("sensors run %d different software versions: %s", len(h.Versions), strings.Join(vs, ", "))
	}
	for k, n := range h.Notifications {
		if strings.Contains(k, "(failed)") || strings.Contains(k, "(error)") || strings.Contains(k, "(warning)") {
			attn("%d open notification(s): %s", n, k)
		}
	}
	if h.Backups == "off" {
		attn("automatic backups are off")
	}
	sort.Strings(h.Attention)
	if len(h.Health) == 0 {
		h.Health = nil
	}
	if len(h.Versions) == 0 {
		h.Versions = nil
	}
	if len(h.Notifications) == 0 {
		h.Notifications = nil
	}
	return h
}

func truthyAny(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != "" && x != "false" && x != "0"
	case []any:
		return len(x) > 0
	}
	return false
}
