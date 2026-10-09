package tools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/fleet"
	"github.com/jlagermann/fleet-mcp/internal/jsonview"
	"github.com/jlagermann/fleet-mcp/internal/redact"
)

const (
	pathInfo           = "/fleet/v1/info"
	pathUserInfo       = "/fleet/v1/userinfo"
	pathCatalog        = "/fleet/v1/sensor/catalog"
	pathGroups         = "/fleet/v1/sensor/group/list"
	pathPolicies       = "/fleet/v1/sensor/policy/list"
	pathPolicy         = "/fleet/v1/sensor/policy/"
	pathSuricataList   = "/fleet/v1/suricata/policies"
	pathSuricata       = "/fleet/v1/suricata/"
	pathUpdateStatus   = "/fleet/v1/sensor-update/status"
	pathNotifications  = "/fleet/v1/notifications"
	pathBackups        = "/fleet/v1/server/backup"
	pathBackupStatus   = "/fleet/v1/server/backup/status"
	pathBackupSchedule = "/fleet/v1/server/backup/schedule"
)

var sensorUID = regexp.MustCompile(`^[0-9a-f]{2}(-[0-9a-f]{2}){7}$`)

// genericHeaders are sent on every Fleet Manager response and say nothing
// about a backup image.
var genericHeaders = map[string]bool{
	"x-request-id": true, "x-xss-protection": true, "x-development-mode": true,
	"x-fleet-api-compatibility": true, "x-content-type-options": true, "x-frame-options": true,
}

type noArgs struct{}

func (d *Deps) getDecoded(ctx context.Context, path string, q url.Values, extra ...string) (any, error) {
	resp, err := d.Client.Get(ctx, path, q)
	if err != nil {
		return nil, err
	}
	return decode(resp.Body, extra...)
}

func asList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case map[string]any:
		if l, ok := t["list"].([]any); ok {
			return l
		}
	}
	return nil
}

func names(v any) []any {
	out := []any{}
	for _, el := range asList(v) {
		if m, ok := el.(map[string]any); ok {
			out = append(out, m["name"])
		}
	}
	return out
}

func count(v any) int { return len(asList(v)) }

func registerRead(s *mcp.Server, d *Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_info",
		Description: "Fleet Manager version and features, the logged-in user and tenant, and whether the REST and GraphQL schemas are available for fm_api_describe.",
		Annotations: readOnly("Fleet Manager info"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
		info, err := d.getDecoded(ctx, pathInfo, nil)
		if err != nil {
			return nil, nil, err
		}
		out := map[string]any{"fleet_manager": info, "host": d.Client.Host()}
		if ui, err := d.getDecoded(ctx, pathUserInfo, nil); err == nil {
			if m, ok := ui.(map[string]any); ok {
				perms := strings.Split(fmt.Sprint(m["permission_actions"]), ",")
				out["user"] = map[string]any{
					"username": m["username"], "current_tenant": m["current_tenant"],
					"tenants": m["tenant_names"], "permission_count": len(perms),
				}
			}
		} else {
			out["user_error"] = err.Error()
		}
		out["schemas"] = d.Specs.Status(ctx)
		r, err := jsonResult(out)
		return r, nil, err
	})

	type sensorsArgs struct {
		NameContains string `json:"name_contains,omitempty" jsonschema:"only sensors whose name contains this text (case-insensitive)"`
		Health       string `json:"health,omitempty" jsonschema:"only sensors with this health.status value"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_sensors_list",
		Description: "List the sensors Fleet Manager manages, one summary row each: uid, name, health, connection, last ping, group, policy, software version, model, config-apply status, exceptions, failed services and license warnings. Use fm_sensor_get for a full record.",
		Annotations: readOnly("List sensors"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a sensorsArgs) (*mcp.CallToolResult, any, error) {
		cat, err := d.getDecoded(ctx, pathCatalog, nil)
		if err != nil {
			return nil, nil, err
		}
		var rows []any
		for _, el := range asList(cat) {
			sm, ok := el.(map[string]any)
			if !ok {
				continue
			}
			if a.NameContains != "" && !strings.Contains(strings.ToLower(fmt.Sprint(sm["name"])), strings.ToLower(a.NameContains)) {
				continue
			}
			if a.Health != "" && !strings.EqualFold(fmt.Sprint(sm["health.status"]), a.Health) {
				continue
			}
			rows = append(rows, sensorSummary(sm))
		}
		out := map[string]any{"sensors": rows}
		if m, ok := cat.(map[string]any); ok {
			out["counts"] = m["information"]
		}
		r, err := jsonResult(out)
		return r, nil, err
	})

	type sensorGetArgs struct {
		Sensor string `json:"sensor" jsonschema:"sensor uid (like 0a-1b-2c-3d-4e-5f-60-71) or exact sensor name"`
		viewArgs
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_sensor_get",
		Description: "Full Fleet Manager detail for one sensor. Top-level keys: information (the status record: health, network, services.status, licenses, bro.inputs, exceptions), configuration.live / configuration.current / configuration.delta (running vs desired config), filter-configuration.current, metrics.status, packages.enabled.live, packages.metadata, configuration.metadata, exporter.metadata, suricata-file, file-info. Large (often >100 KB); always narrow with select/fields, e.g. select \"/information/services.status\" with fields [\"name\",\"status\"], or select \"/configuration.delta\".",
		Annotations: readOnly("Get sensor"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a sensorGetArgs) (*mcp.CallToolResult, any, error) {
		uid, err := d.resolveSensor(ctx, a.Sensor)
		if err != nil {
			return nil, nil, err
		}
		v, err := d.getDecoded(ctx, pathCatalog+"/"+uid, nil)
		if err != nil {
			return nil, nil, err
		}
		r, err := d.view(v, a.viewArgs)
		return r, nil, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_groups_list",
		Description: "List sensor groups with their policy and member sensor names.",
		Annotations: readOnly("List sensor groups"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
		v, err := d.getDecoded(ctx, pathGroups, nil)
		if err != nil {
			return nil, nil, err
		}
		var rows []any
		for _, el := range asList(v) {
			g, ok := el.(map[string]any)
			if !ok {
				continue
			}
			rows = append(rows, map[string]any{
				"id": g["id"], "name": g["name"], "description": g["description"],
				"policy_id": g["policy.id"], "policy": g["policy.name"],
				"sensors": names(g["sensors"]), "tags": names(g["tags"]),
			})
		}
		r, err := jsonResult(rows)
		return r, nil, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_policies_list",
		Description: "List sensor policies: id, name, whether global, the groups using each one, linked Suricata policy, YARA ruleset, input/intel/CA-bundle/resource collections, bundle and enabled packages. Use fm_policy_get for the full configuration.",
		Annotations: readOnly("List sensor policies"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
		v, err := d.getDecoded(ctx, pathPolicies, nil)
		if err != nil {
			return nil, nil, err
		}
		var rows []any
		for _, el := range asList(v) {
			p, ok := el.(map[string]any)
			if !ok {
				continue
			}
			rows = append(rows, map[string]any{
				"id": p["id"], "name": p["name"], "description": p["description"], "global": p["isGlobal"],
				"groups": names(p["groups"]), "bundle_id": p["bundle.id"],
				"suricata_policy_id": p["suricataPolicyID"], "yara_ruleset_id": p["yaraRulesetID"],
				"input_collection_id": p["inputCollectionID"], "intel_collection_id": p["intelCollectionID"],
				"ca_bundle_collection_id": p["caBundleCollectionID"], "resource_collection_id": p["resourceCollectionID"],
				"upgrade_schedule_id": p["upgradeScheduleID"], "packages_enabled": p["packages.enabled"],
				"updated_at": p["record.updated-at"], "updated_by": p["record.updated-by"],
			})
		}
		r, err := jsonResult(rows)
		return r, nil, err
	})

	type idArgs struct {
		ID int `json:"id" jsonschema:"numeric id from the matching list tool"`
		viewArgs
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_policy_get",
		Description: "Full sensor policy by id, including its configuration and filter configuration. Use select (e.g. \"/configuration\") to narrow.",
		Annotations: readOnly("Get sensor policy"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a idArgs) (*mcp.CallToolResult, any, error) {
		v, err := d.getDecoded(ctx, fmt.Sprintf("%s%d", pathPolicy, a.ID), nil)
		if err != nil {
			return nil, nil, err
		}
		r, err := d.view(v, a.viewArgs)
		return r, nil, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_suricata_policies_list",
		Description: "List Fleet Manager Suricata policies with their rule sources, modifier files (enable/disable/modify), rules automation and whether each is in use. Feed URLs have license codes redacted.",
		Annotations: readOnly("List Suricata policies"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
		v, err := d.getDecoded(ctx, pathSuricataList, nil)
		if err != nil {
			return nil, nil, err
		}
		var rows []any
		for _, el := range asList(v) {
			p, ok := el.(map[string]any)
			if !ok {
				continue
			}
			var sources, mods []any
			for _, x := range asList(p["sources"]) {
				if m, ok := x.(map[string]any); ok {
					sources = append(sources, jsonview.Project(m, []string{"id", "name", "entityType", "url", "enabled", "last_modified"}))
				}
			}
			for _, x := range asList(p["modifierFiles"]) {
				if m, ok := x.(map[string]any); ok {
					mods = append(mods, jsonview.Project(m, []string{"id", "name", "enabled", "status", "url"}))
				}
			}
			rows = append(rows, map[string]any{
				"id": p["id"], "name": p["name"], "description": p["description"], "home_net": p["homeNet"],
				"rules_automation": p["rulesAutomation"], "use_modifier_files": p["useModifierFiles"],
				"in_use": p["inUse"], "sources": sources, "modifier_files": mods,
				"rules_file_id": p["suricata-file-id"], "yaml_file_id": p["suricata-yaml-file-id"],
				"updated_at": p["updatedAt"], "updated_by": p["updatedBy"],
			})
		}
		r, err := jsonResult(rows)
		return r, nil, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_suricata_policy_get",
		Description: "Full Suricata policy by id, including Suricata settings (address/port groups, eve options) and config. Use select (e.g. \"/settings\") to narrow.",
		Annotations: readOnly("Get Suricata policy"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a idArgs) (*mcp.CallToolResult, any, error) {
		v, err := d.getDecoded(ctx, fmt.Sprintf("%s%d", pathSuricata, a.ID), nil)
		if err != nil {
			return nil, nil, err
		}
		r, err := d.view(v, a.viewArgs)
		return r, nil, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_sensor_updates_status",
		Description: "Software update state for each sensor (with names): update status, target version, last message, errors, offline/online update.",
		Annotations: readOnly("Sensor update status"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
		v, err := d.getDecoded(ctx, pathUpdateStatus, nil)
		if err != nil {
			return nil, nil, err
		}
		byUID := d.sensorNames(ctx)
		var rows []any
		for _, el := range asList(v) {
			if m, ok := el.(map[string]any); ok {
				m["name"] = byUID[fmt.Sprint(m["uid"])]
				rows = append(rows, m)
			}
		}
		r, err := jsonResult(rows)
		return r, nil, err
	})

	type notifArgs struct {
		IncludeDismissed bool   `json:"include_dismissed,omitempty" jsonschema:"also return dismissed notifications"`
		Severity         string `json:"severity,omitempty" jsonschema:"only this severity, e.g. failed or warning"`
		Type             string `json:"type,omitempty" jsonschema:"only this type, e.g. license"`
		Limit            int    `json:"limit,omitempty" jsonschema:"newest N (default 50)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_notifications",
		Description: "Fleet Manager notifications (license, certificate, disk, backup, sensor events), newest first. Undismissed only unless include_dismissed is set.",
		Annotations: readOnly("Notifications"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a notifArgs) (*mcp.CallToolResult, any, error) {
		v, err := d.getDecoded(ctx, pathNotifications, nil)
		if err != nil {
			return nil, nil, err
		}
		rows := []map[string]any{}
		all := asList(v)
		dismissed := 0
		for _, el := range all {
			m, ok := el.(map[string]any)
			if !ok {
				continue
			}
			if m["dismissed"] == true {
				dismissed++
				if !a.IncludeDismissed {
					continue
				}
			}
			if a.Severity != "" && !strings.EqualFold(fmt.Sprint(m["severity"]), a.Severity) {
				continue
			}
			if a.Type != "" && !strings.EqualFold(fmt.Sprint(m["type"]), a.Type) {
				continue
			}
			rows = append(rows, m)
		}
		sort.SliceStable(rows, func(i, j int) bool { return fmt.Sprint(rows[i]["timestamp"]) > fmt.Sprint(rows[j]["timestamp"]) })
		limit := a.Limit
		if limit <= 0 {
			limit = 50
		}
		notes := []string{fmt.Sprintf("%d notifications in total, %d dismissed", len(all), dismissed)}
		if len(rows) > limit {
			notes = append(notes, fmt.Sprintf("showing newest %d of %d", limit, len(rows)))
			rows = rows[:limit]
		}
		r, err := jsonResult(rows, notes...)
		return r, nil, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "fm_backups",
		Description: "Fleet Manager backup state: the current backup image (size and date, from a HEAD request; the image itself is not downloaded), the status of the last backup generation and the automatic backup schedule.",
		Annotations: readOnly("Backups"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
		out := map[string]any{}
		// GET on this path downloads the image; HEAD describes it.
		if resp, err := d.Client.Do(ctx, http.MethodHead, pathBackups, nil, nil, ""); err != nil {
			var apiErr *fleet.APIError
			if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
				out["image"] = "no backup image"
			} else {
				out["image_error"] = err.Error()
			}
		} else {
			img := map[string]any{"exists": true}
			for k, vs := range resp.Header {
				lk := strings.ToLower(k)
				switch {
				case lk == "content-length", lk == "last-modified", lk == "content-disposition", lk == "etag":
				case strings.HasPrefix(lk, "x-") && !genericHeaders[lk] && !redact.SensitiveKey(lk):
				default:
					continue
				}
				img[lk] = strings.Join(vs, ", ")
			}
			out["image"] = img
		}
		for key, p := range map[string]string{"status": pathBackupStatus, "schedule": pathBackupSchedule} {
			if v, err := d.getDecoded(ctx, p, nil); err != nil {
				out[key+"_error"] = err.Error()
			} else {
				out[key] = v
			}
		}
		r, err := jsonResult(out)
		return r, nil, err
	})
}

func sensorSummary(s map[string]any) map[string]any {
	st := s["extendedinformation.status"]
	failed := count(s["services.failed"])
	return map[string]any{
		"uid": s["uid"], "name": s["name"],
		"health": s["health.status"], "connected": s["fleet.connected"], "last_ping": s["ping.last"],
		"group": s["group.name"], "policy": s["policy.name"], "policy_id": s["policy.id"],
		"version":       jsonview.Lookup(st, "/os.version"),
		"model":         jsonview.Lookup(st, "/model"),
		"platform":      jsonview.Lookup(st, "/platform.type"),
		"mgmt_ipv4":     jsonview.Lookup(st, "/network.address.v4"),
		"config_apply":  s["configuration.apply.status"],
		"exceptions":    s["exceptions.exist"],
		"update_status": s["image.update.status"],
		"failed_services": failed, "licenses_warning": s["licenses.warn"], "licenses_ended": s["licenses.end"],
		"has_suricata": s["has-suricata"], "has_yara": s["has-yara"],
	}
}

func (d *Deps) catalog(ctx context.Context) ([]map[string]any, error) {
	v, err := d.getDecoded(ctx, pathCatalog, nil)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for _, el := range asList(v) {
		if m, ok := el.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

func (d *Deps) sensorNames(ctx context.Context) map[string]any {
	out := map[string]any{}
	cat, err := d.catalog(ctx)
	if err != nil {
		return out
	}
	for _, s := range cat {
		out[fmt.Sprint(s["uid"])] = s["name"]
	}
	return out
}

// resolveSensor accepts a uid or a sensor name.
func (d *Deps) resolveSensor(ctx context.Context, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", errors.New("sensor is required")
	}
	if sensorUID.MatchString(strings.ToLower(ref)) {
		return strings.ToLower(ref), nil
	}
	cat, err := d.catalog(ctx)
	if err != nil {
		return "", err
	}
	var known []string
	for _, s := range cat {
		name := fmt.Sprint(s["name"])
		if strings.EqualFold(name, ref) {
			return fmt.Sprint(s["uid"]), nil
		}
		known = append(known, name)
	}
	sort.Strings(known)
	return "", fmt.Errorf("no sensor named %q; known sensors: %s", ref, strings.Join(known, ", "))
}
