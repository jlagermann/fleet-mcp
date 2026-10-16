package policyedit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// GroupRequest creates, changes or deletes a sensor group.
type GroupRequest struct {
	Action        string   `json:"action" jsonschema:"create, update or delete"`
	Group         string   `json:"group" jsonschema:"group id or exact name (create: the new group's name)"`
	NewName       string   `json:"new_name,omitempty" jsonschema:"update: rename the group"`
	Description   string   `json:"description,omitempty" jsonschema:"create/update: description"`
	Policy        string   `json:"policy,omitempty" jsonschema:"create/update: sensor policy for the group (id or name), or none to leave the group without a policy"`
	AddSensors    []string `json:"add_sensors,omitempty" jsonschema:"create/update: sensors to move into the group (uid or exact name); they leave their current group"`
	RemoveSensors []string `json:"remove_sensors,omitempty" jsonschema:"update: sensors to take out of the group (they become unassigned and keep their current configuration)"`
}

// SensorMove is a sensor's group and policy change.
type SensorMove struct {
	Sensor     string   `json:"sensor"`
	UID        string   `json:"uid"`
	FromGroup  string   `json:"from_group"`
	FromPolicy string   `json:"from_policy"`
	ToGroup    string   `json:"to_group"`
	ToPolicy   string   `json:"to_policy"`
	Unlicensed []string `json:"unlicensed_features,omitempty"`
	Connected  bool     `json:"connected"`
}

// GroupPlan is what a group change will do; exported fields are the preview.
type GroupPlan struct {
	Action   string       `json:"action"`
	Group    Ref          `json:"group"`
	Changes  []Change     `json:"changes,omitempty"`
	Sensors  []SensorMove `json:"sensors,omitempty"`
	Steps    []string     `json:"steps"`
	Notes    []string     `json:"notes,omitempty"`
	Warnings []string     `json:"warnings,omitempty"`
	Blockers []string     `json:"blockers,omitempty"`

	body     map[string]any
	moves    []map[string]any // bulk catalog update
	policyID *int64           // group policy after (nil: unchanged)
	state    string
}

// Ready reports whether there is something to do and nothing blocks it.
func (p *GroupPlan) Ready() bool {
	return len(p.Blockers) == 0 && (p.Action == "delete" || p.Action == "create" || len(p.Changes) > 0 || len(p.moves) > 0)
}

// State is what the plan was built from, for the confirm token.
func (p *GroupPlan) State() string { return p.state }

type sensorRec struct {
	uid, name string
	group     int64
	connected bool
	licenses  map[string]bool
}

func catalog(ctx context.Context, api API) ([]sensorRec, error) {
	var cat struct {
		List []map[string]any `json:"list"`
	}
	if err := api.GetJSON(ctx, pathCatalog, nil, &cat); err != nil {
		return nil, fmt.Errorf("reading the sensor catalog: %w", err)
	}
	var out []sensorRec
	for _, s := range cat.List {
		r := sensorRec{uid: str(s["uid"]), name: str(s["name"]), group: idOf(s["group.id"]), connected: s["fleet.connected"] == true, licenses: map[string]bool{}}
		if r.name == "" {
			r.name = r.uid // a sensor that just connected has not reported its name yet
		}
		for _, l := range listOf(s["licenses"]) {
			m := obj(l)
			r.licenses[str(m["name"])] = m["active"] == true
		}
		out = append(out, r)
	}
	return out, nil
}

// PrepareGroup builds the plan. It changes nothing.
func PrepareGroup(ctx context.Context, api API, req GroupRequest) (*GroupPlan, error) {
	act := strings.ToLower(strings.TrimSpace(req.Action))
	p := &GroupPlan{Action: act, body: map[string]any{}}
	groups, err := listGroups(ctx, api)
	if err != nil {
		return nil, err
	}
	byID := map[int64]GroupInfo{}
	for _, g := range groups {
		byID[g.ID] = g
	}
	var cur *GroupInfo
	gid, _ := strconv.ParseInt(strings.TrimSpace(req.Group), 10, 64)
	for i, g := range groups {
		if (gid > 0 && g.ID == gid) || g.Name == strings.TrimSpace(req.Group) {
			cur = &groups[i]
		}
	}
	switch act {
	case "create":
		if strings.TrimSpace(req.Group) == "" {
			return nil, fmt.Errorf("give the new group's name in group")
		}
		if cur != nil {
			p.Blockers = append(p.Blockers, fmt.Sprintf("a group named %q already exists (%d)", cur.Name, cur.ID))
		}
		p.Group = Ref{Name: strings.TrimSpace(req.Group)}
		p.body["name"] = p.Group.Name
		if req.Description != "" {
			p.body["description"] = req.Description
		}
		if len(req.RemoveSensors) > 0 {
			p.Blockers = append(p.Blockers, "remove_sensors does not apply to a new group")
		}
		p.Steps = append(p.Steps, fmt.Sprintf("create sensor group %q", p.Group.Name))
	case "update", "delete":
		if cur == nil {
			var names []string
			for _, g := range groups {
				names = append(names, g.Name)
			}
			return nil, fmt.Errorf("no sensor group %q; groups: %s", req.Group, strings.Join(names, ", "))
		}
		if cur.ID == 0 {
			return nil, fmt.Errorf("%s is Fleet Manager's built-in group for unassigned sensors and cannot be changed; take sensors out of a group with remove_sensors", cur.Name)
		}
		p.Group = Ref{ID: cur.ID, Name: cur.Name}
	default:
		return nil, fmt.Errorf("action must be create, update or delete")
	}

	sensors, err := catalog(ctx, api)
	if err != nil {
		return nil, err
	}
	policyNames := map[int64]string{}
	pols, err := policies(ctx, api)
	if err != nil {
		return nil, err
	}
	var polRefs []Ref
	for _, x := range pols {
		policyNames[idOf(x["id"])] = str(x["name"])
		polRefs = append(polRefs, Ref{idOf(x["id"]), str(x["name"])})
	}
	groupLabel := func(id int64) string {
		if id == 0 {
			return "unassigned"
		}
		return byID[id].Name
	}
	policyOf := func(groupID int64) int64 { return byID[groupID].PolicyID }

	if act == "delete" {
		p.Steps = append(p.Steps, fmt.Sprintf("delete sensor group %s", p.Group))
		if len(cur.Sensors) > 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf("the group has %d sensor(s) (%s): they become unassigned and keep their current configuration until they join a group with a policy",
				len(cur.Sensors), strings.Join(cur.Sensors, ", ")))
		}
		if req.NewName != "" || req.Policy != "" || len(req.AddSensors)+len(req.RemoveSensors) > 0 {
			p.Blockers = append(p.Blockers, "delete takes only the group")
		}
		p.state = fmt.Sprintf("%d|%v", cur.ID, cur.Sensors)
		return p, nil
	}

	// The group's policy after the change.
	newPolicy := int64(-1) // unchanged
	if cur != nil {
		newPolicy = cur.PolicyID
	} else {
		newPolicy = 0
	}
	if pr := strings.TrimSpace(req.Policy); pr != "" {
		target := int64(0)
		if !strings.EqualFold(pr, "none") {
			r, err := pick(polRefs, pr, "sensor policy")
			if err != nil {
				p.Blockers = append(p.Blockers, err.Error())
			} else {
				target = r.ID
			}
		}
		if cur == nil || target != cur.PolicyID {
			from := "none"
			if cur != nil && cur.PolicyID > 0 {
				from = fmt.Sprintf("%q (%d)", policyNames[cur.PolicyID], cur.PolicyID)
			}
			to := "none"
			if target > 0 {
				to = fmt.Sprintf("%q (%d)", policyNames[target], target)
			}
			if cur != nil {
				p.Changes = append(p.Changes, Change{Kind: "policy", Key: "policy", From: from, To: to})
			}
			p.body["policy.id"] = nullable(target)
			p.policyID = &target
			newPolicy = target
		}
	}
	if cur != nil {
		if req.NewName != "" && req.NewName != cur.Name {
			p.body["name"] = req.NewName
			p.Changes = append(p.Changes, Change{Kind: "name", Key: "name", From: show(cur.Name), To: show(req.NewName)})
		}
		if req.Description != "" {
			p.body["description"] = req.Description
			p.Changes = append(p.Changes, Change{Kind: "description", Key: "description", To: show(req.Description)})
		}
		if len(p.Changes) > 0 {
			p.Steps = append(p.Steps, fmt.Sprintf("update sensor group %s", p.Group))
		}
	}

	find := func(ref string) (sensorRec, bool) {
		ref = strings.TrimSpace(ref)
		for _, s := range sensors {
			if s.uid == ref || s.name == ref {
				return s, true
			}
		}
		return sensorRec{}, false
	}
	features, err := policyFeatures(ctx, api, newPolicy)
	if err != nil {
		return nil, err
	}
	toLabel := p.Group.Name
	moved := map[string]bool{}
	for _, ref := range req.AddSensors {
		s, ok := find(ref)
		if !ok {
			p.Blockers = append(p.Blockers, fmt.Sprintf("no sensor %q on this Fleet Manager (sensors: %s; a sensor that just connected is known only by its uid until it reports its name)", ref, sensorList(sensors)))
			continue
		}
		if cur != nil && s.group == cur.ID {
			p.Notes = append(p.Notes, fmt.Sprintf("%s is already in the group", s.name))
			continue
		}
		moved[s.uid] = true
		m := SensorMove{Sensor: s.name, UID: s.uid, FromGroup: groupLabel(s.group), FromPolicy: label(policyNames, policyOf(s.group)),
			ToGroup: toLabel, ToPolicy: label(policyNames, newPolicy), Connected: s.connected}
		m.Unlicensed = unlicensed(features, s)
		p.Sensors = append(p.Sensors, m)
		p.moves = append(p.moves, map[string]any{"uid": s.uid})
	}
	for _, ref := range req.RemoveSensors {
		s, ok := find(ref)
		if !ok {
			p.Blockers = append(p.Blockers, fmt.Sprintf("no sensor %q on this Fleet Manager (sensors: %s; a sensor that just connected is known only by its uid until it reports its name)", ref, sensorList(sensors)))
			continue
		}
		if cur == nil || s.group != cur.ID {
			p.Notes = append(p.Notes, fmt.Sprintf("%s is not in the group", s.name))
			continue
		}
		p.Sensors = append(p.Sensors, SensorMove{Sensor: s.name, UID: s.uid, FromGroup: cur.Name, FromPolicy: label(policyNames, cur.PolicyID),
			ToGroup: "unassigned", ToPolicy: "none (keeps its current configuration)", Connected: s.connected})
		p.moves = append(p.moves, map[string]any{"uid": s.uid, "group.id": 0})
	}
	// Sensors already in the group get the new policy too.
	if cur != nil && p.policyID != nil {
		for _, uid := range cur.uids {
			if moved[uid] {
				continue
			}
			for _, s := range sensors {
				if s.uid == uid {
					p.Sensors = append(p.Sensors, SensorMove{Sensor: s.name, UID: s.uid, FromGroup: cur.Name, FromPolicy: label(policyNames, cur.PolicyID),
						ToGroup: cur.Name, ToPolicy: label(policyNames, newPolicy), Connected: s.connected, Unlicensed: unlicensed(features, s)})
				}
			}
		}
	}
	if len(p.moves) > 0 {
		p.Steps = append(p.Steps, fmt.Sprintf("move %d sensor(s)", len(p.moves)))
	}
	for _, m := range p.Sensors {
		if len(m.Unlicensed) > 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf("%s has no active license for %s, which policy %s enables: those features stay off on it",
				m.Sensor, strings.Join(m.Unlicensed, ", "), m.ToPolicy))
		}
		if !m.Connected {
			p.Notes = append(p.Notes, fmt.Sprintf("%s is not connected; it gets the change when it reconnects", m.Sensor))
		}
	}
	if len(p.Sensors) > 0 && newPolicy > 0 {
		p.Notes = append(p.Notes, "sensors that change policy get the new policy's whole configuration; their sensor-specific exceptions stay")
	}
	b, _ := json.Marshal([]any{groups, p.body, p.moves})
	p.state = string(b)
	return p, nil
}

func nullable(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func label(names map[int64]string, id int64) string {
	if id <= 0 {
		return "none"
	}
	return fmt.Sprintf("%q (%d)", names[id], id)
}

// policyFeatures lists the licensed features a policy turns on: settings
// controlled by system.license.<feature>.active whose value (or default)
// is true.
func policyFeatures(ctx context.Context, api API, id int64) ([]string, error) {
	if id <= 0 {
		return nil, nil
	}
	var pol map[string]any
	if err := api.GetJSON(ctx, fmt.Sprintf("%s/%d", pathPolicy, id), nil, &pol); err != nil {
		return nil, fmt.Errorf("reading sensor policy %d: %w", id, err)
	}
	cfg := obj(pol["configuration"])
	seen := map[string]bool{}
	var out []string
	for key, v := range obj(obj(pol["configuration.metadata"])["properties"]) {
		prop := obj(v)
		lic := str(prop["cl:internalController"])
		if !strings.HasPrefix(lic, "system.license.") || str(prop["cl:type"]) != "Boolean" {
			continue
		}
		on := str(prop["cl:default"]) == "1"
		if val, set := cfg[key]; set {
			on = val == true
		}
		feature := strings.TrimSuffix(strings.TrimPrefix(lic, "system.license."), ".active")
		if on && !seen[feature] {
			seen[feature] = true
			out = append(out, feature)
		}
	}
	return out, nil
}

func unlicensed(features []string, s sensorRec) []string {
	var out []string
	for _, f := range features {
		if !s.licenses[f] {
			out = append(out, f)
		}
	}
	return out
}

// GroupResult is what a group change did.
type GroupResult struct {
	Done         []string `json:"done"`
	GroupID      int64    `json:"group_id,omitempty"`
	Verification []string `json:"verification,omitempty"`
}

// ApplyGroup carries out a ready plan and reads the result back.
func ApplyGroup(ctx context.Context, api API, p *GroupPlan) (*GroupResult, error) {
	if !p.Ready() {
		return nil, fmt.Errorf("nothing to do or blocked: %v", p.Blockers)
	}
	res := &GroupResult{GroupID: p.Group.ID}
	switch p.Action {
	case "delete":
		if _, err := api.Do(ctx, http.MethodDelete, fmt.Sprintf("%s/%d", pathGroup, p.Group.ID), nil, nil, ""); err != nil {
			return res, fmt.Errorf("deleting group %s: %w", p.Group, err)
		}
		res.Done = append(res.Done, fmt.Sprintf("deleted sensor group %s", p.Group))
		groups, err := listGroups(ctx, api)
		if err == nil {
			for _, g := range groups {
				if g.ID == p.Group.ID {
					res.Verification = append(res.Verification, "the group is still listed")
				}
			}
		}
		return res, nil
	case "create":
		resp, err := api.Do(ctx, http.MethodPost, pathGroup, nil, jsonBody(p.body), "application/json")
		if err != nil {
			return res, fmt.Errorf("creating group %q: %w", p.Group.Name, err)
		}
		var out map[string]any
		_ = json.Unmarshal(resp.Body, &out)
		res.GroupID = idOf(out["id"])
		if res.GroupID == 0 {
			return res, fmt.Errorf("creating group %q: no id in the response", p.Group.Name)
		}
		res.Done = append(res.Done, fmt.Sprintf("created sensor group %q (%d)", p.Group.Name, res.GroupID))
	case "update":
		if len(p.body) > 0 {
			body := map[string]any{"id": p.Group.ID}
			for k, v := range p.body {
				body[k] = v
			}
			if _, err := api.Do(ctx, http.MethodPut, fmt.Sprintf("%s/%d", pathGroup, p.Group.ID), nil, jsonBody(body), "application/json"); err != nil {
				return res, fmt.Errorf("updating group %s: %w", p.Group, err)
			}
			res.Done = append(res.Done, fmt.Sprintf("updated sensor group %s", p.Group))
		}
	}
	if len(p.moves) > 0 {
		moves := make([]map[string]any, len(p.moves))
		for i, m := range p.moves {
			moves[i] = map[string]any{"uid": m["uid"], "group.id": res.GroupID}
			if g, ok := m["group.id"]; ok {
				moves[i]["group.id"] = g
			}
		}
		if _, err := api.Do(ctx, http.MethodPut, pathCatalog, nil, jsonBody(moves), "application/json"); err != nil {
			return res, fmt.Errorf("moving sensors: %w", err)
		}
		res.Done = append(res.Done, fmt.Sprintf("moved %d sensor(s)", len(moves)))
	}
	// Read back.
	groups, err := listGroups(ctx, api)
	if err != nil {
		res.Verification = append(res.Verification, err.Error())
		return res, nil
	}
	var g *GroupInfo
	for i := range groups {
		if groups[i].ID == res.GroupID {
			g = &groups[i]
		}
	}
	if g == nil {
		res.Verification = append(res.Verification, "the group is not listed")
		return res, nil
	}
	if name, ok := p.body["name"].(string); ok && g.Name != name {
		res.Verification = append(res.Verification, fmt.Sprintf("the group is named %q, not %q", g.Name, name))
	}
	if p.policyID != nil && g.PolicyID != *p.policyID {
		res.Verification = append(res.Verification, fmt.Sprintf("the group's policy is %d, not %d", g.PolicyID, *p.policyID))
	}
	sensors, err := catalog(ctx, api)
	if err == nil {
		for _, m := range p.moves {
			want := res.GroupID
			if v, ok := m["group.id"]; ok {
				want = idOf(v)
			}
			for _, s := range sensors {
				if s.uid == str(m["uid"]) && s.group != want {
					res.Verification = append(res.Verification, fmt.Sprintf("%s is in group %d, not %d", s.name, s.group, want))
				}
			}
		}
	}
	return res, nil
}

func sensorList(sensors []sensorRec) string {
	var out []string
	for _, s := range sensors {
		if s.name == s.uid {
			out = append(out, s.uid)
		} else {
			out = append(out, s.name+" ("+s.uid+")")
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ", ")
}
