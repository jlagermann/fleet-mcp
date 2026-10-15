package policyedit

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// DeleteRequest deletes a sensor policy and, optionally, objects only it
// uses.
type DeleteRequest struct {
	Policy string `json:"policy" jsonschema:"sensor policy id or exact name"`
	// RemoveUnused names the referenced objects to delete as well; only
	// objects no other sensor policy uses can be removed.
	RemoveUnused []string `json:"remove_unused,omitempty" jsonschema:"objects only this policy uses to delete too: all, or any of suricata_policy, yara_ruleset, intel_collection, input_collection, resource_collection, ca_bundle_collection, bundle (the preview lists them; ask the user)"`
}

var removeNames = map[string]string{"suricataPolicyID": "suricata_policy", "yaraRulesetID": "yara_ruleset", "intelCollectionID": "intel_collection",
	"inputCollectionID": "input_collection", "resourceCollectionID": "resource_collection", "caBundleCollectionID": "ca_bundle_collection", "bundle.id": "bundle"}

// Reference is an object a policy links to.
type Reference struct {
	Kind   string   `json:"kind"`
	What   string   `json:"what"`
	Object Ref      `json:"object"`
	UsedBy []string `json:"also_used_by,omitempty"`
	Remove bool     `json:"remove"`
	field  string
	ctype  string
}

// DeletePlan is what a delete will do; the exported fields are the preview.
type DeletePlan struct {
	Policy     Ref         `json:"policy"`
	Groups     []GroupInfo `json:"groups_using_it,omitempty"`
	References []Reference `json:"references"`
	Steps      []string    `json:"steps"`
	Notes      []string    `json:"notes,omitempty"`
	Blockers   []string    `json:"blockers,omitempty"`
	state      string
}

// Ready reports whether the delete can go ahead.
func (p *DeletePlan) Ready() bool { return len(p.Blockers) == 0 }

// State is what the plan was built from, for the confirm token.
func (p *DeletePlan) State() string { return p.state }

// PrepareDelete lists what the policy references and which of those no
// other policy uses. It changes nothing.
func PrepareDelete(ctx context.Context, api API, req DeleteRequest) (*DeletePlan, error) {
	ref, pol, err := resolvePolicy(ctx, api, req.Policy)
	if err != nil {
		return nil, err
	}
	p := &DeletePlan{Policy: ref}
	if pol["isGlobal"] == true {
		p.Blockers = append(p.Blockers, "this is the global policy; Fleet Manager does not let it be deleted")
	}
	if p.Groups, err = groupsUsing(ctx, api, ref.ID); err != nil {
		return nil, err
	}
	for _, g := range p.Groups {
		p.Blockers = append(p.Blockers, fmt.Sprintf("sensor group %q (%d sensor(s)) uses this policy: give the group another policy first (fm_group_manage)", g.Name, len(g.Sensors)))
	}
	want := map[string]bool{}
	for _, r := range req.RemoveUnused {
		want[strings.ToLower(strings.TrimSpace(r))] = true
	}
	all, err := policies(ctx, api)
	if err != nil {
		return nil, err
	}
	var state []string
	for _, l := range links {
		id := idOf(pol[l.Field])
		if id == 0 {
			continue
		}
		r := Reference{Kind: removeNames[l.Field], What: l.What, Object: Ref{ID: id}, field: l.Field, ctype: l.CollectionType}
		if refs, err := named(ctx, api, l.Field, l.CollectionType); err == nil {
			for _, x := range refs {
				if x.ID == id {
					r.Object.Name = x.Name
				}
			}
		}
		for _, other := range all {
			if idOf(other["id"]) != ref.ID && idOf(other[l.Field]) == id {
				r.UsedBy = append(r.UsedBy, fmt.Sprintf("%s (%d)", str(other["name"]), idOf(other["id"])))
			}
		}
		if want["all"] || want[r.Kind] {
			if len(r.UsedBy) > 0 {
				p.Notes = append(p.Notes, fmt.Sprintf("%s %s is kept: other policies use it", r.What, r.Object))
			} else {
				r.Remove = true
			}
		}
		delete(want, r.Kind)
		p.References = append(p.References, r)
		state = append(state, fmt.Sprintf("%s=%d", l.Field, id))
	}
	delete(want, "all")
	for k := range want {
		p.Blockers = append(p.Blockers, fmt.Sprintf("remove_unused %q: the policy has no such reference (kinds: all, suricata_policy, yara_ruleset, intel_collection, input_collection, resource_collection, ca_bundle_collection, bundle)", k))
	}
	p.Steps = append(p.Steps, fmt.Sprintf("delete sensor policy %s", ref))
	for _, r := range p.References {
		switch {
		case r.Remove:
			p.Steps = append(p.Steps, fmt.Sprintf("delete %s %s", r.What, r.Object))
		case len(r.UsedBy) == 0:
			p.Notes = append(p.Notes, fmt.Sprintf("%s %s is used only by this policy; it stays unless remove_unused includes %s", r.What, r.Object, r.Kind))
		}
		if r.Remove && r.ctype != "" {
			p.Notes = append(p.Notes, fmt.Sprintf("deleting %s %s keeps its file sources (they may be in other collections)", r.What, r.Object))
		}
		if r.Remove && r.field == "yaraRulesetID" {
			p.Notes = append(p.Notes, fmt.Sprintf("deleting YARA ruleset %s keeps its YARA sources", r.Object))
		}
	}
	p.state = fmt.Sprintf("%d|%s|%v", ref.ID, str(pol["record.updated-at"]), state)
	return p, nil
}

// DeleteResult is what a delete did.
type DeleteResult struct {
	Done         []string `json:"done"`
	Verification []string `json:"verification,omitempty"`
}

// ApplyDelete deletes the policy, then the objects chosen for removal.
func ApplyDelete(ctx context.Context, api API, p *DeletePlan) (*DeleteResult, error) {
	if !p.Ready() {
		return nil, fmt.Errorf("blocked: %v", p.Blockers)
	}
	res := &DeleteResult{}
	if _, err := api.Do(ctx, http.MethodDelete, fmt.Sprintf("%s/%d", pathPolicy, p.Policy.ID), nil, nil, ""); err != nil {
		return res, fmt.Errorf("deleting sensor policy %s: %w", p.Policy, err)
	}
	res.Done = append(res.Done, fmt.Sprintf("deleted sensor policy %s", p.Policy))
	var failed []string
	for _, r := range p.References {
		if !r.Remove {
			continue
		}
		if err := deleteObject(ctx, api, r); err != nil {
			failed = append(failed, fmt.Sprintf("%s %s: %v", r.What, r.Object, err))
			continue
		}
		res.Done = append(res.Done, fmt.Sprintf("deleted %s %s", r.What, r.Object))
	}
	// Read back: the policy and the removed objects are gone.
	list, err := policies(ctx, api)
	if err == nil {
		for _, x := range list {
			if idOf(x["id"]) == p.Policy.ID {
				res.Verification = append(res.Verification, "the sensor policy is still listed")
			}
		}
	}
	for _, r := range p.References {
		if !r.Remove {
			continue
		}
		refs, err := named(ctx, api, r.field, r.ctype)
		if err != nil {
			continue
		}
		for _, x := range refs {
			if x.ID == r.Object.ID {
				res.Verification = append(res.Verification, fmt.Sprintf("%s %s still exists", r.What, r.Object))
			}
		}
	}
	if len(failed) > 0 {
		return res, fmt.Errorf("the policy was deleted, but removing these failed: %s", strings.Join(failed, "; "))
	}
	return res, nil
}

func deleteObject(ctx context.Context, api API, r Reference) error {
	id := fmt.Sprint(r.Object.ID)
	switch r.field {
	case "suricataPolicyID":
		_, err := api.Do(ctx, http.MethodDelete, fmt.Sprintf("%s/%d", pathSuricata, r.Object.ID), nil, nil, "")
		return err
	case "bundle.id":
		_, err := api.Do(ctx, http.MethodDelete, fmt.Sprintf("%s/%d", pathBundle, r.Object.ID), nil, nil, "")
		return err
	case "yaraRulesetID":
		return gql(ctx, api, `mutation($ids: [ID!]!) { deleteYaraRulesets(ids: $ids) { message } }`, map[string]any{"ids": []string{id}}, nil)
	default:
		return gql(ctx, api, `mutation($ids: [ID!]!) { deleteFileCollections(ids: $ids) { message } }`, map[string]any{"ids": []string{id}}, nil)
	}
}
