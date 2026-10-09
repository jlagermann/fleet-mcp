package jsonview

import (
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// Change is one difference between two JSON documents.
type Change struct {
	Path string `json:"path"` // JSON Pointer
	Op   string `json:"op"`   // "add", "remove" or "change"
	From any    `json:"from,omitempty"`
	To   any    `json:"to,omitempty"`
}

// Diff lists the differences from a to b, at most limit entries (0 = all).
// Objects are compared key by key; arrays and scalars are compared whole
// unless both are arrays of equal length.
func Diff(a, b any, limit int) (changes []Change, truncated bool) {
	var walk func(p string, x, y any) bool
	walk = func(p string, x, y any) bool {
		if limit > 0 && len(changes) >= limit {
			return false
		}
		xm, xok := x.(map[string]any)
		ym, yok := y.(map[string]any)
		if xok && yok {
			keys := map[string]bool{}
			for k := range xm {
				keys[k] = true
			}
			for k := range ym {
				keys[k] = true
			}
			sorted := make([]string, 0, len(keys))
			for k := range keys {
				sorted = append(sorted, k)
			}
			sort.Strings(sorted)
			for _, k := range sorted {
				cp := p + "/" + escape(k)
				xv, inX := xm[k]
				yv, inY := ym[k]
				switch {
				case !inX:
					changes = append(changes, Change{Path: cp, Op: "add", To: yv})
				case !inY:
					changes = append(changes, Change{Path: cp, Op: "remove", From: xv})
				default:
					if !walk(cp, xv, yv) {
						return false
					}
					continue
				}
				if limit > 0 && len(changes) >= limit {
					return false
				}
			}
			return true
		}
		xa, xok := x.([]any)
		ya, yok := y.([]any)
		if xok && yok && len(xa) == len(ya) {
			for i := range xa {
				if !walk(p+"/"+strconv.Itoa(i), xa[i], ya[i]) {
					return false
				}
			}
			return true
		}
		if !equal(x, y) {
			changes = append(changes, Change{Path: p, Op: "change", From: x, To: y})
		}
		return true
	}
	if !walk("", a, b) {
		truncated = true
	}
	return changes, truncated
}

// equal compares decoded JSON, treating numbers by value.
func equal(x, y any) bool {
	if reflect.DeepEqual(x, y) {
		return true
	}
	bx, _ := json.Marshal(x)
	by, _ := json.Marshal(y)
	return string(bx) == string(by)
}

func escape(k string) string {
	return strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
}
