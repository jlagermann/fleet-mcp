// Package jsonview trims decoded JSON so tool results stay small: select a
// sub-tree, keep chosen fields, page through arrays and cap the output size.
//
// Fleet Manager keys often contain dots ("ping.last", "health.status"), so
// paths use JSON Pointer syntax (RFC 6901): "/list/0/health.status".
package jsonview

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Options controls View.
type Options struct {
	// Select is a JSON Pointer to the part of the document to return.
	Select string
	// Fields keeps only these pointers (relative to each array element, or
	// to the selected object). A field may omit the leading "/".
	Fields []string
	// Offset and Limit page through the selected array. Limit 0 means all.
	Offset, Limit int
	// MaxBytes caps the encoded result. 0 means no cap.
	MaxBytes int
}

// Result is the trimmed document plus notes about what was left out.
type Result struct {
	JSON  []byte
	Notes []string
}

// View applies opts to v and encodes the result.
func View(v any, opts Options) (*Result, error) {
	res := &Result{}
	node, err := Get(v, opts.Select)
	if err != nil {
		return nil, err
	}
	if arr, ok := node.([]any); ok {
		total := len(arr)
		start := min(max(opts.Offset, 0), total)
		end := total
		if opts.Limit > 0 && start+opts.Limit < total {
			end = start + opts.Limit
		}
		if start != 0 || end != total {
			res.Notes = append(res.Notes, fmt.Sprintf("showing items %d-%d of %d", start, end-1, total))
		}
		arr = arr[start:end]
		if len(opts.Fields) > 0 {
			out := make([]any, len(arr))
			for i, el := range arr {
				out[i] = Project(el, opts.Fields)
			}
			arr = out
		}
		node = arr
	} else if len(opts.Fields) > 0 {
		node = Project(node, opts.Fields)
	}

	b, err := json.Marshal(node)
	if err != nil {
		return nil, err
	}
	if opts.MaxBytes > 0 && len(b) > opts.MaxBytes {
		if arr, ok := node.([]any); ok {
			// Drop whole items rather than cutting JSON in the middle.
			n := fitItems(arr, opts.MaxBytes)
			b, _ = json.Marshal(arr[:n])
			res.Notes = append(res.Notes, fmt.Sprintf("output capped at %d bytes: returned %d of %d items; use offset/limit, fields or select to see more", opts.MaxBytes, n, len(arr)))
		} else {
			full := len(b)
			b = b[:opts.MaxBytes]
			res.Notes = append(res.Notes, fmt.Sprintf("output truncated to %d of %d bytes (not valid JSON); use select or fields to narrow it", opts.MaxBytes, full))
		}
	}
	res.JSON = b
	return res, nil
}

func fitItems(arr []any, maxBytes int) int {
	size := 2 // brackets
	for i, el := range arr {
		b, _ := json.Marshal(el)
		size += len(b) + 1
		if size > maxBytes {
			return i
		}
	}
	return len(arr)
}

// Get returns the value at a JSON Pointer. "" or "/" is the whole document.
func Get(v any, pointer string) (any, error) {
	if pointer == "" || pointer == "/" {
		return v, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		pointer = "/" + pointer
	}
	cur := v
	for _, raw := range strings.Split(pointer[1:], "/") {
		tok := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch t := cur.(type) {
		case map[string]any:
			next, ok := t[tok]
			if !ok {
				return nil, fmt.Errorf("select %q: no key %q", pointer, tok)
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(t) {
				return nil, fmt.Errorf("select %q: bad array index %q (length %d)", pointer, tok, len(t))
			}
			cur = t[i]
		default:
			return nil, fmt.Errorf("select %q: cannot descend into %T at %q", pointer, cur, tok)
		}
	}
	return cur, nil
}

// Project keeps only the given field pointers of an object. Missing fields
// are left out. Output keys are the field strings as given.
func Project(v any, fields []string) any {
	if _, ok := v.(map[string]any); !ok {
		return v
	}
	out := make(map[string]any, len(fields))
	for _, f := range fields {
		if val, err := Get(v, f); err == nil {
			out[strings.TrimPrefix(f, "/")] = val
		}
	}
	return out
}

// Lookup is Get without the error, for building summaries.
func Lookup(v any, pointer string) any {
	val, _ := Get(v, pointer)
	return val
}
