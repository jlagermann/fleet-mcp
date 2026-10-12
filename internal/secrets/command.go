package secrets

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Command returns the terminal command that runs this fleet-mcp binary
// with args, by its full path: fleet-mcp is often not on the user's PATH.
// Arguments containing spaces are quoted.
func Command(args ...string) string {
	parts := []string{exe()}
	for _, a := range args {
		parts = append(parts, quote(a))
	}
	return strings.Join(parts, " ")
}

func exe() string {
	p, err := os.Executable()
	if err != nil || !strings.HasPrefix(strings.ToLower(filepath.Base(p)), "fleet-mcp") {
		return "fleet-mcp" // a test binary, or the path is unknown
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	if runtime.GOOS == "windows" {
		return `& "` + p + `"` // PowerShell
	}
	return quote(p)
}

func quote(s string) string {
	if !strings.ContainsAny(s, " \t'\"") {
		return s
	}
	if runtime.GOOS == "windows" {
		return `"` + s + `"`
	}
	return `'` + strings.ReplaceAll(s, `'`, `'\''`) + `'`
}
