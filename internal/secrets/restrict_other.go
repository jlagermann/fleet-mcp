//go:build !windows

package secrets

import "os"

func restrict(dir string) error {
	return os.Chmod(dir, 0o700)
}
