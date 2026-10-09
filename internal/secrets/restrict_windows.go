//go:build windows

package secrets

import (
	"fmt"
	"os/exec"
	"os/user"
)

// restrict removes inherited permissions from dir and grants full control
// to the current user only; files created inside inherit that.
func restrict(dir string) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	out, err := exec.Command("icacls", dir, "/inheritance:r", "/grant:r", u.Username+":(OI)(CI)F").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %v: %s", err, out)
	}
	return nil
}
