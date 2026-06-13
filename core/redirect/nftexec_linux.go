//go:build linux

package redirect

import (
	"fmt"
	"os/exec"
	"strings"
)

// runNftErr runs nft with the given arguments and returns a descriptive error
// (including stderr) on failure.
func runNftErr(args []string) error {
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
