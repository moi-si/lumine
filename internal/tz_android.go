//go:build android && arm64

package lumine

import (
	"os/exec"
	"strings"
	"time"
)

func init() {
	cmd := exec.Command("getprop", "persist.sys.timezone")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	timezone := strings.TrimSpace(string(output))
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return
	}
	time.Local = location
}
