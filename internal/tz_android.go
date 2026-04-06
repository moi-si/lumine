//go:build android

package lumine

import (
	"os/exec"
	"strings"
	"time"
)

func init() {
	output, err := exec.Command("getprop", "persist.sys.timezone").Output()
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
