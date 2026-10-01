package cases

import (
	"os"
	"os/exec"
)

// allowedActions names the operator actions runAction will accept.
var allowedActions = map[string]bool{
	"status":  true,
	"reload":  true,
	"restart": true,
}

// runAction runs one of the operator actions named in allowedActions against nginx.
func runAction(action string) ([]byte, error) {
	if !allowedActions[action] {
		return nil, os.ErrInvalid
	}
	return exec.Command("systemctl", action, "nginx").Output()
}
