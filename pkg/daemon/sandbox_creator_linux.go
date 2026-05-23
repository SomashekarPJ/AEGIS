//go:build linux

package daemon

import (
	"aegiscore/pkg/config"
	"aegiscore/pkg/sandbox"
)

func createTargetSandbox(id string, name string, workloadPath string, policy *config.Policy, eventChan chan interface{}) sandbox.Sandbox {
	return sandbox.NewLinuxSandbox(id, name, workloadPath, policy, eventChan)
}
