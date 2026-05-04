// Package persistence holds techniques that ensure a payload survives
// reboot or user logoff.  Every technique implements sim.TTP.
package persistence

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// RegistryHive selects the registry root for RegistryRunKey.
type RegistryHive int

const (
	HKCU RegistryHive = iota // current user; no admin required
	HKLM                     // local machine; admin required
)

// RegistryRunKey writes a value under the Windows Run key so the payload
// executes at every user logon.  MITRE T1547.001.
type RegistryRunKey struct {
	Hive        RegistryHive // HKCU (default) or HKLM
	ValueName   string       // default: "WindowsUpdateHelper"
	PayloadPath string       // required
}

func (r *RegistryRunKey) Name() string { return "registry-run-key" }
func (r *RegistryRunKey) ID() string   { return "T1547.001" }

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

func (r *RegistryRunKey) hive() registry.Key {
	if r.Hive == HKLM {
		return registry.LOCAL_MACHINE
	}
	return registry.CURRENT_USER
}

func (r *RegistryRunKey) valueName() string {
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
	return k.SetStringValue(r.valueName(), r.PayloadPath)
}

func (r *RegistryRunKey) Rollback() error {
	k, err := registry.OpenKey(r.hive(), runKeyPath, registry.SET_VALUE)
	if err != nil {
		return nil // already gone
	}
	defer k.Close()
	if err := k.DeleteValue(r.valueName()); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}
