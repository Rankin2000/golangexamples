// Package sim provides a lightweight orchestrator for chaining offensive
// techniques into a single end-to-end simulation.
//
// The package exposes two interfaces:
//
//   Technique  - every offensive primitive in the library implements this.
//                Run() executes the technique; Name() and MITRE() are used
//                for logging and dry-run output.
//
//   Cleaner    - optionally implemented by techniques that can revert their
//                own changes (persistence, registry-modifying techniques).
//                One-shot operations such as token theft or LSASS dump do
//                not implement this.
//
// Usage:
//
//   s := sim.New().
//       Add(&persistence.SchTask{PayloadPath: payload}).
//       Add(&persistence.RegistryRunKey{Hive: persistence.HKCU, PayloadPath: payload}).
//       Add(&tokens.Steal{TargetExe: "winlogon.exe", SpawnExe: `C:\Windows\System32\cmd.exe`}).
//       Add(&creds.LSASSDump{OutputPath: `C:\Tools\lsass.dmp`})
//   if err := s.Run(); err != nil { log.Fatal(err) }
package sim

// Technique is implemented by every offensive primitive the library exposes.
type Technique interface {
	// Name returns a stable, human-readable identifier (e.g. "registry-run-key").
	Name() string

	// MITRE returns the ATT&CK technique identifier (e.g. "T1547.001").
	MITRE() string

	// Run executes the technique.  Implementations should validate their
	// configuration before mutating system state.
	Run() error
}

// Cleaner is implemented by techniques whose state changes can be reverted.
type Cleaner interface {
	Cleanup() error
}
