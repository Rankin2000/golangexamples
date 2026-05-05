// cmd/builder is the operator-side TUI for composing and cross-compiling
// a lean sim.exe from a YAML profile.
//
// Usage:
//
//	builder --profile profiles/fin7.yaml --output sim.exe
//
// The tool presents a BubbleTea TUI that lets the operator:
//  1. Review and toggle individual phases/TTPs
//  2. Preview the generated execution plan
//  3. Cross-compile a sim.exe containing only the selected techniques
//
// The resulting sim.exe accepts only --rollback (no profile, no dry-run flags).
// Deploy it to the target environment as a standalone binary.
//
// Build this tool (runs on Linux/Mac):
//
//	go build -o builder ./cmd/builder
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rankin2000/golangexamples/profiles"
)

func main() {
	profilePath := flag.String("profile", "", "path to YAML profile (required)")
	output := flag.String("output", "sim.exe", "output binary path")
	flag.Parse()

	if *profilePath == "" {
		// If no profile given, list available ones from the profiles/ directory
		matches, _ := filepath.Glob("profiles/*.yaml")
		if len(matches) == 0 {
			fmt.Fprintln(os.Stderr, "[-] no profile specified and no profiles/*.yaml found")
			fmt.Fprintln(os.Stderr, "    usage: builder --profile profiles/fin7.yaml")
			os.Exit(1)
		}
		// Default to the first match with a hint
		*profilePath = matches[0]
		fmt.Fprintf(os.Stderr, "[*] no --profile given, using %s\n", *profilePath)
	}

	profile, err := profiles.ParseProfile(*profilePath)
	if err != nil {
		log.Fatalf("[-] load profile: %v", err)
	}

	m := newModel(profile, *output)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatalf("[-] tui: %v", err)
	}
}
