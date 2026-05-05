// Package codegen generates a self-contained _build/main.go from a Profile.
//
// The generated file imports only the TTP packages needed by the selected
// phases, hardcodes all configuration as literals, and exposes a single
// --rollback flag.  Cross-compile it with:
//
//	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o sim.exe ./_build
package codegen

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/rankin2000/golangexamples/profiles"
)

// Options controls what Generate produces.
type Options struct {
	// Profile is the parsed profile to generate from.
	Profile *profiles.Profile

	// EnabledPhases is a set of phase labels to include (nil = all).
	EnabledPhases map[string]bool

	// OutDir is the directory where main.go will be written (default: _build).
	OutDir string

	// Module is the Go module path (default: github.com/rankin2000/golangexamples).
	Module string
}

// Generate writes a _build/main.go file derived from opts and returns the
// directory path so the caller can run go build on it.
func Generate(opts Options) (string, error) {
	if opts.OutDir == "" {
		opts.OutDir = "_build"
	}
	if opts.Module == "" {
		opts.Module = "github.com/rankin2000/golangexamples"
	}

	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", opts.OutDir, err)
	}

	data, err := buildTemplateData(opts)
	if err != nil {
		return "", err
	}

	tmpl, err := template.New("main").Funcs(template.FuncMap{
		"join": strings.Join,
	}).Parse(mainTemplate)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	outPath := filepath.Join(opts.OutDir, "main.go")
	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", outPath, err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return "", fmt.Errorf("render template: %w", err)
	}

	return opts.OutDir, nil
}

// ─── template data ────────────────────────────────────────────────────────────

type templateData struct {
	Module  string
	Imports []string // sorted unique extra imports (persistence, tokens, creds)
	Phases  []phaseData
	UseTime bool // true when any sleep > 0
}

type phaseData struct {
	Label string
	Sleep string // Go expression, e.g. "48*time.Hour" or "0"
	TTPs  []ttpData
}

type ttpData struct {
	Expr string // Go expression producing a sim.TTP, e.g. &persistence.SchTask{...}
}

func buildTemplateData(opts Options) (templateData, error) {
	data := templateData{Module: opts.Module}
	importSet := map[string]bool{}

	for _, pc := range opts.Profile.Phases {
		if !phaseEnabled(pc, opts.EnabledPhases) {
			continue
		}

		sleep, err := time.ParseDuration(pc.Sleep)
		if err != nil {
			return data, fmt.Errorf("phase %q: bad sleep %q: %w", pc.Label, pc.Sleep, err)
		}

		if sleep > 0 {
			data.UseTime = true
		}

		pd := phaseData{
			Label: pc.Label,
			Sleep: durationExpr(sleep),
		}

		for _, tc := range pc.TTPs {
			expr, pkg, err := ttpExpr(tc)
			if err != nil {
				return data, fmt.Errorf("phase %q ttp %q: %w", pc.Label, tc.TTP, err)
			}
			pd.TTPs = append(pd.TTPs, ttpData{Expr: expr})
			if pkg != "" {
				importSet[opts.Module+"/pkg/"+pkg] = true
			}
		}
		data.Phases = append(data.Phases, pd)
	}

	for imp := range importSet {
		data.Imports = append(data.Imports, imp)
	}

	return data, nil
}

func phaseEnabled(pc profiles.PhaseConfig, enabled map[string]bool) bool {
	if !pc.IsEnabled() {
		return false
	}
	if enabled == nil {
		return true
	}
	return enabled[pc.Label]
}

// durationExpr converts a duration to a Go source expression.
func durationExpr(d time.Duration) string {
	if d == 0 {
		return "0"
	}
	if d%time.Hour == 0 {
		return fmt.Sprintf("%d*time.Hour", int(d.Hours()))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%d*time.Minute", int(d.Minutes()))
	}
	if d%time.Second == 0 {
		return fmt.Sprintf("%d*time.Second", int(d.Seconds()))
	}
	return fmt.Sprintf("time.Duration(%d)", int64(d))
}

// ttpExpr returns a Go source expression and the pkg/ sub-package name.
func ttpExpr(cfg profiles.TTPConfig) (expr string, pkg string, err error) {
	q := func(s string) string { return fmt.Sprintf("%q", s) }

	switch cfg.TTP {
	case "schtask":
		return fmt.Sprintf(
			`&persistence.SchTask{TaskName: %s, PayloadPath: %s, UseXML: %v, Delay: %s}`,
			q(cfg.TaskName), q(cfg.PayloadPath), cfg.UseXML, q(cfg.Delay),
		), "persistence", nil

	case "registry-run-key":
		hive := "persistence.HKCU"
		if strings.EqualFold(cfg.Hive, "hklm") {
			hive = "persistence.HKLM"
		}
		return fmt.Sprintf(
			`&persistence.RegistryRunKey{Hive: %s, ValueName: %s, PayloadPath: %s}`,
			hive, q(cfg.ValueName), q(cfg.PayloadPath),
		), "persistence", nil

	case "startup-folder":
		return fmt.Sprintf(
			`&persistence.StartupFolder{PayloadPath: %s, DropName: %s, UseLNK: %v}`,
			q(cfg.PayloadPath), q(cfg.DropName), cfg.UseLNK,
		), "persistence", nil

	case "service":
		argsLit := argsSliceLiteral(cfg.Args)
		return fmt.Sprintf(
			`&persistence.Service{ServiceName: %s, DisplayName: %s, Description: %s, ExePath: %s, Args: %s}`,
			q(cfg.ServiceName), q(cfg.DisplayName), q(cfg.Description), q(cfg.ExePath), argsLit,
		), "persistence", nil

	case "com-hijack":
		return fmt.Sprintf(
			`&persistence.COMHijack{CLSID: %s, DLLPath: %s, ThreadingModel: %s}`,
			q(cfg.CLSID), q(cfg.DLLPath), q(cfg.ThreadingModel),
		), "persistence", nil

	case "token-steal":
		return fmt.Sprintf(
			`&tokens.Steal{TargetExe: %s, SpawnExe: %s, EnableSeDebug: %v}`,
			q(cfg.TargetExe), q(cfg.SpawnExe), cfg.EnableSeDebug,
		), "tokens", nil

	case "lsass-dump":
		return fmt.Sprintf(
			`&creds.LSASSDump{OutputPath: %s, EnableSeDebug: %v}`,
			q(cfg.OutputPath), cfg.EnableSeDebug,
		), "creds", nil

	default:
		return "", "", fmt.Errorf("unknown ttp %q", cfg.TTP)
	}
}

func argsSliceLiteral(args []string) string {
	if len(args) == 0 {
		return "nil"
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	return "[]string{" + strings.Join(quoted, ", ") + "}"
}

// ─── generated file template ─────────────────────────────────────────────────

const mainTemplate = `// Code generated by cmd/builder. DO NOT EDIT.
// Build: GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o sim.exe ./_build
//go:build windows

package main

import (
	"flag"
	"log"
{{- if .UseTime}}
	"time"
{{- end}}

	"{{.Module}}/pkg/sim"
{{- range .Imports}}
	"{{.}}"
{{- end}}
)

func main() {
	rollback := flag.Bool("rollback", false, "undo all installed persistence")
	flag.Parse()

	s := sim.New()
{{range .Phases}}
	s.AddPhase({{printf "%q" .Label}}, {{.Sleep}},
{{- range .TTPs}}
		{{.Expr}},
{{- end}}
	)
{{end}}
	if *rollback {
		if err := s.Rollback(); err != nil {
			log.Fatalf("[-] rollback: %v", err)
		}
		log.Println("[+] rollback complete")
		return
	}

	if err := s.Run(); err != nil {
		log.Fatalf("[-] sim: %v", err)
	}
}
`
