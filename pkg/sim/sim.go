package sim

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// Sim orchestrates a sequence of Phases, each containing one or more TTPs.
// Phases execute in order; TTPs within a phase execute in order.
// Errors within a TTP are recorded in the JSON report but do not halt
// the run — operators see the full pass/fail picture across all techniques.
type Sim struct {
	Phases     []Phase
	DryRun     bool
	ReportPath string // JSON report destination; default "mitre_report.json"
	Logger     *log.Logger
}

// New returns a Sim writing logs to stderr with a default report path.
func New() *Sim {
	return &Sim{
		Logger:     log.New(os.Stderr, "", log.LstdFlags),
		ReportPath: "mitre_report.json",
	}
}

// SetOutput redirects log output (useful in tests).
func (s *Sim) SetOutput(w io.Writer) {
	s.Logger.SetOutput(w)
}

// AddPhase appends a phase and returns the receiver for chaining.
func (s *Sim) AddPhase(label string, sleep time.Duration, ttps ...TTP) *Sim {
	s.Phases = append(s.Phases, Phase{
		Label:   label,
		TTPs:    ttps,
		Sleep:   sleep,
		Enabled: true,
	})
	return s
}

// Plan returns a human-readable description of every phase and TTP without
// executing anything.  Use this for dry-run logging and pre-flight review.
func (s *Sim) Plan() []string {
	var lines []string
	for i, ph := range s.Phases {
		state := ""
		if !ph.Enabled {
			state = " [disabled]"
		}
		lines = append(lines, fmt.Sprintf(
			"phase %d: %s  sleep=%s%s", i+1, ph.Label, ph.Sleep, state,
		))
		for _, t := range ph.TTPs {
			lines = append(lines, "  - "+ttpLabel(t))
		}
	}
	return lines
}

// Run executes all enabled phases in insertion order.
// Between phases it sleeps for Phase.Sleep (unless DryRun or 0).
// A JSON report is written to ReportPath when the run finishes.
func (s *Sim) Run() error {
	start := time.Now()
	report := Report{
		Timestamp: start.UTC(),
		DryRun:    s.DryRun,
	}

	for i, ph := range s.Phases {
		pr := PhaseResult{
			Label:   ph.Label,
			Sleep:   ph.Sleep.String(),
			Enabled: ph.Enabled,
		}

		if !ph.Enabled {
			s.Logger.Printf("[skip]  phase %q (disabled)", ph.Label)
			report.Phases = append(report.Phases, pr)
			continue
		}

		s.Logger.Printf("[phase] %s", ph.Label)

		for _, t := range ph.TTPs {
			tr := TTPResult{ID: t.ID()}
			s.Logger.Printf("  [*]   %s", ttpLabel(t))

			if s.DryRun {
				tr.Status = "dry-run"
				s.Logger.Printf("  [dry] skipped")
			} else if err := t.Run(); err != nil {
				tr.Status = "fail"
				tr.Error = err.Error()
				s.Logger.Printf("  [-]   %v", err)
			} else {
				tr.Status = "pass"
				s.Logger.Printf("  [+]   done")
			}

			pr.TTPs = append(pr.TTPs, tr)
		}

		report.Phases = append(report.Phases, pr)

		if ph.Sleep > 0 && !s.DryRun && i < len(s.Phases)-1 {
			s.Logger.Printf("[sleep] %s", ph.Sleep)
			time.Sleep(ph.Sleep)
		}
	}

	report.Duration = time.Since(start).Round(time.Millisecond).String()

	if err := writeReport(s.ReportPath, report); err != nil {
		s.Logger.Printf("[warn]  report write failed: %v", err)
	}
	return nil
}

// Rollback calls Rollback() on every TTP in reverse phase order, reverse TTP
// order within each phase.  Errors are accumulated; iteration always continues.
func (s *Sim) Rollback() error {
	var errs []string
	for i := len(s.Phases) - 1; i >= 0; i-- {
		ph := s.Phases[i]
		if !ph.Enabled {
			continue
		}
		s.Logger.Printf("[rollback] phase %q", ph.Label)
		for j := len(ph.TTPs) - 1; j >= 0; j-- {
			t := ph.TTPs[j]
			s.Logger.Printf("  [*] rollback %s", ttpLabel(t))
			if err := t.Rollback(); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", t.ID(), err))
				s.Logger.Printf("  [-] %v", err)
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("rollback: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ttpLabel returns "name (ID)" if the TTP exposes a Name() method, else just ID.
func ttpLabel(t TTP) string {
	type namer interface{ Name() string }
	if n, ok := t.(namer); ok {
		return fmt.Sprintf("%s (%s)", n.Name(), t.ID())
	}
	return t.ID()
}
