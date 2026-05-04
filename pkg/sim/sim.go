package sim

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// Sim chains a sequence of techniques into a single executable plan.
// Run order is FIFO; Cleanup order is LIFO so later changes are reverted
// before earlier ones (matching defer-style semantics).
type Sim struct {
	techniques []Technique
	Logger     *log.Logger
}

// New returns a Sim that logs to stderr.
func New() *Sim {
	return &Sim{Logger: log.New(os.Stderr, "", log.LstdFlags)}
}

// SetOutput redirects log output (useful in tests or when chaining loggers).
func (s *Sim) SetOutput(w io.Writer) {
	s.Logger.SetOutput(w)
}

// Add appends a technique to the plan and returns the receiver to allow chaining.
func (s *Sim) Add(t Technique) *Sim {
	s.techniques = append(s.techniques, t)
	return s
}

// Run executes each technique in order.  Stops at the first failure and
// returns its error wrapped with the technique name.  Already-applied
// techniques are NOT automatically rolled back; call Cleanup for that.
func (s *Sim) Run() error {
	for _, t := range s.techniques {
		s.Logger.Printf("[*] run %s (%s)", t.Name(), t.MITRE())
		if err := t.Run(); err != nil {
			return fmt.Errorf("%s: %w", t.Name(), err)
		}
		s.Logger.Printf("[+] %s done", t.Name())
	}
	return nil
}

// Cleanup invokes Cleanup() on every technique that implements Cleaner, in
// reverse insertion order.  Errors are accumulated; iteration continues so
// that a single failure does not strand later cleanup steps.
func (s *Sim) Cleanup() error {
	var errs []string
	for i := len(s.techniques) - 1; i >= 0; i-- {
		t := s.techniques[i]
		c, ok := t.(Cleaner)
		if !ok {
			continue
		}
		s.Logger.Printf("[*] cleanup %s", t.Name())
		if err := c.Cleanup(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", t.Name(), err))
		}
	}
	if len(errs) > 0 {
		return errors.New("cleanup: " + strings.Join(errs, "; "))
	}
	return nil
}

// Plan returns "name (MITRE)" strings for every queued technique without
// executing anything - useful for dry-run logging in red-team reports.
func (s *Sim) Plan() []string {
	out := make([]string, 0, len(s.techniques))
	for _, t := range s.techniques {
		out = append(out, fmt.Sprintf("%s (%s)", t.Name(), t.MITRE()))
	}
	return out
}
