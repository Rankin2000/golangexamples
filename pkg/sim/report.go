package sim

import (
	"encoding/json"
	"os"
	"time"
)

// Report is the JSON artifact written after every Run().
type Report struct {
	Timestamp time.Time     `json:"timestamp"`
	Duration  string        `json:"duration"`
	DryRun    bool          `json:"dry_run"`
	Phases    []PhaseResult `json:"phases"`
}

// PhaseResult captures execution outcome for a single Phase.
type PhaseResult struct {
	Label   string      `json:"label"`
	Sleep   string      `json:"sleep"`
	Enabled bool        `json:"enabled"`
	TTPs    []TTPResult `json:"ttps"`
}

// TTPResult captures execution outcome for a single TTP.
type TTPResult struct {
	ID     string `json:"id"`
	Status string `json:"status"` // "pass" | "fail" | "dry-run" | "skipped"
	Error  string `json:"error,omitempty"`
}

func writeReport(path string, r Report) error {
	if path == "" {
		return nil
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
