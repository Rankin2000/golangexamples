package sim

import "time"

// Phase groups a set of TTPs that execute together, with an optional dwell
// period afterward to simulate APT timing between kill-chain stages.
type Phase struct {
	Label   string
	TTPs    []TTP
	Sleep   time.Duration // dwell time after this phase; 0 = proceed immediately
	Enabled bool          // false = skip phase entirely (useful for profiling)
}
