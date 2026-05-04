// Package sim provides a phased simulation orchestrator for purple-team
// and detection-engineering exercises.
//
// Build a sim by chaining AddPhase calls, then call Run() to execute and
// produce a MITRE-mapped JSON report.  Call Rollback() to revert all
// reversible state changes in LIFO order.
package sim

// TTP is the interface every offensive primitive in this library implements.
type TTP interface {
	// ID returns the ATT&CK technique identifier, e.g. "T1053.005".
	ID() string

	// Run executes the technique.
	Run() error

	// Rollback reverts any state changes made by Run.
	// Techniques with no reversible state (token theft, LSASS dump) return nil.
	Rollback() error
}
