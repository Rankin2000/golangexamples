package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/rankin2000/golangexamples/internal/codegen"
	"github.com/rankin2000/golangexamples/profiles"
)

// ─── screens ──────────────────────────────────────────────────────────────────

type screen int

const (
	screenPlan  screen = iota // phase/TTP toggle list
	screenBuild               // spinner while compiling
	screenDone                // result / error
)

// ─── styles ───────────────────────────────────────────────────────────────────

var (
	styleBold    = lipgloss.NewStyle().Bold(true)
	stylePhase   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("33"))
	styleEnabled = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleDim     = lipgloss.NewStyle().Faint(true)
	styleError   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleOK      = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleCursor  = lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Bold(true)
)

// ─── model ────────────────────────────────────────────────────────────────────

// item represents one row in the plan list (either a phase header or a TTP).
type item struct {
	phaseIdx int    // which phase
	ttpIdx   int    // -1 = phase header row
	label    string // display text
}

type model struct {
	profile  *profiles.Profile
	output   string
	enabled  [][]bool // [phaseIdx][ttpIdx] → enabled
	items    []item   // flattened list of rows
	cursor   int
	screen   screen
	spinner  spinner.Model
	buildErr error
	buildOut string
}

type buildDoneMsg struct {
	err error
	out string
}

func newModel(profile *profiles.Profile, output string) model {
	// Default all phases and TTPs to their profile setting.
	enabled := make([][]bool, len(profile.Phases))
	for i, pc := range profile.Phases {
		enabled[i] = make([]bool, len(pc.TTPs))
		for j := range pc.TTPs {
			enabled[i][j] = pc.IsEnabled()
		}
	}

	// Build the flat item list for the cursor.
	var items []item
	for i, pc := range profile.Phases {
		items = append(items, item{phaseIdx: i, ttpIdx: -1, label: pc.Label})
		for j, tc := range pc.TTPs {
			items = append(items, item{phaseIdx: i, ttpIdx: j, label: tc.TTP})
		}
	}

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return model{
		profile: profile,
		output:  output,
		enabled: enabled,
		items:   items,
		spinner: sp,
	}
}

// ─── update ───────────────────────────────────────────────────────────────────

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.screen {
	case screenPlan:
		return m.updatePlan(msg)
	case screenBuild:
		return m.updateBuild(msg)
	case screenDone:
		return m.updateDone(msg)
	}
	return m, nil
}

func (m model) updatePlan(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}

		case " ", "enter":
			it := m.items[m.cursor]
			if it.ttpIdx == -1 {
				// Phase header: toggle all TTPs in phase.
				// If any are on, turn all off; otherwise turn all on.
				anyOn := false
				for _, v := range m.enabled[it.phaseIdx] {
					if v {
						anyOn = true
						break
					}
				}
				for j := range m.enabled[it.phaseIdx] {
					m.enabled[it.phaseIdx][j] = !anyOn
				}
			} else {
				m.enabled[it.phaseIdx][it.ttpIdx] = !m.enabled[it.phaseIdx][it.ttpIdx]
			}

		case "b":
			// Start build.
			m.screen = screenBuild
			return m, tea.Batch(m.spinner.Tick, m.startBuild())
		}
	}
	return m, nil
}

func (m model) updateBuild(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case buildDoneMsg:
		m.screen = screenDone
		m.buildErr = msg.err
		m.buildOut = msg.out
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m model) updateDone(msg tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "r":
			// Return to plan screen.
			m.screen = screenPlan
		}
	}
	return m, nil
}

// ─── view ─────────────────────────────────────────────────────────────────────

func (m model) View() string {
	switch m.screen {
	case screenPlan:
		return m.viewPlan()
	case screenBuild:
		return m.viewBuild()
	case screenDone:
		return m.viewDone()
	}
	return ""
}

func (m model) viewPlan() string {
	var b strings.Builder

	b.WriteString(styleBold.Render("  Red Team Sim Builder") + "\n")
	b.WriteString(styleDim.Render(fmt.Sprintf("  Profile: %s   Output: %s", m.profile.Name, m.output)) + "\n\n")

	for i, it := range m.items {
		cursor := "  "
		if i == m.cursor {
			cursor = styleCursor.Render("▶ ")
		}

		if it.ttpIdx == -1 {
			// Phase header.
			phaseOn := false
			for _, v := range m.enabled[it.phaseIdx] {
				if v {
					phaseOn = true
					break
				}
			}
			tick := "○"
			if phaseOn {
				tick = styleEnabled.Render("●")
			}
			pc := m.profile.Phases[it.phaseIdx]
			sleep := ""
			if pc.Sleep != "" && pc.Sleep != "0s" {
				sleep = styleDim.Render("  sleep:" + pc.Sleep)
			}
			b.WriteString(fmt.Sprintf("%s%s %s%s\n", cursor, tick, stylePhase.Render(it.label), sleep))
		} else {
			// TTP row.
			on := m.enabled[it.phaseIdx][it.ttpIdx]
			tick := styleDim.Render("  ○")
			if on {
				tick = styleEnabled.Render("  ●")
			}
			tc := m.profile.Phases[it.phaseIdx].TTPs[it.ttpIdx]
			b.WriteString(fmt.Sprintf("%s%s %s\n", cursor, tick, ttpSummary(tc)))
		}
	}

	b.WriteString("\n")
	b.WriteString(styleDim.Render("  [↑/↓] move   [space/enter] toggle   [b] build   [q] quit\n"))
	return b.String()
}

func (m model) viewBuild() string {
	return fmt.Sprintf("\n  %s Compiling %s …\n\n  %s\n",
		m.spinner.View(),
		m.output,
		styleDim.Render("GOOS=windows GOARCH=amd64 go build -ldflags \"-s -w\""),
	)
}

func (m model) viewDone() string {
	var b strings.Builder
	b.WriteString("\n")
	if m.buildErr != nil {
		b.WriteString(styleError.Render("  ✗ Build failed") + "\n\n")
		b.WriteString("  " + m.buildErr.Error() + "\n")
		if m.buildOut != "" {
			b.WriteString("\n" + m.buildOut + "\n")
		}
	} else {
		b.WriteString(styleOK.Render("  ✓ Build complete") + "\n\n")
		b.WriteString(fmt.Sprintf("  Binary: %s\n", styleBold.Render(m.output)))
		b.WriteString("  Deploy to target and run:\n")
		b.WriteString(styleDim.Render("    sim.exe\n"))
		b.WriteString(styleDim.Render("    sim.exe --rollback\n"))
	}
	b.WriteString("\n")
	b.WriteString(styleDim.Render("  [r] back to plan   [q] quit\n"))
	return b.String()
}

// ─── build command ────────────────────────────────────────────────────────────

func (m model) startBuild() tea.Cmd {
	return func() tea.Msg {
		// Build the enabled-phases map.
		enabledPhases := map[string]bool{}
		for i, pc := range m.profile.Phases {
			anyOn := false
			for _, v := range m.enabled[i] {
				if v {
					anyOn = true
					break
				}
			}
			if anyOn {
				enabledPhases[pc.Label] = true
			}
		}

		// Produce a profile copy that honours per-TTP toggles.
		filtered := filterProfile(m.profile, m.enabled)

		outDir, err := codegen.Generate(codegen.Options{
			Profile:       filtered,
			EnabledPhases: enabledPhases,
		})
		if err != nil {
			return buildDoneMsg{err: fmt.Errorf("codegen: %w", err)}
		}

		cmd := exec.Command("go", "build",
			"-ldflags", "-s -w",
			"-o", m.output,
			"./"+outDir,
		)
		cmd.Env = append(goEnv(), "GOOS=windows", "GOARCH=amd64")

		out, err := cmd.CombinedOutput()
		if err != nil {
			return buildDoneMsg{err: err, out: string(out)}
		}
		return buildDoneMsg{out: string(out)}
	}
}

// filterProfile returns a Profile copy that only includes enabled TTPs.
func filterProfile(profile *profiles.Profile, enabled [][]bool) *profiles.Profile {
	filtered := &profiles.Profile{Name: profile.Name}
	for i, pc := range profile.Phases {
		var ttps []profiles.TTPConfig
		for j, tc := range pc.TTPs {
			if j < len(enabled[i]) && enabled[i][j] {
				ttps = append(ttps, tc)
			}
		}
		if len(ttps) == 0 {
			continue
		}
		yes := true
		filtered.Phases = append(filtered.Phases, profiles.PhaseConfig{
			Label:   pc.Label,
			Sleep:   pc.Sleep,
			Enabled: &yes,
			TTPs:    ttps,
		})
	}
	return filtered
}

func goEnv() []string {
	// Inherit current environment, stripping any existing GOOS/GOARCH overrides.
	env := make([]string, 0, 32)
	for _, e := range exec.Command("go", "env").Environ() {
		if !strings.HasPrefix(e, "GOOS=") && !strings.HasPrefix(e, "GOARCH=") {
			env = append(env, e)
		}
	}
	return env
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func ttpSummary(tc profiles.TTPConfig) string {
	switch tc.TTP {
	case "schtask":
		name := tc.TaskName
		if name == "" {
			name = "(default)"
		}
		return fmt.Sprintf("schtask  %s → %s", styleDim.Render(name), styleDim.Render(tc.PayloadPath))
	case "registry-run-key":
		return fmt.Sprintf("registry-run-key  %s  %s", styleDim.Render(tc.Hive), styleDim.Render(tc.PayloadPath))
	case "startup-folder":
		return fmt.Sprintf("startup-folder  %s", styleDim.Render(tc.PayloadPath))
	case "service":
		return fmt.Sprintf("service  %s", styleDim.Render(tc.ServiceName))
	case "com-hijack":
		return fmt.Sprintf("com-hijack  %s", styleDim.Render(tc.CLSID))
	case "token-steal":
		return fmt.Sprintf("token-steal  %s → %s", styleDim.Render(tc.TargetExe), styleDim.Render(tc.SpawnExe))
	case "lsass-dump":
		return fmt.Sprintf("lsass-dump  %s", styleDim.Render(tc.OutputPath))
	default:
		return tc.TTP
	}
}

// ensure time import is used
var _ = time.Second
