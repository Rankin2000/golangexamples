// Package profiles loads YAML simulation profiles and converts them into
// a configured *sim.Sim ready to call Run() on.
//
// YAML schema:
//
//	name: my-profile
//	phases:
//	  - label: Persistence
//	    sleep: 48h
//	    enabled: true        # optional; default true
//	    ttps:
//	      - ttp: schtask
//	        payload_path: "C:\\Temp\\payload.exe"
//	        use_xml: true
//	      - ttp: registry-run-key
//	        hive: hkcu
//	        payload_path: "C:\\Temp\\payload.exe"
//
// Supported ttp values: schtask, registry-run-key, startup-folder, service,
// com-hijack, token-steal, lsass-dump.
package profiles

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rankin2000/golangexamples/pkg/creds"
	"github.com/rankin2000/golangexamples/pkg/persistence"
	"github.com/rankin2000/golangexamples/pkg/sim"
	"github.com/rankin2000/golangexamples/pkg/tokens"
)

// Profile mirrors the top-level YAML document.
type Profile struct {
	Name   string        `yaml:"name"`
	Phases []PhaseConfig `yaml:"phases"`
}

// PhaseConfig mirrors a single phase entry in the YAML.
type PhaseConfig struct {
	Label   string      `yaml:"label"`
	Sleep   string      `yaml:"sleep"`   // Go duration string, e.g. "48h", "0s"
	Enabled *bool       `yaml:"enabled"` // nil → true
	TTPs    []TTPConfig `yaml:"ttps"`
}

// TTPConfig holds all possible fields for every supported TTP.
// Unused fields for a given ttp value are silently ignored.
type TTPConfig struct {
	// Discriminator field — selects which TTP struct to construct.
	TTP string `yaml:"ttp"`

	// persistence.SchTask
	PayloadPath string `yaml:"payload_path"`
	UseXML      bool   `yaml:"use_xml"`
	TaskName    string `yaml:"task_name"`
	Delay       string `yaml:"delay"`

	// persistence.RegistryRunKey
	Hive      string `yaml:"hive"`       // "hkcu" | "hklm"
	ValueName string `yaml:"value_name"`

	// persistence.StartupFolder
	DropName string `yaml:"drop_name"`
	UseLNK   bool   `yaml:"use_lnk"`

	// persistence.Service
	ServiceName string   `yaml:"service_name"`
	DisplayName string   `yaml:"display_name"`
	Description string   `yaml:"description"`
	ExePath     string   `yaml:"exe_path"`
	Args        []string `yaml:"args"`

	// persistence.COMHijack
	CLSID          string `yaml:"clsid"`
	DLLPath        string `yaml:"dll_path"`
	ThreadingModel string `yaml:"threading_model"`

	// tokens.Steal
	TargetExe     string `yaml:"target_exe"`
	SpawnExe      string `yaml:"spawn_exe"`
	EnableSeDebug bool   `yaml:"enable_se_debug"`

	// creds.LSASSDump
	OutputPath string `yaml:"output_path"`
}

// LoadProfile reads the YAML file at path and returns a fully configured *sim.Sim.
func LoadProfile(path string) (*sim.Sim, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}

	var profile Profile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("parse profile %q: %w", path, err)
	}

	s := sim.New()

	for _, pc := range profile.Phases {
		sleep, err := time.ParseDuration(pc.Sleep)
		if err != nil {
			return nil, fmt.Errorf("phase %q: invalid sleep %q: %w", pc.Label, pc.Sleep, err)
		}

		enabled := true
		if pc.Enabled != nil {
			enabled = *pc.Enabled
		}

		var ttps []sim.TTP
		for _, tc := range pc.TTPs {
			t, err := buildTTP(tc)
			if err != nil {
				return nil, fmt.Errorf("phase %q, ttp %q: %w", pc.Label, tc.TTP, err)
			}
			ttps = append(ttps, t)
		}

		s.Phases = append(s.Phases, sim.Phase{
			Label:   pc.Label,
			TTPs:    ttps,
			Sleep:   sleep,
			Enabled: enabled,
		})
	}

	return s, nil
}

func buildTTP(cfg TTPConfig) (sim.TTP, error) {
	switch cfg.TTP {
	case "schtask":
		return &persistence.SchTask{
			TaskName:    cfg.TaskName,
			PayloadPath: cfg.PayloadPath,
			UseXML:      cfg.UseXML,
			Delay:       cfg.Delay,
		}, nil

	case "registry-run-key":
		hive := persistence.HKCU
		if cfg.Hive == "hklm" {
			hive = persistence.HKLM
		}
		return &persistence.RegistryRunKey{
			Hive:        hive,
			ValueName:   cfg.ValueName,
			PayloadPath: cfg.PayloadPath,
		}, nil

	case "startup-folder":
		return &persistence.StartupFolder{
			PayloadPath: cfg.PayloadPath,
			DropName:    cfg.DropName,
			UseLNK:      cfg.UseLNK,
		}, nil

	case "service":
		return &persistence.Service{
			ServiceName: cfg.ServiceName,
			DisplayName: cfg.DisplayName,
			Description: cfg.Description,
			ExePath:     cfg.ExePath,
			Args:        cfg.Args,
		}, nil

	case "com-hijack":
		return &persistence.COMHijack{
			CLSID:          cfg.CLSID,
			DLLPath:        cfg.DLLPath,
			ThreadingModel: cfg.ThreadingModel,
		}, nil

	case "token-steal":
		return &tokens.Steal{
			TargetExe:     cfg.TargetExe,
			SpawnExe:      cfg.SpawnExe,
			EnableSeDebug: cfg.EnableSeDebug,
		}, nil

	case "lsass-dump":
		return &creds.LSASSDump{
			OutputPath:    cfg.OutputPath,
			EnableSeDebug: cfg.EnableSeDebug,
		}, nil

	default:
		return nil, fmt.Errorf("unknown ttp %q", cfg.TTP)
	}
}
