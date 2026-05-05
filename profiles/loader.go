//go:build windows

package profiles

import (
	"fmt"
	"time"

	"github.com/rankin2000/golangexamples/pkg/creds"
	"github.com/rankin2000/golangexamples/pkg/persistence"
	"github.com/rankin2000/golangexamples/pkg/sim"
	"github.com/rankin2000/golangexamples/pkg/tokens"
)

// LoadProfile reads the YAML file at path and returns a fully configured *sim.Sim.
// Only available on Windows; use ParseProfile on other platforms.
func LoadProfile(path string) (*sim.Sim, error) {
	profile, err := ParseProfile(path)
	if err != nil {
		return nil, err
	}

	s := sim.New()

	for _, pc := range profile.Phases {
		sleep, err := time.ParseDuration(pc.Sleep)
		if err != nil {
			return nil, fmt.Errorf("phase %q: invalid sleep %q: %w", pc.Label, pc.Sleep, err)
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
			Enabled: pc.IsEnabled(),
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
