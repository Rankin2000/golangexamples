// Package profiles handles YAML simulation profiles.
//
// This file is platform-agnostic: it only parses YAML into config structs.
// It is safe to import on Linux/Mac for the operator-side builder tool.
//
// The Windows-only LoadProfile() (which instantiates actual TTP objects) lives
// in loader.go behind a //go:build windows tag.
package profiles

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
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

// ParseProfile reads the YAML file at path and returns the parsed Profile.
// This function is platform-agnostic — it does not construct any Windows objects.
func ParseProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}

	var profile Profile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("parse profile %q: %w", path, err)
	}
	return &profile, nil
}

// IsEnabled reports whether a PhaseConfig is enabled (nil → true).
func (pc *PhaseConfig) IsEnabled() bool {
	return pc.Enabled == nil || *pc.Enabled
}
