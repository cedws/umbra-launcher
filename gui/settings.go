package gui

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/cedws/umbra-launcher/internal/umbra"
)

const settingsVersion = 2

type savedSettings struct {
	Version     int    `json:"version"`
	Dir         string `json:"dir"`
	Username    string `json:"username"`
	LoginServer string `json:"login_server"`
	PatchServer string `json:"patch_server"`
	PatchOnly   bool   `json:"patch_only"`
	FullPatch   bool   `json:"full_patch"`
}

func defaultSettings() savedSettings {
	return savedSettings{
		Version:     settingsVersion,
		Dir:         umbra.DefaultClientDir(),
		LoginServer: umbra.DefaultLoginServerAddr(),
		PatchServer: umbra.DefaultPatchServerAddr(),
		PatchOnly:   true,
	}
}

func loadSettings() savedSettings {
	settings := defaultSettings()

	path, err := settingsPath()
	if err != nil {
		return settings
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return settings
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return defaultSettings()
	}
	if settings.Version < settingsVersion {
		if settings.Dir == "Wizard101" {
			settings.Dir = umbra.DefaultClientDir()
		}
		settings.Version = settingsVersion
	}
	return settings
}

func writeSettings(settings savedSettings) error {
	path, err := settingsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func settingsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "umbra-launcher", "settings.json"), nil
}
