package umbra

import (
	"os"
	"path/filepath"
	"runtime"
)

func DefaultClientDir() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData,
			"KingsIsle Entertainment", "Wizard101")
	}

	prefix := os.Getenv("WINEPREFIX")
	if prefix == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "Wizard101"
		}
		prefix = filepath.Join(home, ".wine")
	}
	return filepath.Join(prefix, "drive_c", "ProgramData",
		"KingsIsle Entertainment", "Wizard101")
}
