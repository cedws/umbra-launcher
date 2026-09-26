package main

import (
	"os"
	"runtime"

	"github.com/cedws/umbra-launcher/cmd"
	"github.com/cedws/umbra-launcher/gui"
)

func main() {
	if len(os.Args) > 1 || headlessLinux() {
		cmd.Execute()
		return
	}

	gui.Run()
}

func headlessLinux() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	return os.Getenv("DISPLAY") == "" &&
		os.Getenv("WAYLAND_DISPLAY") == ""
}
