package cmd

import (
	"context"
	"flag"
	"log"
	"os"
	"runtime"

	"github.com/cedws/umbra-launcher/internal/umbra"
)

const (
	defaultLoginServer = "login.us.wizard101.com:12000"
	defaultPatchServer = "patch.us.wizard101.com:12500"
)

var defaultConcurrencyLimit = runtime.NumCPU()

func Execute() {
	var (
		dir                              string
		username, password               string
		loginServerAddr, patchServerAddr string
		patchOnly                        bool
		fullPatch                        bool
	)

	flag.StringVar(&dir, "dir", "Wizard101", "client directory")

	flag.StringVar(&username, "username", "", "login username")
	flag.StringVar(&password, "password", "", "login password")

	flag.StringVar(&loginServerAddr, "login-server", defaultLoginServer, "login server addr")
	flag.StringVar(&patchServerAddr, "patch-server", defaultPatchServer, "patch server addr")

	flag.BoolVar(&patchOnly, "patch-only", false, "only patch files without logging in")
	flag.BoolVar(&fullPatch, "full", false, "patch all game files")

	flag.Parse()

	if !patchOnly && (username == "" || password == "") {
		flag.Usage()
		os.Exit(1)
	}

	if len(flag.Args()) > 0 {
		flag.Usage()
		os.Exit(1)
	}

	params := umbra.LaunchParams{
		Dir:              dir,
		Username:         username,
		Password:         password,
		PatchOnly:        patchOnly,
		FullPatch:        fullPatch,
		LoginServerAddr:  loginServerAddr,
		PatchServerAddr:  patchServerAddr,
		ConcurrencyLimit: defaultConcurrencyLimit,
	}

	if err := umbra.Patch(context.Background(), params); err != nil {
		log.Fatal(err)
	}
}
