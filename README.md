# umbra-launcher

A patch client for Wizard101. It connects to the Wizard101 patch and login servers, verifies and downloads necessary files, and launches the game client.

## Features

* Patch without logging in with `-patch-only`
* Patch to custom directory with `-dir`
* Fully patch with all game files with `-full`
* Super fast patching
* Automatically launch the game with Wine on Linux and macOS

## Options

- `-dir string`
  - Client directory (default "Wizard101")
- `-username string`
  - Login username
- `-password string`
  - Login password
- `-login-server string`
  - Login server address (default "login.us.wizard101.com:12000")
- `-patch-server string`
  - Patch server address (default "patch.us.wizard101.com:12500")
- `-patch-only`
  - Only patch files without logging in
- `-full`
  - Patch all game files