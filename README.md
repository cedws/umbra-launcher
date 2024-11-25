# umbra-launcher

A patch client for Wizard101. It connects to the Wizard101 patch and login servers, verifies and downloads necessary files, and launches the game client.

## Features

* Super fast patching
* Patch without logging in with `-patch-only`
* Patch to custom directory with `-dir`
* Fully patch with all game files with `-full`
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

## Security

Wizard101 game files are served from an official webserver that is not TLS-secured. The file checksums are also served over a plaintext connection. Although unlikely, this means that an attacker on the network (man-in-the-middle) could theoretically intercept these files as they are downloaded and then execute malicious code on the user's system. The launcher takes a best-effort approach to mitigate this. All file checksums are verified prior to execution, and where possible their [Authenticode](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode) signature is verified, though many files have an expired signature.
