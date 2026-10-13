# wificonnector

A native Wi-Fi connection helper for Windows, with two front-ends over one
shared core. Built for eduroam (802.1X) but just as happy joining an ordinary
WPA2 network.

- **`edurm-gui.exe`** — a Win32/GDI desktop app: adapter picker, dark or light,
  live scanning, one-click connect
- **`edurm.exe`** — a CLI for scripting and for reading the exact 802.1X state

Both are C++17 with **no runtime and no external dependencies** — they link
`wlanapi`, `user32`, `gdi32`, `comctl32`, `dwmapi`, `uxtheme` and nothing else.
No .NET, no NuGet, no CMake needed.

## What it does

It builds a **WPA2-Enterprise (802.1X) profile** for `eduroam` — PEAP with
MSCHAPv2, validated against the system certificate store — installs it, and
connects.

## Current status

**WPA2-PSK (personal networks) — works.** Profile installs and associates.

**WPA2-Enterprise / 802.1X (eduroam) — not yet working.** The generated profile
is accepted by the WLAN profile schema but is then rejected inside EAPHost
(`ERROR_INVALID_FUNCTION` / `0x80420019`). See "Profile format gotchas" below
for everything that has been established and ruled out.

### Profile format gotchas (all verified empirically on Windows 11 26200)

The WLAN profile schema is stricter than the documentation suggests. Each of
these was found by bisecting against `WlanSetProfile` and `netsh wlan add
profile`, which reports precise schema errors:

| Gotcha | Wrong | Right |
|---|---|---|
| Root namespace | `https://www.microsoft.com/networking/WLAN/profile/v1` | **`http://`** — https yields "The WLAN profile element is missing" |
| Enterprise auth token | `WPA2Enterprise`, `WPAEnterprise` | **`WPA2`** or `WPA` — the long forms are "invalid according to the schema" |
| 802.1X location | top-level `<8021X>` sibling of `<MSM>` | **`<OneX>` immediately under `<MSM><security>`** |
| Credentials | `<credentials><domain>` under `<MSM>` | **`<EapHostUserCredentials>` under `<EAPConfig>`** — `<credentials>` is not in the schema at all |
| `<autoSwitch>` | emitting it | **omit it** — its presence alone makes PSK profiles fail with `ERROR_INVALID_PROFILE` |
| PSK key material | empty `<keyMaterial>` | must contain the passphrase, else rejected |
| `<EAPConfig>` namespace | `EapHostConfig` namespace | **inherit the `OneX/v1` default** — setting it explicitly is schema-invalid |

### Commands

```
edurm scan        # what is nearby; flags enterprise networks
edurm caps        # auth/cipher pairs the adapter supports
edurm connect     # create/update the profile and connect
edurm status      # what am I connected to, and via which auth?
edurm roots       # is the eduroam CA bundle installed?
edurm install f.xml  # install a profile XML verbatim (import / testing)
edurm export <name>  # print a profile's XML (password redacted)
```

`edurm install` is the escape hatch: it hands a file straight to
`WlanSetProfile`, so you can test a profile exported from a working machine
without touching this codebase.

## The GUI

```
build\edurm-gui.exe
```

```
┌─ edurm ─────────────────────────────────────── [Light] ─┐
│  ADAPTER                    [ Realtek RTL8192EU     ▾ ] │
│  ┌────────────────────────────────────────────────┐   │
│  │ ● TECNO SPARK 6                                │   │
│  │   WPA2-PSK · CCMP (AES)                        │   │
│  └────────────────────────────────────────────────┘   │
│  NETWORKS                                    [ Scan ]  │
│  ┌────────────────────────────────────────────────┐   │
│  │ TECNO SPARK 6            WPA2-PSK        ▂▄▆█ │   │
│  │ SM Net Mian SB           WPA2-PSK        ▂▄▆ │   │
│  └────────────────────────────────────────────────┘   │
│  USERNAME [your-roll-number@student.example.edu          ]     │
│  REALM    [uaf.edu.pk                           ]     │
│  PASSWORD [••••••••                             ]     │
│  [ Connect ]  [ Disconnect ]                            │
│  ┌────────────────────────────────────────────────┐   │
│  │ edurm ready.                                   │   │
│  │ Connected via profile 'TECNO SPARK 6'          │   │
│  └────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────┘
```

How to drive it:

- **Pick your adapter** from the dropdown under the title. Machines usually have
  more than one Wi-Fi NIC (internal plus a USB dongle), and every scan/connect
  targets the selected one. The choice is remembered in
  `%APPDATA%\edurm\adapter.txt`, and the list refreshes on a timer so hot-plugged
  adapters show up. Switching adapters clears the network list and rescans.
- **Scans on launch**, then whenever you press **Scan** or **F5**.
- **Click a network** to select it. Enterprise networks get an 802.1X profile,
  personal networks get a WPA2-PSK profile — so the tool is useful for any
  visible SSID, not just eduroam.
- **Type** into any field. **Tab** moves between fields, **Ctrl+V** pastes,
  **Backspace** deletes, **Up/Down** changes the selected network,
  **Enter** connects.
- **Connect** installs the profile and associates. **Disconnect** drops the
  association. Progress and failures appear in the log panel.
- **Light/Dark** toggles the theme; the accent colour follows your Windows
  accent setting.

Scanning and connecting run on a worker thread, so the window never freezes.
The worker only posts results back to the UI thread through a mutex-guarded
queue; it never touches UI state directly.

Rendering is plain Win32 + GDI: `CreateFontW` with `MulDiv(pt, dpi, 72)` for
DPI-scaled text, `DrawTextW` with `DT_END_ELLIPSIS` for truncation, and a
double-buffered `WM_PAINT`. Colours are `COLORREF`, so the app follows Windows
dark mode automatically.

## The CLI

```
edurm scan        # what is nearby; flags enterprise networks
edurm connect     # create/update the eduroam profile and connect
edurm status      # what am I connected to, and via which auth?
edurm roots       # is the eduroam CA bundle installed? (common failure cause)
```

## Scope: what "deep hardware control" means here on Windows

This is worth being precise about, because it shaped the whole design.

On Windows the **802.1X/EAPOL exchange is performed by the WLAN AutoConfig
service and the miniport driver**, in the kernel. A user-mode process cannot
take that over. So the deepest legitimate control available to a native app is:

- constructing the complete 802.1X profile (EAP method, inner credentials,
  **server certificate validation**, realm/domain suffix),
- installing it per-user or all-users,
- driving the connection and reading back state.

That is exactly what this tool does. It is the *same boundary* a phone's WiFi
framework puts on the phone — on both platforms, the OS supplicant performs the
EAPOL/TLS/MSCHAPv2 exchange and the app supplies the profile.

If you want to own the **supplicant itself** (your own EAPOL PAE state machine,
your own TLS client, your own MSCHAPv2 + PMK derivation), that requires talking
to the driver directly over `nl80211`, which means **Linux**. That is a
different, much larger project, and this codebase is not it.

## Mapping the printed card to a Windows profile

Your card says:

| Card field | Windows profile XML |
|---|---|
| EAP method: `PEAP` | `<outerMethod>PEAP</outerMethod>` |
| Phase 2: `MSCHAPv2` | implicit — PEAP + `<passwordPlaintext>` is MSCHAPv2 |
| CA certificate: system | **absence** of any `<rootCert>` element |
| Domain: `uaf.edu.pk` | `<domainSuffixMatch>` under `<serverValidation>` |
| Identity | `<username>` under `<EAPUserIdentity>` |

Two of these are easy to get wrong, and both are silent failures:

1. **`<useOneX>true</useOneX>`** — without it the profile quietly degrades to a
   preshared-key profile and will never authenticate.
2. **`Domain` is the certificate check, not just a realm hint.** It goes in
   `<serverValidation><domainSuffixMatch>`, *not* only in
   `<MSM><credentials><domain>`. Omitting it is the most common cause of
   *"the server certificate is not trusted"* / *"name does not match"* on
   eduroam, because the RADIUS server usually presents a certificate issued for
   the realm rather than for the SSID.

`<validateServerCert>` is always `true` here — an eduroam profile that skips
server certificate validation is an open door to any rogue RADIUS on the SSID.

## Build

Requires Visual Studio 2022 (or Build Tools) with the C++ workload.

```bat
build.bat
```

This locates the MSVC toolchain via `vswhere` on its own; CMake is not
required. A `CMakeLists.txt` is included if you prefer it.

## Usage

```
edurm <command> [options]

Commands:
  scan                 List nearby networks, flagging enterprise ones
  list                 List saved Wi-Fi profiles
  status               Show current connection state
  connect              Create/update the eduroam profile and connect
  disconnect           Disconnect the current network
  forget <name>        Delete a saved profile
  export <name>        Print a profile's XML (password redacted)
  xml                  Print the eduroam profile XML without installing
  roots                Show trusted root CAs relevant to eduroam

Options:
  --ssid <s>           Network SSID            (default: eduroam)
  --profile <name>     Profile name            (default: eduroam)
  --username <u>       EAP identity            (default: your-roll-number@student.example.edu)
  --domain <d>         Realm / cert suffix     (default: uaf.edu.pk)
  --server <s>         Exact server cert name to require
  --password <p>       Password (prefer --password-stdin)
  --password-stdin     Read the password from stdin
  --interface <guid>   Target a specific interface
  --all-users          Install the profile for all users (needs admin)
  --tkip               Use TKIP instead of AES
  --no-suffix-match    Do not require the cert domain suffix
  --timeout <ms>       Connection timeout       (default: 45000)
  --dry-run            Print what would be installed, change nothing
  --redact             Hide the password in 'xml' output
  --json               Machine-readable output where supported
```

### Typical session

```bat
REM 1. Is eduroam even in range, and is it enterprise?
edurm scan

REM 2. Is the CA bundle installed? (Fix this FIRST if it says none.)
edurm roots

REM 3. Connect. You will be prompted for the password; it is not echoed
REM    and never appears in the process list or shell history.
edurm connect

REM 4. Confirm what you actually authenticated with.
edurm status
```

Avoid `--password` on shared machines — it is visible to anything that can list
processes. Prefer the interactive prompt or `--password-stdin`.

## Troubleshooting

`edurm connect` prints the OS failure state but the authoritative 802.1X reason
code lives in the event log:

```bat
netsh wlan show wlanreport
```

or **Event Viewer → Applications and Services Logs → Microsoft → Windows →
WLAN-AutoConfig → Operational**, event **12012**, which carries the EAP failure
text.

The usual causes, in rough order of frequency:

1. **eduroam CA bundle not installed.** `edurm roots` will say "(none found)".
   Install it via your institution's eduroam Configuration Assistant Tool, or
   from <https://www.eduroam.org/>. The certs go under `certmgr.msc` → Trusted
   Root Certification Authorities.
2. **Wrong username/password**, or the identity is not `rollnumber@realm`.
3. **System clock is wrong.** Certificates are validated against it, and a
   skewed clock breaks the chain instantly.
4. **Wrong realm** for `--domain`. Try `edurm status` on a working network, or
   ask your IT desk for the exact realm string.

## Layout

| File | Purpose |
|---|---|
| `src/eduroam.{h,cpp}` | Shared core: profile install + connect with progress callbacks; CA-bundle check |
| `src/profile.{h,cpp}` | Builds the WLAN profile XML; XML escaping; password redaction |
| `src/wlan.{h,cpp}` | RAII wrapper over the Native Wifi API (open/enumerate/scan/connect/profiles) |
| `src/util.{h,cpp}` | UTF-8 ↔ UTF-16, Win32 error formatting, enum name tables, masked input |
| `src/main.cpp` | The CLI |
| `src/gui/main_gui.cpp` | The Win32/GDI GUI |
| `tools/screenshot.ps1` | Captures the GUI window to a PNG (used to verify rendering) |

`src/eduroam.cpp` is the single implementation of "install the profile and
connect"; both the CLI and the GUI call it, so there is no duplicated 802.1X
logic.

SSIDs are written as `<hex>` rather than text, which sidesteps encoding issues
for non-ASCII network names entirely.