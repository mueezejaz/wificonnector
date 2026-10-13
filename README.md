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

**WPA2-PSK (personal networks) - works, verified end to end.** Profile install,
association and authentication all succeed. See `TEST_REPORT.md`.

**WPA2-Enterprise / 802.1X (eduroam) - NOT verified.** The generated profile now
clears the WLAN profile schema and EAPHost's XML parse, but Windows still returns
`ERROR_INVALID_FUNCTION` (1) when installing it, before any credentials or
certificates are involved. eduroam was also out of range during the final test
round, so no live 802.1X handshake has been attempted. Do not assume it works.

Run `edurm diagnose` to see the current state on your own machine.

### Bugs found and fixed (all verified on Windows 11 26200)

| Bug | Symptom | Fix |
|---|---|---|
| Root namespace `https://` | "The WLAN profile element is missing" | must be `http://` |
| Enterprise token `WPA2Enterprise` | "invalid according to the schema" | must be `WPA2` / `WPA` |
| Top-level `<8021X>` element | `ERROR_INVALID_PROFILE` | no such element; it is `<OneX>` under `<MSM><security>` |
| `<credentials>` under `<MSM>` | `ERROR_INVALID_PROFILE` | not in the schema; credentials go through `WlanSetProfileEapXmlUserData` |
| `<EapMethod>` child order | `0x80420019 EAP_E_EAPHOST_XML_MALFORMED` | XSD sequence is `Type, VendorId, VendorType, AuthorId` |
| `<autoSwitch>` present | `ERROR_INVALID_PROFILE` (even for PSK) | omit it |
| empty `<keyMaterial>` | profile rejected | must contain the passphrase |
| PSK profile from the CLI | empty key | CLI fills `password`, generator read `psk` |
| success message never printed | a successful connect looked like silence | `Stage::Succeeded` fell through to `default:` |
| `busy_` stuck true after a scan | fields uneditable, buttons greyed out | scan never reported job completion |

### Known remaining blocker

`WlanSetProfile` returns 1206 with reason `ERROR_INVALID_FUNCTION` (1) for a
schema-valid PEAP profile. The XML parses, EAPHost accepts the element order, and
the adapter advertises WPA2-Enterprise + AES - but Windows refuses to install the
profile. About 25 structural variants were tested against
`netsh wlan add profile`: every namespace combination, EapMethod shapes,
ServerValidation/PeapExtensions permutations, credential placement, per-user vs
all-user, WPA/WPA2 and TKIP/AES.

The step that would close this is empirical rather than analytical - export a
profile the **Windows Settings UI** can build and connect with, then diff it
against what this tool generates:

```bat
REM Settings -> Network & internet -> Wi-Fi -> connect to eduroam, then:
netsh wlan export profile name="eduroam" folder=. key=clear
```

Anything Windows builds and `netsh wlan add profile` can re-import is by
definition schema-valid, so diffing it will show the remaining difference.

### The verification ladder

`edurm connect` tries progressively weaker certificate checks and stops at the
first success. It never steps down on its own - you decide how far it may go:

| Level | Name | Checks | Allowed by |
|---|---|---|---|
| 1 | strict | system root store + server name must match | default |
| 2 | pinned | as 1, with one specific CA pinned | `--ca-cert <file>` / `--pin-sha256 <hex>` |
| 3 | legacy-tls | as 2, plus enabling TLS 1.0/1.1 machine-wide | `--allow-legacy-tls` (admin) |
| 4 | no-validation | **nothing** - last resort, warns hard | `--insecure-skip-validation` |

Levels 3 and 4 carry real security risk and are never defaults. See
`USER_GUIDE.md`.


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

> **Known gap:** the generator does **not** yet emit
> `<domainSuffixMatch>` or `<validateServerCert>`. Today `--domain` only reaches
> `msChapV2:LogonDomain` in the credentials blob, and the name check is made
> with `<msPeapV2:AcceptServerName>` instead. So the "domain suffix is
> enforced" claim below does not hold in the current build, and
> `--no-suffix-match` is accepted but does nothing. Both are part of the
> unresolved 802.1X work described in "Known remaining blocker"; see
> `TEST_REPORT.md`.

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
  --machine            install-ca: trust the CA machine-wide (needs admin)
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
