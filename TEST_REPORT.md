# Test report

Machine: Windows 11 Pro, build 26200
Adapters present:

| GUID | Description |
|---|---|
| `{B993B4D0-FBA9-4C8E-A4D5-7DEE0C365D85}` | Qualcomm Atheros QCA61x4A (built-in) |
| `{90A557F4-5B70-4A3B-A21E-36BBE09BC8C3}` | Realtek RTL8192EU (USB) |

Build: `build.bat`, MSVC 14.44, `/W4`, zero warnings for both binaries.

**eduroam was not in range for the final test round**, so no live 802.1X
handshake was attempted. Everything below is what was actually run.

---

## 1. Verified working

### WPA2-PSK end to end (Realtek RTL8192EU)

```
edurm connect --psk --interface {90A557F4-...} --profile regtest ^
              --ssid "TECNO SPARK 6" --password <redacted> --timeout 25000

interface: {90A557F4-5B70-4A3B-A21E-36BBE09BC8C3}
Installing profile (level strict)
Associating with preshared key...

ladder summary:
  level 1 (strict): connected
```

Confirmed independently with `edurm status`:

```
interface: Realtek RTL8192EU Wireless LAN 802.11n USB 2.0 Network Adapter
  state:    connected
  profile:  regtest
  bssid:    7E:3D:A2:F6:22:63
  auth:     WPA2-PSK
  cipher:   CCMP (AES)
  802.1X:   not in use
```

Disconnect/reconnect cycle also verified. Profile named `TECNO SPARK 6`
successfully overwrote a pre-existing profile (no name collision error).

### Adapter capability probe

Both adapters advertise WPA2-Enterprise + AES:

```
auth/cipher pairs advertised: 20
  802.1X (Enterprise): yes
  WPA2-Enterprise + AES: yes
```

So neither adapter is the blocker.

### `edurm diagnose`

Runs clean end to end: clock, trusted roots, adapter capability, profile XML
validity probe and last-EAP-failure lookup all produce output.

---

## 2. Verified failing

### 802.1X profile install

`WlanSetProfile` returns `ERROR_INVALID_PROFILE` (1206) with reason
`ERROR_INVALID_FUNCTION` (1). `netsh wlan add profile` agrees:

```
Profile format error 0x1:
The network connection profile is corrupted.
```

This happens at *profile install* time, before any association, credential
exchange or certificate validation. So it is a formatting/plumbing problem, not
a CA, clock or password problem.

Progress during this round:

| Change | Result |
|---|---|
| `<EapMethod>` child order corrected to `Type, VendorId, VendorType, AuthorId` | `0x80420019` → `0x1` (**real fix**) |
| `<Config>` omitted entirely | `0x80420019` (correctly "malformed" - it is required) |
| `<EAPConfig>` omitted | `0x80001` (correctly schema-invalid) |
| ServerValidation removed / PeapExtensions removed / both removed | `0x1` |
| Credentials moved to `EapHostUserCredentials` (PEAP 25 > MSCHAPv2 26 + LogonDomain) | `0x1` |
| `<msPeap:RoutingIdentity/>` added | `0x1` |
| `PerformServerValidation` / `AcceptServerName` added (V2 namespace) | `0x1` |
| `<msPeap:ServerNames>` added | `0x1` |
| `WPA` instead of `WPA2`; `TKIP` instead of `AES` | `0x1` |
| per-user vs all-user scope | `0x1` (same for both) |

`ERROR_INVALID_FUNCTION` is reached with a schema-valid, XML-parseable document,
so the remaining difference is something the schema does not capture.

Not tested: a live handshake, because eduroam was out of range.

---

## 3. Diagnostics implemented and exercised

- `EAP_E_EAPHOST_XML_MALFORMED` (0x80420019) decoded from `EapHostError.h` —
  this is what identified the `<EapMethod>` ordering bug
- `explainEapError()` / `explainWlanReason()` map codes to plain language
- `diagnoseLastFailure()` reads `WLAN-AutoConfig/Operational` and
  `EapHost/Operational` via the event-log API bound at run time from
  `wevtapi.dll` (the SDK ships no header or import lib for it)
- A bug found and fixed during testing: the reason code was being run through
  `explainWlanReason()` even when it was actually a raw Win32 error from
  `WlanSetProfile` (code `1` is `ERROR_INVALID_FUNCTION`, not WLAN reason 1)

---

## 4. Could not be made to work, and why

**802.1X profile installation.** I could not get `WlanSetProfile` to accept a
PEAP profile on this machine. I verified the driver supports it, the adapter
advertises it, the XML is well-formed and schema-valid, and EAPHost parses it.
Roughly 25 structural variants were tried.

The most likely remaining cause, stated honestly: **a missing element or
namespace that only a profile built by Windows itself would contain.** I could
not obtain ground truth because I cannot drive the Windows Settings UI. The
decisive experiment is in `README.md`: build the profile by hand in Settings,
export it with `netsh wlan export profile`, and diff.

**Level 2 pinning cannot be automatic.** Genuine trust-on-first-use requires
fetching the RADIUS server's certificate. That is only observable once a
connection attempt reaches TLS, which did not happen here. Level 2 therefore
requires the user to supply the CA (`--ca-cert`) or a thumbprint that resolves
in the local store (`--pin-sha256`); the ladder skips the rung and says so
rather than inventing a pin.

**Level 3 is implemented but untested against a real server.** The registry
write/delete paths are implemented and `restore-tls` removes exactly what was
created, but whether EAPHost PEAP actually honours the SCHANNEL client keys on
Windows 11 could not be determined without a server that requires them. Treat
that level as unproven.

---

## 5. Recommendation for finishing

1. Get onto a network where eduroam is visible.
2. Build the profile once through **Settings → Wi-Fi → eduroam**.
3. `netsh wlan export profile name="eduroam" folder=. key=clear`
4. Feed that file to `edurm install` — if Windows accepts its own export, the
   difference against our generator is the remaining bug, and it is now scoped
   to one diff rather than a search space.