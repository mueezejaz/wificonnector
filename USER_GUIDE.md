# edurm / wificonnector — User Guide

Windows 11, MSVC Build Tools, no external dependencies.

## 1. Build

```bat
build.bat
```

Produces `build\edurm.exe` (CLI) and `build\edurm-gui.exe` (GUI).
Both need nothing installed beyond Visual Studio C++ Build Tools.

## 2. Quick start (GUI)

1. Run `build\edurm-gui.exe`.
2. Pick your Wi-Fi adapter from the **ADAPTER** dropdown. With an internal NIC
   and a USB stick, this matters: every scan and connect targets only the
   selected adapter. The choice is remembered.
3. Press **Scan**.
4. Click a network.
5. Fill in **USERNAME**, **REALM** and **PASSWORD**, then **Connect**.

Keyboard: `Tab` moves between fields, `Ctrl+V` pastes, `Up`/`Down` picks a
network, `Enter` connects, `F5` rescans.

## 3. Quick start (CLI)

```bat
REM ordinary network (verified working)
edurm connect --psk --ssid "MyNetwork" --interface "{GUID}"

REM eduroam - password is prompted for, never passed on the command line
edurm connect --ssid eduroam --username 2024ag0000@student.uaf.edu.pk ^
              --domain uaf.edu.pk --password-stdin < pw.txt
```

Find your adapter GUID with `edurm status`.

## 4. The verification ladder

eduroam tries progressively weaker server-certificate checks and **stops at the
first success**. It never steps down on its own — you choose how far it may go.

| Level | Name | What it checks | How to allow |
|---|---|---|---|
| 1 | strict | system root store **and** the server name must match | default |
| 2 | pinned | the same, but with one specific CA pinned in `<TrustedRootCA>` | `--ca-cert <file>` or `--pin-sha256 <hex>` |
| 3 | legacy-tls | as 2, but assumes an old TLS stack (machine-wide change) | `--allow-legacy-tls` (admin) |
| 4 | no-validation | **nothing** — the certificate is not checked at all | `--insecure-skip-validation` |

After every attempt it prints a ladder summary, e.g.

```
ladder summary:
  level 1 (strict): did not reach 'connected' ...
  level 2 (pinned): Connected via profile 'eduroam' (level pinned)
```

Level 2 is skipped with an explanation when no CA was supplied, because a pin
cannot be invented.

### Risks — read before using Level 3 or 4

**Level 3 (`--allow-legacy-tls`)** writes these machine-wide registry values:

```
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client
    Enabled=1  DisabledByDefault=0
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client
    Enabled=1  DisabledByDefault=0
```

That lowers the TLS floor for **every** program on the machine. Undo it with:

```bat
edurm restore-tls
```

**Level 4 (`--insecure-skip-validation`)** accepts *any* certificate. Anyone who
can broadcast an access point named `eduroam` can capture your username and
password. Use it only to prove that certificate validation is the blocker, on a
network you control. It prints a large warning and is never the default.

## 5. Diagnostics

```bat
edurm diagnose
```

Checks, in order:

1. **system clock** — certificate validation is time-sensitive
2. **trusted roots** — whether an eduroam/eduPKI root is present
3. **adapter capability** — does this NIC advertise WPA2-Enterprise + AES?
4. **profile XML validity** — hands the generated XML to Windows and reports the
   exact rejection code. This separates *format* problems from *credential* or
   *certificate* problems.
5. **last EAP failure** — recent `WLAN-AutoConfig` and `EapHost` events, mapped
   to a plain-language cause

Other useful commands:

```bat
edurm caps                     REM auth/cipher pairs this adapter supports
edurm scan                     REM nearby networks, flags enterprise ones
edurm status                   REM what am I connected to, via which auth
edurm roots                    REM eduroam roots in the trust store
edurm install profile.xml      REM install a profile XML verbatim
edurm export <name>            REM print a profile (password redacted)
```

## 6. Installing the eduroam CA

The most common real-world failure is a missing CA bundle, not a wrong profile.

```bat
REM 1. download the bundle from https://www.eduroam.org/ (or ask your IT desk)
REM 2. import it (needs an elevated prompt)
edurm install-ca eduroam_roots.crt
REM 3. retry
edurm connect --username <id>@<realm>
```

`install-ca` puts the certificate in the machine's trusted ROOT store, which is
what "CA certificate: use system certificates" on your eduroam card means.

**Note:** `edurm roots` reports "none found" when it cannot find a root whose
*subject name* mentions eduroam/terena/eduPKI/GÉANT. That is a keyword search,
not a real trust decision — a RADIUS server using a public-CA certificate will
not match it and may still connect perfectly. Only a failed connection proves
the bundle is missing.

## 7. Multiple adapters

```bat
edurm status                     REM lists every adapter with GUID and state
edurm scan --interface "{GUID}"   REM target one adapter
edurm connect --interface "{GUID}" ...
```

The GUI remembers the adapter you pick in `%APPDATA%\edurm\adapter.txt`.

Common USB-adapter problems, all reported by `edurm diagnose`:

- **driver not installed** — the adapter will not appear in `edurm status` at all
- **power saving** — adapter sits at `disconnected` or drops during association
- **no 802.1X support** — `edurm caps` will not list any `Enterprise` pair;
  `diagnose` prints `WPA2-Enterprise + AES usable: NO`

## 8. Troubleshooting the ladder itself

If `edurm diagnose` step 4 says the profile is **REJECTED**, the problem is the
XML, not your password or the CA. Common codes:

| Code | Meaning |
|---|---|
| `ERROR_INVALID_PROFILE` (1206) | schema violation — often a wrong element or element order |
| `EAP_E_EAPHOST_XML_MALFORMED` (0x80420019) | EAPHost could not parse the EAP config |
| `ERROR_INVALID_FUNCTION` (1) | Windows refused the EAP method silently |

If step 4 is **ACCEPTED** and the connection still fails, the profile is fine and
the problem is credentials, the CA bundle, the clock, or the RADIUS server.

## 9. If Windows still will not connect

Old campus RADIUS servers sometimes only offer TLS 1.0/1.1. Try, in order:

1. `edurm install-ca <bundle>` — most "impossible" cases are a missing CA
2. `edurm connect --ca-cert <ca.crt> --max-level 2`
3. `edurm connect --allow-legacy-tls` then `edurm restore-tls` afterwards
4. `edurm connect --insecure-skip-validation` — diagnosis only

If all four fail, the honest conclusion is that Windows' EAP stack will not
negotiate with that server. On Linux, `wpa_supplicant` can be told to accept old
crypto directly:

```
eap=PEAP
identity=<roll-number>@student.uaf.edu.pk
password=<password>
domain_suffix_match=uaf.edu.pk
phase1="tls_disable_tlsv1_0=0 tls_disable_tlsv1_1=0"
openssl_ciphers="DEFAULT@SECLEVEL=0"
phase2="auth=MSCHAPV2"
```

This is a real security trade-off: accepting TLS 1.0 and low-grade ciphers makes
the tunnel breakable. It is the right answer only when the server cannot be
upgraded and you accept that risk on that network.