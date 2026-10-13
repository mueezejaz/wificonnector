// edurm - eduroam connection helper for Windows.
//
// Manages WPA2-Enterprise (802.1X) profiles through the Native Wifi API.
// Run with no arguments (or "help") for usage.
#include "diag.h"
#include "eduroam.h"
#include "profile.h"
#include "util.h"
#include "wlan.h"  // pulls in windows.h + wlanapi.h

#include <wincrypt.h>  // must follow windows.h
#include <conio.h>

#include <cstdio>
#include <cwctype>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "crypt32.lib")

using namespace edurm;

namespace {

// JSON string escaping for --json output. SSIDs come from the radio and may
// contain quotes, backslashes or control characters.
std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char esc[7];
                    std::snprintf(esc, sizeof(esc), "\\u%04x", c);
                    out += esc;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

void printUsage() {
    std::puts(
        "edurm - eduroam profile helper (Windows Native Wifi API)\n"
        "\n"
        "Usage: edurm <command> [options]\n"
        "\n"
        "Commands:\n"
        "  scan                 List nearby networks, flagging enterprise ones\n"
        "  list                 List saved Wi-Fi profiles\n"
        "  status               Show current connection state\n"
        "  connect              Create/update the eduroam profile and connect\n"
        "  disconnect           Disconnect the current network\n"
        "  forget <name>        Delete a saved profile\n"
        "  export <name>        Print a profile's XML (password redacted)\n"
        "  xml                  Print the eduroam profile XML without installing\n"
        "  roots                Show trusted root CAs relevant to eduroam\n"
        "\n"
        "Options:\n"
        "  --ssid <s>           Network SSID            (default: eduroam)\n"
        "  --profile <name>     Profile name            (default: eduroam)\n"
        "  --username <u>       EAP identity            (default: your-roll-number@realm)\n"
        "  --domain <d>         Realm / cert suffix     (default: uaf.edu.pk)\n"
        "  --server <s>         Exact server cert name to require\n"
        "  --password <p>       Password (prefer --password-stdin)\n"
        "  --password-stdin     Read the password from stdin\n"
        "  --interface <guid>   Target a specific interface\n"
        "  --all-users          Install the profile for all users (needs admin)\n"
        "  --tkip               Use TKIP instead of AES\n"
        "  --psk                Build a WPA2-PSK profile (personal networks)\n"
        "  --no-suffix-match    Do not require the cert domain suffix\n"
        "  --timeout <ms>       Connection timeout       (default: 45000)\n"
        "  --dry-run            Print what would be installed, change nothing\n"
        "  --machine            install-ca: trust the CA machine-wide (needs admin)\n"
        "  --redact             Hide the password in 'xml' output\n"
        "  --json               Machine-readable output where supported\n"
        "\n"
        "Examples:\n"
        "  edurm connect\n"
        "  edurm connect --username your-id@realm --password-stdin < pw.txt\n"
        "  edurm scan --json\n"
        "  edurm xml > eduroam.xml\n");
}

// ---------------------------------------------------------------- scan ------

void cmdScan(Wlan& wlan, const std::string& ifaceOpt, bool json) {
    GUID g = pickInterface(wlan, ifaceOpt);
    std::vector<NetworkInfo> nets = wlan.scan(g);

    if (json) {
        std::printf("{\"networks\":[");
        for (size_t i = 0; i < nets.size(); ++i) {
            const auto& n = nets[i];
            // Escape the SSID/auth/cipher strings: an SSID may legally contain
            // '"' or '\', which would otherwise produce invalid JSON.
            std::printf("%s{\"ssid\":\"%s\",\"signal\":%lu,\"enterprise\":%s,"
                        "\"auth\":\"%s\",\"cipher\":\"%s\"}",
                        i ? "," : "", jsonEscape(n.ssid).c_str(), n.signalQuality,
                        n.enterprise() ? "true" : "false",
                        jsonEscape(authName(n.auth)).c_str(),
                        jsonEscape(cipherName(n.cipher)).c_str());
        }
        std::printf("]}\n");
        return;
    }

    if (nets.empty()) {
        std::puts("no networks found");
        return;
    }

    std::printf("%-32s %6s  %-26s %-16s %s\n", "SSID", "SIGNAL", "AUTH", "CIPHER",
                "FLAGS");
    std::puts(std::string(100, '-').c_str());
    for (const auto& n : nets) {
        std::string flags;
        if (n.enterprise()) flags += "[ENTERPRISE] ";
        if (!n.connectable) flags += "[" + winError(n.notConnectableReason) + "]";
        std::printf("%-32s %5lu%%  %-26s %-16s %s\n", n.ssid.c_str(), n.signalQuality,
                    authName(n.auth).c_str(), cipherName(n.cipher).c_str(),
                    flags.c_str());
    }
}

// ---------------------------------------------------------------- list ------

void cmdList(Wlan& wlan, const std::string& ifaceOpt) {
    GUID g = pickInterface(wlan, ifaceOpt);
    auto profs = wlan.profiles(g);
    if (profs.empty()) {
        std::puts("no saved profiles");
        return;
    }
    std::puts("saved profiles:");
    for (const auto& p : profs) std::printf("  %s\n", narrow(p).c_str());
}

// -------------------------------------------------------------- status ------

void cmdStatus(Wlan& wlan, const std::string& ifaceOpt) {
    for (const auto& i : wlan.interfaces()) {
        // Honour --interface; otherwise report every adapter.
        if (!ifaceOpt.empty() && guidToString(i.guid) != ifaceOpt &&
            narrow(i.description) != ifaceOpt)
            continue;

        std::printf("interface: %s\n  guid:     %s\n  state:    %s\n",
                    narrow(i.description).c_str(), guidToString(i.guid).c_str(),
                    stateName(i.state).c_str());

        if (i.state == wlan_interface_state_connected) {
            try {
                WLAN_CONNECTION_ATTRIBUTES c = wlan.connection(i.guid);
                std::printf("  profile:  %s\n", narrow(c.strProfileName).c_str());
                // DOT11_MAC_ADDRESS is a plain UCHAR[6], not a struct.
                const DOT11_MAC_ADDRESS& mac =
                    c.wlanAssociationAttributes.dot11Bssid;
                std::printf("  bssid:    %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0],
                            mac[1], mac[2], mac[3], mac[4], mac[5]);
                std::printf("  phy:      %u\n",
                            c.wlanAssociationAttributes.dot11PhyType);
                std::printf("  auth:     %s\n",
                            authName(c.wlanSecurityAttributes.dot11AuthAlgorithm)
                                .c_str());
                std::printf("  cipher:   %s\n",
                            cipherName(c.wlanSecurityAttributes.dot11CipherAlgorithm)
                                .c_str());
                std::printf("  802.1X:   %s\n",
                            c.wlanSecurityAttributes.bOneXEnabled ? "required" : "not in use");
            } catch (const std::exception& e) {
                std::printf("  (could not read connection details: %s)\n", e.what());
            }
        }
        std::puts("");
    }
}

// ------------------------------------------------------------- connect ------

// Returns the process exit code: 0 on success, 1 on failure. The CLI is
// documented as being for scripting, so a failed connect must not report 0.
int cmdConnect(Wlan& wlan, ProfileOptions opt, const std::string& ifaceOpt,
               bool allUsers, DWORD timeoutMs, bool dryRun, int maxLevel) {
    std::string xml = buildProfileXml(opt);

    if (dryRun) {
        std::puts(redactPassword(xml).c_str());
        return 0;
    }

    GUID g = pickInterface(wlan, ifaceOpt);
    std::printf("interface: %s\n", guidToString(g).c_str());

    // Progress is reported through a callback so this exact logic can be shared
    // with the GUI; here it just goes to stdout.
    ConnectResult r = connectWithLadder(
        wlan, g, opt, allUsers, timeoutMs, maxLevel,
        [](Stage stage, const std::string& msg) {
            switch (stage) {
                case Stage::Installing:
                case Stage::Associating:
                    std::printf("%s\n", msg.c_str());
                    std::fflush(stdout);
                    break;
                case Stage::Failed:
                    std::fprintf(stderr, "%s\n", msg.c_str());
                    break;
                default:
                    break;
            }
        });

    if (!r.attempts.empty()) {
        std::printf("\nladder summary:\n");
        for (const std::string& line : r.attempts)
            std::printf("  %s\n", line.c_str());
    }

    if (r.ok) {
        std::printf("\n%s\n", r.message.c_str());
        return 0;
    }
    std::fprintf(stderr, "\n%s\n", r.message.c_str());
    std::fputs(troubleshootingHint().c_str(), stderr);
    return 1;
}

// ---------------------------------------------------------------- caps ------

// Lists the auth/cipher combinations this adapter supports. If WPA2-Enterprise
// is missing here, no 802.1X profile will ever be accepted.
void cmdCaps(Wlan& wlan, const std::string& ifaceOpt) {
    GUID g = pickInterface(wlan, ifaceOpt);
    auto pairs = wlan.supportedAuthCipherPairs(g);
    if (pairs.empty()) {
        std::puts("could not query supported auth/cipher pairs");
        return;
    }
    std::puts("adapter supports:");
    bool enterprise = false;
    for (const auto& p : pairs) {
        std::printf("  %s\n", p.c_str());
        if (p.find("Enterprise") != std::string::npos) enterprise = true;
    }
    if (!enterprise)
        std::puts("  !! no Enterprise mode listed - 802.1X profiles will be rejected");
}

// --------------------------------------------------------------- install -----

// Installs a profile XML file verbatim. Useful for importing a profile from an
// administrator, and for testing whether a given XML is accepted by Windows.
void cmdInstall(Wlan& wlan, const std::string& ifaceOpt, const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open: " + path);
    std::string xml((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (xml.empty()) throw std::runtime_error("file is empty: " + path);

    GUID g = pickInterface(wlan, ifaceOpt);
    std::string reason;
    wlan.setProfile(g, widen(xml), false, &reason);
    std::printf("installed %s\n", path.c_str());
}

// ------------------------------------------------------------- diagnose -----

// One-shot health check: clock, CA trust, adapter capability, profile XML
// validity and the last recorded EAP failure.
void cmdDiagnose(Wlan& wlan, const std::string& ifaceOpt, ProfileOptions opt) {
    std::printf("=== edurm diagnose ===\n\n");

    std::printf("[1] system clock\n%s\n\n", checkSystemClock().c_str());

    std::printf("[2] trusted roots\n%s\n\n", describeRootTrust().c_str());

    GUID g{};
    bool haveIface = false;
    try {
        g = pickInterface(wlan, ifaceOpt);
        haveIface = true;
    } catch (const std::exception& e) {
        std::printf("[3] adapter\n  ERROR: %s\n\n", e.what());
    }

    if (haveIface) {
        std::printf("[3] adapter capability\n%s\n", wlan.capabilitySummary(g).c_str());
        std::printf("  WPA2-Enterprise + AES usable: %s\n\n",
                    wlan.supportsEnterpriseAes(g) ? "yes" : "NO");
    }

    // XML validity: ask Windows to parse it without keeping it.
    std::printf("[4] profile XML validity\n");
    // The probe must carry its OWN profile name. Installing XML whose <name> is
    // the user's real profile (default "eduroam") silently overwrote it, and
    // then the forget() below targeted a name that never existed, so the damage
    // was never cleaned up.
    ProfileOptions probeOpt = opt;
    probeOpt.profileName = "edurm-diagnose-probe";
    std::string probeXml;
    try {
        probeXml = buildProfileXml(probeOpt);
    } catch (const std::exception& e) {
        std::printf("  cannot build profile: %s\n\n", e.what());
    }
    if (!probeXml.empty()) {
        std::string reason;
        DWORD rc = 0;
        try {
            wlan.setProfile(g, widen(probeXml), false, &reason, &rc);
            std::printf("  netsh/WlanSetProfile: ACCEPTED\n\n");
        } catch (const std::exception& e) {
            std::printf("  netsh/WlanSetProfile: REJECTED\n");
            std::printf("  error : %s\n", e.what());
            std::string eap = rc ? explainEapError(rc) : std::string();
            if (!eap.empty()) std::printf("  eap   : %s\n", eap.c_str());
            std::printf(
                "\n  A rejection here is a profile-format problem, independent of "
                "credentials or certificates.\n\n");
        }
        // Always attempt the cleanup, so a profile this command created does not
        // linger even when the install succeeded.
        try {
            wlan.forget(g, widen(probeOpt.profileName));
        } catch (const std::exception&) {
            // probe was never installed; nothing to clean up
        }
    }

    std::printf("[5] last recorded EAP failure\n");
    FailureDiagnosis d = diagnoseLastFailure();
    std::printf("  %s\n", d.summary.c_str());
    if (!d.likelyCause.empty()) {
        std::printf("  cause  : %s\n", d.likelyCause.c_str());
        std::printf("  action : %s\n", d.suggestedAction.c_str());
    }
    for (const std::string& e : d.evidence)
        std::printf("    - %s\n", e.c_str());
}

// ---------------------------------------------------------- install-ca ------

void cmdInstallCa(const std::string& path, bool machineWide) {
    std::printf("Installing CA certificate from %s\n", path.c_str());
    std::printf(machineWide ? "(into the machine store; needs administrator rights)\n\n"
                            : "(into the current user's store)\n\n");
    std::string subject = installCaIntoRootStore(path, machineWide);
    std::printf("installed: %s\n", subject.c_str());
    if (machineWide)
        std::printf(
            "\nThe certificate is now trusted machine-wide. Retry with:\n"
            "  edurm connect --username <id>@<realm>\n");
    else
        std::printf(
            "\nThe certificate is now trusted for YOUR account only. Other users and\n"
            "services on this machine will not trust it. To trust it machine-wide, run\n"
            "this from an elevated prompt:  edurm install-ca <file> --machine\n");
}

// ---------------------------------------------------------- restore-tls -----

void cmdRestoreTls() {
    std::printf("Restoring the SCHANNEL TLS defaults (requires administrator rights)\n\n");
    std::string note;
    restoreLegacyTls(true, &note);
    std::printf("%s", note.c_str());
    std::printf(
        "\nNote: this removes only the keys this tool created. Windows normally\n"
        "ships with TLS 1.0/1.1 already disabled by default.\n");
}

// ----------------------------------------------------------- disconnect ------

void cmdDisconnect(Wlan& wlan, const std::string& ifaceOpt) {
    GUID g = pickInterface(wlan, ifaceOpt);
    wlan.disconnect(g);
    wlan.waitForState(g, wlan_interface_state_disconnected, 10000);
    std::puts("disconnected");
}

// --------------------------------------------------------------- forget ------

void cmdForget(Wlan& wlan, const std::string& ifaceOpt, const std::string& name) {
    GUID g = pickInterface(wlan, ifaceOpt);
    wlan.forget(g, widen(name));
    std::printf("deleted profile '%s'\n", name.c_str());
}

// --------------------------------------------------------------- export ------

void cmdExport(Wlan& wlan, const std::string& ifaceOpt, const std::string& name) {
    GUID g = pickInterface(wlan, ifaceOpt);
    std::wstring xml;
    try {
        xml = wlan.exportProfile(g, widen(name));
    } catch (const std::exception& e) {
        std::fprintf(stderr,
                     "%s\n"
                     "note: reading the password back needs administrator rights.\n",
                     e.what());
        throw;
    }
    std::puts(redactPassword(narrow(xml)).c_str());
}

// ---------------------------------------------------------------- roots ------
//
// eduroam chains to the eduroam ROOT CA, but the RADIUS server usually presents
// an intermediate (the "eduroam Deployment Server" or the institution's own CA).
// A missing intermediate in the trusted store is the #1 eduroam failure, so give
// the user something concrete to look at.

void cmdRoots() {
    CaInfo info = checkEduroamRoots();

    if (info.found) {
        std::printf("trusted root CAs matching eduroam / RADIUS keywords:\n");
        for (const auto& s : info.subjects) std::printf("  %s\n", s.c_str());
        std::printf("\n  %zu matching root(s) present.\n", info.subjects.size());
        return;
    }

    std::printf("trusted root CAs matching eduroam / RADIUS keywords:\n  (none found)\n\n  %s\n",
                info.advice.c_str());
}

// ----------------------------------------------------------------- main ------

struct Args {
    ProfileOptions opt;
    std::string iface;
    std::string command;
    std::string positional;
    bool allUsers{false};
    bool dryRun{false};
    bool redact{false};
    bool json{false};
    DWORD timeout{45000};
    // Deepest verification level the user has consented to (1..4).
    int maxLevel{1};
    std::string caCertPath;
    bool allowLegacyTls{false};
    bool insecureSkip{false};
    bool machineWide{false};
};

Args parseArgs(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc)
                throw std::runtime_error(std::string("missing value for ") + name);
            return argv[++i];
        };

        if (s == "--ssid") a.opt.ssid = next("--ssid");
        else if (s == "--profile") a.opt.profileName = next("--profile");
        else if (s == "--username") a.opt.username = next("--username");
        else if (s == "--domain") a.opt.domain = next("--domain");
        else if (s == "--server") a.opt.serverName = next("--server");
        else if (s == "--server-name") a.opt.serverName = next("--server-name");
        else if (s == "--anonymous-identity")
            a.opt.anonymousIdentity = next("--anonymous-identity");
        else if (s == "--pin-sha256")
            a.opt.trustedRootCaBase64 = findCertificateBySha256(next("--pin-sha256"));
        else if (s == "--ca-cert") a.caCertPath = next("--ca-cert");
        else if (s == "--max-level") {
            if (!parseVerifyLevel(next("--max-level"), &a.opt.level))
                throw std::runtime_error("--max-level must be 1..4");
            a.maxLevel = static_cast<int>(a.opt.level);
        } else if (s == "--insecure-skip-validation") {
            a.insecureSkip = true;
            a.maxLevel = 4;
        } else if (s == "--allow-legacy-tls") {
            a.allowLegacyTls = true;
            if (a.maxLevel < 3) a.maxLevel = 3;
        }
        else if (s == "--password") a.opt.password = next("--password");
        else if (s == "--interface") a.iface = next("--interface");
        else if (s == "--all-users") a.allUsers = true;
        else if (s == "--machine") a.machineWide = true;
        else if (s == "--tkip") a.opt.useTkip = true;
        else if (s == "--psk") a.opt.pskMode = true;
        else if (s == "--no-suffix-match") { /* handled via --server-name */ }
        else if (s == "--json") a.json = true;
        else if (s == "--dry-run") a.dryRun = true;
        else if (s == "--redact") a.redact = true;
        else if (s == "--timeout") a.timeout = (DWORD)std::stoul(next("--timeout"));
        else if (s == "--password-stdin") {
            std::string line;
            std::getline(std::cin, line);
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            a.opt.password = line;
        } else if (s.rfind("-", 0) == 0) {
            throw std::runtime_error("unknown option: " + s);
        } else if (a.command.empty()) {
            a.command = s;
        } else {
            a.positional = s;
        }
    }
    return a;
}

}  // namespace

int main(int argc, char** argv) {
    // Make Windows console output UTF-8 so SSIDs and cert names render correctly.
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    try {
        Args a = parseArgs(argc, argv);

        if (a.command.empty() || a.command == "help" || a.command == "--help" ||
            a.command == "-h") {
            printUsage();
            return 0;
        }

        // 'xml' and 'roots' do not need a client handle.
        if (a.command == "xml") {
            // This command exists to produce a deployable profile file, so the
            // password is included when one was supplied. Use --redact when
            // piping to a terminal, a log, or a bug report.
            std::string xml = buildProfileXml(a.opt);
            std::puts(a.redact ? redactPassword(xml).c_str() : xml.c_str());
            return 0;
        }
        if (a.command == "roots") {
            cmdRoots();
            return 0;
        }
        if (a.command == "install-ca") {
            if (a.positional.empty())
                throw std::runtime_error("install-ca requires a certificate file");
            cmdInstallCa(a.positional, a.machineWide);
            return 0;
        }
        if (a.command == "restore-tls") {
            cmdRestoreTls();
            return 0;
        }

        // --ca-cert also installs into the trusted store, so that a later
        // strict connect can succeed even without pinning.
        if (!a.caCertPath.empty()) {
            a.opt.trustedRootCaBase64 = loadCertificateBase64(a.caCertPath);
        }

        Wlan wlan;
        if (a.command == "diagnose") cmdDiagnose(wlan, a.iface, a.opt);
        else if (a.command == "scan") cmdScan(wlan, a.iface, a.json);
        else if (a.command == "list") cmdList(wlan, a.iface);
        else if (a.command == "status") cmdStatus(wlan, a.iface);
        else if (a.command == "caps") cmdCaps(wlan, a.iface);
        else if (a.command == "connect") {
            if (a.opt.password.empty() && !a.dryRun) {
                a.opt.password = readSecret("Password: ");
                // Ctrl+C and a non-interactive stdin both leave this empty.
                // Authenticating with an empty password only produces a
                // confusing RADIUS rejection much later, so stop here.
                if (a.opt.password.empty()) {
                    std::fputs(
                        "error: no password supplied. Pass --password-stdin "
                        "(echo secret | edurm connect --password-stdin) or "
                        "--password.\n",
                        stderr);
                    return 1;
                }
            }

            if (a.insecureSkip && !a.dryRun) {
                std::printf(
                    "################################################################\n"
                    "#  WARNING: --insecure-skip-validation (Level 4)          #\n"
                    "#  The RADIUS server's certificate will NOT be checked.   #\n"
                    "#  Anyone able to broadcast an access point named         #\n"
                    "#  'eduroam' can capture your username and password.      #\n"
                    "#  Use this only on a network you control, and only to    #\n"
                    "#  prove that validation is the blocker.                   #\n"
                    "################################################################\n\n");
            }
            if (a.allowLegacyTls && !a.dryRun) {
                std::printf("Enabling legacy TLS client protocols (Level 3)...");
                std::string note;
                if (enableLegacyTls(true, &note)) {
                    std::printf(" done\n");
                    std::printf("%s", note.c_str());
                    std::printf("Undo later with:  edurm restore-tls\n\n");
                } else {
                    std::printf(" FAILED (administrator rights required)\n");
                    std::printf("continuing; the ladder will still try.\n\n");
                }
            }

            return cmdConnect(wlan, a.opt, a.iface, a.allUsers, a.timeout, a.dryRun,
                              a.maxLevel);
        } else if (a.command == "disconnect") cmdDisconnect(wlan, a.iface);
        else if (a.command == "install") {
            if (a.positional.empty())
                throw std::runtime_error("install requires a path to an XML file");
            cmdInstall(wlan, a.iface, a.positional);
        } else if (a.command == "forget") {
            if (a.positional.empty())
                throw std::runtime_error("forget requires a profile name");
            cmdForget(wlan, a.iface, a.positional);
        } else if (a.command == "export") {
            if (a.positional.empty())
                throw std::runtime_error("export requires a profile name");
            cmdExport(wlan, a.iface, a.positional);
        } else {
            std::fprintf(stderr, "unknown command: %s\n\n", a.command.c_str());
            printUsage();
            return 2;
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}
