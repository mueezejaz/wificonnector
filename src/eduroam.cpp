#include "eduroam.h"

#include "diag.h"
#include "util.h"

#include <wincrypt.h>  // must follow windows.h

#include <cwctype>
#include <fstream>
#include <sstream>

namespace edurm {

bool isConnected(Wlan& wlan, const GUID& iface) {
    try {
        return wlan.connection(iface).isState == wlan_interface_state_connected;
    } catch (const std::exception&) {
        return false;
    }
}

ConnectResult installAndConnect(Wlan& wlan, const GUID& iface,
                                const ProfileOptions& opt, bool allUsers,
                                DWORD timeoutMs, const ProgressFn& onProgress) {
    ProgressFn emit = onProgress ? onProgress : ProgressFn();
    ConnectResult res;

    std::string xml;
    try {
        xml = buildProfileXml(opt);
    } catch (const std::exception& e) {
        if (emit) emit(Stage::Failed, std::string("invalid settings: ") + e.what());
        res.message = e.what();
        return res;
    }

    if (emit)
        emit(Stage::Installing, std::string("Installing profile (level ") +
                                   verifyLevelName(opt.level) + ")");

    std::string reason;
    DWORD reasonCode = 0;
    try {
        wlan.setProfile(iface, widen(xml), allUsers, &reason, &reasonCode);
    } catch (const std::exception& e) {
        // The profile itself was rejected. reasonCode here is a raw Win32 error
        // (e.g. 1 = ERROR_INVALID_FUNCTION), NOT a WLAN reason code, so do not
        // run it through explainWlanReason().
        std::string msg = e.what();
        std::string eap = explainEapError(reasonCode);
        if (!eap.empty()) msg += "; " + eap;
        if (emit) emit(Stage::Failed, msg);
        res.message = msg;
        return res;
    }

    // PEAP credentials must NOT live in the profile XML. They are attached with
    // WlanSetProfileEapXmlUserData, which is how Windows stores per-user EAP
    // data and encrypts it.
    if (!opt.pskMode && !opt.username.empty()) {
        try {
            wlan.setEapXmlUserData(iface, widen(opt.profileName),
                                   widen(buildEapUserCredentialsXml(opt)), allUsers);
        } catch (const std::exception& e) {
            if (emit) emit(Stage::Failed, std::string("could not store credentials: ") + e.what());
            res.message = e.what();
            return res;
        }
    }

    if (emit)
        emit(Stage::Associating,
             opt.pskMode ? "Associating with preshared key..."
                         : "Associating and running 802.1X...");

    try {
        wlan.connect(iface, widen(opt.profileName));
    } catch (const std::exception& e) {
        if (emit) emit(Stage::Failed, e.what());
        res.message = e.what();
        return res;
    }

    WLAN_INTERFACE_STATE s =
        wlan.waitForState(iface, wlan_interface_state_connected, timeoutMs);
    if (s == wlan_interface_state_connected) {
        res.ok = true;
        res.levelUsed = static_cast<int>(opt.level);
        res.levelName = verifyLevelName(opt.level);
        res.message = "Connected via profile '" + opt.profileName + "' (level " +
                      res.levelName + ")";
        if (emit) emit(Stage::Succeeded, res.message);
        return res;
    }

    res.message = "did not reach 'connected' (last state: " + stateName(s) + ")";
    if (reasonCode) {
        std::string why = explainWlanReason(reasonCode);
        if (!why.empty()) res.message += "; reason: " + why;
        std::string eap = explainEapError(reasonCode);
        if (!eap.empty()) res.message += "; eap: " + eap;
    }
    if (emit) {
        emit(Stage::Failed, res.message);
        FailureDiagnosis d = diagnoseLastFailure();
        if (!d.likelyCause.empty()) {
            emit(Stage::Failed, "likely cause: " + d.likelyCause);
            if (!d.suggestedAction.empty())
                emit(Stage::Failed, "suggested: " + d.suggestedAction);
        }
    }
    return res;
}

ConnectResult connectWithLadder(Wlan& wlan, const GUID& iface,
                                const ProfileOptions& base, bool allUsers,
                                DWORD timeoutMs, int maxLevel,
                                const ProgressFn& onProgress) {
    ConnectResult final;
    if (maxLevel < 1) maxLevel = 1;

    // Level 3 is not a profile difference on this build - it is a machine-wide
    // TLS setting - so it is reported rather than silently changed.
    const bool legacyWarned = (maxLevel >= 3);

    for (int lvl = 1; lvl <= maxLevel; ++lvl) {
        ProfileOptions opt = base;
        opt.level = static_cast<VerifyLevel>(lvl);

        if (lvl >= 2 && opt.trustedRootCaBase64.empty()) {
            final.attempts.push_back(
                "level 2 (pinned) skipped: no CA supplied. Use --ca-cert or "
                "--pin-sha256.");
            continue;
        }

        if (lvl == 3 && !legacyWarned) {
            final.attempts.push_back("level 3 (legacy-tls) skipped: not requested");
            continue;
        }
        if (lvl == 4) {
            final.attempts.push_back(
                "level 4 (no-validation) ATTEMPTED - the server certificate is not "
                "being checked. Anyone on this network could capture your password.");
        }

        ConnectResult r = installAndConnect(wlan, iface, opt, allUsers, timeoutMs,
                                            onProgress);
        final.attempts.push_back("level " + std::to_string(lvl) + " (" +
                                  verifyLevelName(opt.level) + "): " +
                                  (r.ok ? "connected" : r.message));

        if (r.ok) {
            r.attempts = final.attempts;
            return r;
        }
        final = r;
        final.levelUsed = 0;
        final.levelName.clear();
    }

    final.message = "all permitted verification levels failed";
    if (onProgress) onProgress(Stage::Failed, final.message);
    return final;
}

std::string troubleshootingHint() {
    return
        "For the exact 802.1X reason code, run:  netsh wlan show wlanreport\n"
        "or check Event Viewer > Applications and Services Logs >\n"
        "Microsoft > Windows > WLAN-AutoConfig > Operational (event 12012),\n"
        "which carries the EAP failure text.\n"
        "\n"
        "Common causes, in order:\n"
        "  - the eduroam CA bundle is not in the trusted root store\n"
        "    (install from https://www.eduroam.org/ or your IT desk)\n"
        "  - the system clock is wrong (certificates are validated against it)\n"
        "  - the server certificate is issued for a name other than the realm\n"
        "  - wrong username or password (eduroam wants roll-number@realm)\n"
        "  - the RADIUS server only offers an old TLS version\n";
}

// ------------------------------------------------------------------- CA ----

namespace {

std::string certDisplayName(PCCERT_CONTEXT ctx) {
    DWORD size =
        CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
    if (size == 0) return {};
    std::wstring out(size, L'\0');
    if (!CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, out.data(),
                            size))
        return {};
    while (!out.empty() && out.back() == L'\0') out.pop_back();
    return narrow(out);
}

std::string fileToBase64(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open: " + path);
    std::string raw((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
    std::string body;
    if (raw.find("-----BEGIN") != std::string::npos) {
        size_t b = raw.find('\n', raw.find("-----BEGIN"));
        size_t e = raw.find("-----END");
        if (b == std::string::npos || e == std::string::npos || e < b)
            throw std::runtime_error("malformed PEM: " + path);
        body = raw.substr(b + 1, e - b - 1);
        std::string cleaned;
        for (char c : body)
            if (c != '-' && !isspace(static_cast<unsigned char>(c))) cleaned.push_back(c);
        body = cleaned;
    } else {
        body = raw;
    }
    std::string trimmed;
    for (char c : body)
        if (!isspace(static_cast<unsigned char>(c))) trimmed.push_back(c);
    return trimmed;
}

}  // namespace

std::string installCaIntoRootStore(const std::string& path, bool machineWide) {
    (void)machineWide;  // always the machine store; per-user adds no safety here
    std::string b64 = fileToBase64(path);
    DWORD len = static_cast<DWORD>(b64.size() / 4 * 3 + 3);
    std::vector<unsigned char> der(len);
    if (!CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
                               CRYPT_STRING_BASE64, der.data(), &len, nullptr,
                               nullptr) ||
        len == 0)
        throw std::runtime_error("could not decode certificate: " + path);

    HCERTSTORE store = CertOpenSystemStoreW(0, L"ROOT");
    if (!store) throw std::runtime_error("CertOpenSystemStore failed");

    PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING, der.data(),
                                                       len);
    if (!ctx) {
        CertCloseStore(store, 0);
        throw std::runtime_error("CertCreateCertificateContext failed");
    }
    std::string subject = certDisplayName(ctx);
    if (subject.empty()) subject = "(unnamed)";

    BOOL ok = CertAddEncodedCertificateToStore(
        store, X509_ASN_ENCODING, der.data(), len, CERT_STORE_ADD_REPLACE_EXISTING,
        nullptr);
    CertFreeCertificateContext(ctx);
    CertCloseStore(store, 0);

    if (!ok) throw std::runtime_error("CertAddEncodedCertificateToStore failed");
    return subject;
}

CaInfo checkEduroamRoots() {
    CaInfo info;
    HCERTSTORE store = CertOpenSystemStoreW(0, L"ROOT");
    if (!store) {
        info.advice = "could not open the trusted root store";
        return info;
    }

    PCCERT_CONTEXT ctx = nullptr;
    while ((ctx = CertEnumCertificatesInStore(store, ctx)) != nullptr) {
        std::wstring lower = widen(certDisplayName(ctx));
        for (auto& ch : lower) ch = static_cast<wchar_t>(towlower(ch));
        if (lower.find(L"eduroam") != std::wstring::npos ||
            lower.find(L"terena") != std::wstring::npos ||
            lower.find(L"edupki") != std::wstring::npos ||
            lower.find(L"geant") != std::wstring::npos ||
            lower.find(L"radsec") != std::wstring::npos)
            info.subjects.push_back(certDisplayName(ctx));
    }
    CertCloseStore(store, 0);

    info.found = !info.subjects.empty();
    if (!info.found)
        info.advice =
            "No eduroam/eduPKI root was found by name. Note this is a keyword "
            "search of certificate subjects: a RADIUS server using a public-CA "
            "certificate will not match, so this can report 'none' even when "
            "connecting would work. Only a failed connection proves it is missing.";
    return info;
}

// -------------------------------------------------------- legacy TLS 1.x ---
//
// These live under HKLM, so they need an elevated process. We delete exactly the
// values we create so restoreLegacyTls() is a true undo.

namespace {

const char* kSchannel =
    R"(SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols)";
const char* kTlsVersions[] = {"TLS 1.0", "TLS 1.1"};

}  // namespace

bool enableLegacyTls(bool machineWide, std::string* note) {
    std::ostringstream os;
    os << "keys written:\n";
    for (const char* ver : kTlsVersions)
        os << "  HKLM\\" << kSchannel << "\\" << ver
           << "\\Client  Enabled=1 DisabledByDefault=0\n";
    os << "WARNING: this lowers the TLS floor for the whole machine.\n";
    if (note) *note = os.str();

    bool allOk = true;
    for (const char* ver : kTlsVersions) {
        std::wstring path =
            widen(std::string(kSchannel)) + L"\\" + widen(std::string(ver)) + L"\\Client";
        HKEY key = nullptr;
        LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr,
                                  REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr,
                                  &key, nullptr);
        if (rc != ERROR_SUCCESS) {
            allOk = false;
            continue;
        }
        DWORD enabled = 1, disabledByDefault = 0;
        RegSetValueExW(key, L"Enabled", 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&enabled), sizeof(enabled));
        RegSetValueExW(key, L"DisabledByDefault", 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&disabledByDefault),
                       sizeof(disabledByDefault));
        RegCloseKey(key);
    }
    (void)machineWide;
    return allOk;
}

bool restoreLegacyTls(bool machineWide, std::string* note) {
    std::ostringstream os;
    for (const char* ver : kTlsVersions) {
        std::wstring path =
            widen(std::string(kSchannel)) + L"\\" + widen(std::string(ver)) + L"\\Client";
        LONG rc = RegDeleteKeyW(HKEY_LOCAL_MACHINE, path.c_str());
        os << "  HKLM\\" << kSchannel << "\\" << ver
           << "\\Client : " << (rc == ERROR_SUCCESS ? "removed" : "was absent")
           << "\n";
    }
    (void)machineWide;
    if (note) *note = os.str();
    return true;
}

}  // namespace edurm