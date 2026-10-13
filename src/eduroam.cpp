#include "eduroam.h"

#include "util.h"

#include <wincrypt.h>  // must follow windows.h (pulled in by wlan.h)

#include <cwctype>

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

    std::string xml;
    try {
        xml = buildProfileXml(opt);
    } catch (const std::exception& e) {
        if (emit) emit(Stage::Failed, std::string("invalid settings: ") + e.what());
        return {false, e.what()};
    }

    if (emit)
        emit(Stage::Installing,
             "Installing profile '" + opt.profileName + "' (SSID " + opt.ssid + ", " +
                 opt.username + ")");

    std::string reason;
    try {
        wlan.setProfile(iface, widen(xml), allUsers, &reason);
    } catch (const std::exception& e) {
        if (emit) emit(Stage::Failed, e.what());
        return {false, e.what()};
    }
    if (!reason.empty() && emit) emit(Stage::Installing, "OS reason: " + reason);

    if (emit)
        emit(Stage::Associating,
             opt.pskMode ? "Associating with preshared key..."
                         : "Associating and running 802.1X...");

    try {
        wlan.connect(iface, widen(opt.profileName));
    } catch (const std::exception& e) {
        if (emit) emit(Stage::Failed, e.what());
        return {false, e.what()};
    }

    WLAN_INTERFACE_STATE s =
        wlan.waitForState(iface, wlan_interface_state_connected, timeoutMs);
    if (s == wlan_interface_state_connected) {
        std::string profile = opt.profileName;
        try {
            profile = narrow(wlan.connection(iface).strProfileName);
        } catch (const std::exception&) {
            // keep the name we asked for
        }
        if (emit) emit(Stage::Succeeded, "Connected via profile '" + profile + "'");
        return {true, "Connected via profile '" + profile + "'"};
    }

    std::string msg = "did not reach 'connected' (last state: " + stateName(s) + ")";
    if (emit) emit(Stage::Failed, msg + "\n" + troubleshootingHint());
    return {false, msg};
}

std::string troubleshootingHint() {
    return
        "For the exact 802.1X reason code, run:  netsh wlan show wlanreport\n"
        "or check Event Viewer > Applications and Services Logs >\n"
        "Microsoft > Windows > WLAN-AutoConfig > Operational (event 12012),\n"
        "which carries the EAP failure text.\n"
        "\n"
        "Common eduroam causes:\n"
        "  - wrong username/password\n"
        "  - the system clock is wrong (certificates are validated against it)\n"
        "  - the AAA certificate is not issued for your realm; check the CA\n"
        "    bundle and adjust the realm/domain suffix\n"
        "  - the realm's intermediate CA is missing from the trusted root store\n";
}

namespace {

std::wstring certDisplayName(PCCERT_CONTEXT ctx) {
    // cchNameString is a value, not a pointer; 0 asks for the required size.
    DWORD size =
        CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
    if (size == 0) return {};
    std::wstring out(size, L'\0');
    if (!CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, out.data(),
                            size))
        return {};
    while (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

bool mentionsEduroam(const std::wstring& lower) {
    return lower.find(L"eduroam") != std::wstring::npos ||
           lower.find(L"terena") != std::wstring::npos ||
           lower.find(L"radsec") != std::wstring::npos ||
           lower.find(L"uaf") != std::wstring::npos;
}

}  // namespace

CaInfo checkEduroamRoots() {
    CaInfo info;

    // The legacy-provider argument is ignored for the "ROOT" store; 0 is the
    // documented way to pass "no provider".
    HCERTSTORE store = CertOpenSystemStoreW(0, L"ROOT");
    if (!store) {
        info.advice = "could not open the trusted root store";
        return info;
    }

    PCCERT_CONTEXT ctx = nullptr;
    while ((ctx = CertEnumCertificatesInStore(store, ctx)) != nullptr) {
        std::wstring name = certDisplayName(ctx);
        std::wstring lower = name;
        for (auto& ch : lower) ch = static_cast<wchar_t>(towlower(ch));
        if (mentionsEduroam(lower)) info.subjects.push_back(narrow(name));
    }
    CertCloseStore(store, 0);

    info.found = !info.subjects.empty();
    if (!info.found)
        info.advice =
            "The eduroam CA bundle is not installed on this machine.\n"
            "Install it via your institution's eduroam Configuration Assistant\n"
            "Tool, or fetch the current bundle from https://www.eduroam.org/.\n"
            "Certificates live under: certmgr.msc -> Trusted Root Certification\n"
            "Authorities. Until then, 802.1X will fail certificate validation.";
    return info;
}

}  // namespace edurm