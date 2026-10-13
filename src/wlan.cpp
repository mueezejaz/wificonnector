#include "wlan.h"

#include "util.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <thread>

namespace edurm {
namespace {

// Wlan* functions hand back a single buffer that must go back to the service
// via WlanFreeMemory (not free/delete).
struct MemFree {
    void operator()(void* p) const noexcept {
        if (p) WlanFreeMemory(p);
    }
};

template <typename T>
using Owned = std::unique_ptr<T, MemFree>;

WLAN_INTERFACE_STATE currentState(Wlan& w, const GUID& iface) {
    WLAN_INTERFACE_STATE state = wlan_interface_state_not_ready;
    DWORD size = sizeof(WLAN_CONNECTION_ATTRIBUTES);
    Owned<WLAN_CONNECTION_ATTRIBUTES> attrs(
        static_cast<WLAN_CONNECTION_ATTRIBUTES*>(malloc(size)));
    WLAN_OPCODE_VALUE_TYPE type = wlan_opcode_value_type_query_only;

    if (!attrs) return wlan_interface_state_not_ready;

    DWORD rc = WlanQueryInterface(w.handle(), &iface,
                                  wlan_intf_opcode_current_connection, nullptr,
                                  &size, reinterpret_cast<PVOID*>(&attrs), &type);
    if (rc != ERROR_SUCCESS) return wlan_interface_state_not_ready;
    state = attrs->isState;
    return state;
}

}  // namespace

bool NetworkInfo::enterprise() const {
    // eduroam identifies as WPA2-Enterprise: RSNA/WPA with 802.1X keying.
    if (auth == DOT11_AUTH_ALGO_RSNA || auth == DOT11_AUTH_ALGO_WPA) return true;
#if (NTDDI_VERSION >= NTDDI_WIN10_FE)
    if (auth == DOT11_AUTH_ALGO_WPA3_ENT) return true;
#endif
    return false;
}

Wlan::Wlan(DWORD clientVersion) {
    DWORD negotiated = 0;
    DWORD rc = WlanOpenHandle(clientVersion, nullptr, &negotiated, &h_);
    if (rc != ERROR_SUCCESS) {
        h_ = nullptr;
        throwWin32("WlanOpenHandle", rc);
    }
}

Wlan::~Wlan() {
    if (h_) {
        WlanCloseHandle(h_, nullptr);
        h_ = nullptr;
    }
}

std::vector<InterfaceInfo> Wlan::interfaces() {
    PWLAN_INTERFACE_INFO_LIST raw = nullptr;
    DWORD rc = WlanEnumInterfaces(h_, nullptr, &raw);
    if (rc != ERROR_SUCCESS) throwWin32("WlanEnumInterfaces", rc);
    Owned<WLAN_INTERFACE_INFO_LIST> list(raw);

    std::vector<InterfaceInfo> out;
    if (!list) return out;

    out.reserve(list->dwNumberOfItems);
    for (DWORD i = 0; i < list->dwNumberOfItems; ++i) {
        const WLAN_INTERFACE_INFO& src = list->InterfaceInfo[i];
        InterfaceInfo info;
        info.guid = src.InterfaceGuid;
        info.guidStr = guidToString(src.InterfaceGuid);
        info.description = src.strInterfaceDescription;
        info.state = src.isState;
        out.push_back(info);
    }
    return out;
}

std::vector<std::wstring> Wlan::profiles(const GUID& iface) {
    PWLAN_PROFILE_INFO_LIST raw = nullptr;
    DWORD rc = WlanGetProfileList(h_, &iface, nullptr, &raw);
    if (rc != ERROR_SUCCESS) throwWin32("WlanGetProfileList", rc);
    Owned<WLAN_PROFILE_INFO_LIST> list(raw);

    std::vector<std::wstring> out;
    if (!list) return out;

    out.reserve(list->dwNumberOfItems);
    for (DWORD i = 0; i < list->dwNumberOfItems; ++i)
        out.push_back(list->ProfileInfo[i].strProfileName);
    return out;
}

std::vector<NetworkInfo> Wlan::scan(const GUID& iface, int settleMs) {
    DWORD rc = WlanScan(h_, &iface, nullptr, nullptr, nullptr);
    if (rc != ERROR_SUCCESS && rc != ERROR_ALREADY_EXISTS)
        throwWin32("WlanScan", rc);

    // WlanScan is asynchronous: the results appear a moment later. Poll the
    // available-network list until it stops growing or the budget runs out.
    std::vector<NetworkInfo> best;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(settleMs < 0 ? 0 : settleMs);

    for (;;) {
        PWLAN_AVAILABLE_NETWORK_LIST raw = nullptr;
        DWORD listRc =
            WlanGetAvailableNetworkList(h_, &iface, 0, nullptr, &raw);
        if (listRc != ERROR_SUCCESS) throwWin32("WlanGetAvailableNetworkList", listRc);
        Owned<WLAN_AVAILABLE_NETWORK_LIST> list(raw);

        std::vector<NetworkInfo> cur;
        if (list) {
            cur.reserve(list->dwNumberOfItems);
            for (DWORD i = 0; i < list->dwNumberOfItems; ++i) {
                const WLAN_AVAILABLE_NETWORK& src = list->Network[i];
                NetworkInfo n;
                n.ssid = ssidToString(src.dot11Ssid);
                n.profileName = src.strProfileName;
                n.connectable = src.bNetworkConnectable != FALSE;
                n.notConnectableReason = static_cast<DWORD>(src.wlanNotConnectableReason);
                n.signalQuality = src.wlanSignalQuality;
                n.securityEnabled = src.bSecurityEnabled != FALSE;
                n.auth = src.dot11DefaultAuthAlgorithm;
                n.cipher = src.dot11DefaultCipherAlgorithm;
                n.bssidCount = src.uNumberOfBssids;
                cur.push_back(n);
            }
        }

        if (cur.size() >= best.size()) best.swap(cur);
        if (std::chrono::steady_clock::now() >= deadline) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    // Strongest first.
    std::sort(best.begin(), best.end(),
              [](const NetworkInfo& a, const NetworkInfo& b) {
                  return a.signalQuality > b.signalQuality;
              });
    return best;
}

WLAN_CONNECTION_ATTRIBUTES Wlan::connection(const GUID& iface) {
    DWORD size = sizeof(WLAN_CONNECTION_ATTRIBUTES);
    WLAN_OPCODE_VALUE_TYPE type = wlan_opcode_value_type_query_only;

    PWLAN_CONNECTION_ATTRIBUTES raw =
        static_cast<WLAN_CONNECTION_ATTRIBUTES*>(malloc(size));
    if (!raw) throw std::runtime_error("out of memory");

    DWORD rc = WlanQueryInterface(h_, &iface, wlan_intf_opcode_current_connection,
                                  nullptr, &size,
                                  reinterpret_cast<PVOID*>(&raw), &type);
    if (rc != ERROR_SUCCESS) {
        WlanFreeMemory(raw);
        throwWin32("WlanQueryInterface", rc);
    }

    WLAN_CONNECTION_ATTRIBUTES out = *raw;
    WlanFreeMemory(raw);
    return out;
}

void Wlan::setProfile(const GUID& iface, const std::wstring& xml, bool allUsers,
                      std::string* reasonOut) {
    // dwFlags of 0 means "all users"; WLAN_PROFILE_USER scopes it to the
    // current user, which is what you want for student credentials.
    DWORD flags = allUsers ? 0u : static_cast<DWORD>(WLAN_PROFILE_USER);
    DWORD reasonCode = 0;

    DWORD rc = WlanSetProfile(h_, &iface, flags, xml.c_str(),
                              // strAllUserProfileSecurity: encryption key for an
                              // all-user profile. Not used for enterprise/EAP
                              // profiles, which authenticate per user.
                              nullptr, TRUE /* bOverwrite */, nullptr, &reasonCode);
    if (reasonOut) *reasonOut = reasonCode ? reasonCodeText(reasonCode) : std::string();

    if (rc != ERROR_SUCCESS) {
        std::string msg = "WlanSetProfile: " + winError(rc);
        if (reasonCode && reasonCode != ERROR_SUCCESS)
            msg += "; reason: " + reasonCodeText(reasonCode);
        throw std::runtime_error(msg);
    }
}

void Wlan::connect(const GUID& iface, const std::wstring& profileName) {
    WLAN_CONNECTION_PARAMETERS params{};
    params.wlanConnectionMode = wlan_connection_mode_profile;
    params.strProfile = profileName.c_str();
    params.pDot11Ssid = nullptr;
    params.pDesiredBssidList = nullptr;
    params.dot11BssType = dot11_BSS_type_infrastructure;
    params.dwFlags = 0;

    DWORD rc = WlanConnect(h_, &iface, &params, nullptr);
    if (rc != ERROR_SUCCESS) throwWin32("WlanConnect", rc);
}

void Wlan::disconnect(const GUID& iface) {
    DWORD rc = WlanDisconnect(h_, &iface, nullptr);
    if (rc != ERROR_SUCCESS) throwWin32("WlanDisconnect", rc);
}

void Wlan::forget(const GUID& iface, const std::wstring& profileName) {
    DWORD rc = WlanDeleteProfile(h_, &iface, profileName.c_str(), nullptr);
    if (rc != ERROR_SUCCESS) throwWin32("WlanDeleteProfile", rc);
}

std::wstring Wlan::exportProfile(const GUID& iface,
                                 const std::wstring& profileName) {
    LPWSTR xml = nullptr;
    DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
    DWORD granted = 0;

    DWORD rc = WlanGetProfile(h_, &iface, profileName.c_str(), nullptr, &xml,
                              &flags, &granted);
    if (rc != ERROR_SUCCESS) throwWin32("WlanGetProfile", rc);
    if (!xml) return {};

    std::wstring out(xml);
    WlanFreeMemory(xml);
    return out;
}

std::vector<std::string> Wlan::supportedAuthCipherPairs(const GUID& iface) {
    // This opcode rejects the two-call "query the size first" pattern, so hand it a
// generously sized buffer up front. The list is variable-length, hence the slack.
constexpr DWORD kPairBufBytes = 64 * 1024;
PWLAN_AUTH_CIPHER_PAIR_LIST raw = static_cast<WLAN_AUTH_CIPHER_PAIR_LIST*>(
        malloc(kPairBufBytes));
    if (!raw) throw std::runtime_error("out of memory");

    DWORD size = kPairBufBytes;
    WLAN_OPCODE_VALUE_TYPE type = wlan_opcode_value_type_query_only;
    DWORD rc = WlanQueryInterface(
        h_, &iface, wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs,
        nullptr, &size, reinterpret_cast<PVOID*>(&raw), &type);
    if (rc != ERROR_SUCCESS || !raw) {
        WlanFreeMemory(raw);
        throwWin32("WlanQueryInterface(supported auth/cipher)", rc);
    }

    std::vector<std::string> out;
    for (DWORD i = 0; i < raw->dwNumberOfItems; ++i) {
        out.push_back(authName(raw->pAuthCipherPairList[i].AuthAlgoId) + " / " +
                      cipherName(raw->pAuthCipherPairList[i].CipherAlgoId));
    }
    WlanFreeMemory(raw);
    return out;
}

WLAN_INTERFACE_STATE Wlan::waitForState(const GUID& iface,
                                       WLAN_INTERFACE_STATE want, DWORD timeoutMs) {
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    for (;;) {
        WLAN_INTERFACE_STATE s = currentState(*this, iface);
        if (s == want) return s;
        if (s == wlan_interface_state_disconnected && want != wlan_interface_state_disconnected)
            return s;  // gave up early
        if (std::chrono::steady_clock::now() >= deadline) return s;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}

std::string guidToString(const GUID& g) {
    wchar_t buf[64]{};
    if (FAILED(StringFromGUID2(g, buf, 64))) return {};
    return narrow(buf);
}

GUID pickInterface(Wlan& wlan, const std::string& guidOpt) {
    std::vector<InterfaceInfo> all = wlan.interfaces();
    if (all.empty())
        throw std::runtime_error("no wireless interface found on this machine");

    if (!guidOpt.empty()) {
        for (const auto& i : all) {
            if (guidToString(i.guid) == guidOpt ||
                guidOpt == narrow(i.description))
                return i.guid;
        }
        throw std::runtime_error("no wireless interface matching: " + guidOpt);
    }

    for (const auto& i : all) {
        if (i.state != wlan_interface_state_not_ready) return i.guid;
    }
    // Nothing "ready" right now; still allow an explicit connect attempt.
    return all.front().guid;
}

}  // namespace edurm