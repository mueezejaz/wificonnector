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

// A pre-allocated buffer for the WlanQueryInterface two-call pattern.
//
// Two allocations are in play and they have DIFFERENT owners:
//   * the block this class malloc's, owned by this class, freed with free()
//   * the block the WLAN service allocates on success, owned by the caller,
//     freed with WlanFreeMemory()
// The API overwrites the pointer it is given, so the caller's local copy is no
// longer the address of our block - hence this class keeps its own.
//
// Previously `PWLAN_... raw = malloc(...)` gave the API &raw, so on success the
// malloc'd block was orphaned (64 KB leaked per call) and on failure it was
// released with WlanFreeMemory() even though malloc() produced it.
struct QueryBuffer {
    PVOID p{nullptr};
    explicit QueryBuffer(std::size_t bytes) { p = malloc(bytes); }
    ~QueryBuffer() { if (p) free(p); }
    QueryBuffer(const QueryBuffer&) = delete;
    QueryBuffer& operator=(const QueryBuffer&) = delete;
    explicit operator bool() const { return p != nullptr; }
};

WLAN_INTERFACE_STATE currentState(Wlan& w, const GUID& iface) {
    QueryBuffer buf(sizeof(WLAN_CONNECTION_ATTRIBUTES));
    if (!buf) return wlan_interface_state_not_ready;

    PVOID data = buf.p;
    DWORD size = sizeof(WLAN_CONNECTION_ATTRIBUTES);
    WLAN_OPCODE_VALUE_TYPE type = wlan_opcode_value_type_query_only;

    DWORD rc = WlanQueryInterface(w.handle(), &iface,
                                  wlan_intf_opcode_current_connection, nullptr,
                                  &size, &data, &type);
    if (rc != ERROR_SUCCESS || !data) return wlan_interface_state_not_ready;

    // `data` is now the service's allocation; ~QueryBuffer still frees ours.
    Owned<WLAN_CONNECTION_ATTRIBUTES> attrs(
        static_cast<WLAN_CONNECTION_ATTRIBUTES*>(data));
    return attrs->isState;
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
                n.ssidBytes = ssidToBytes(src.dot11Ssid);
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

    // WlanGetAvailableNetworkList can return the same SSID more than once (one
    // entry per advertised BSSID set), which netsh hides but we did not - the
    // GUI showed duplicate rows. Collapse them, keeping the strongest entry and
    // summing the BSSID count so nothing is lost.
    std::vector<NetworkInfo> merged;
    merged.reserve(best.size());
    for (const NetworkInfo& n : best) {
        auto it = std::find_if(merged.begin(), merged.end(),
                               [&](const NetworkInfo& m) {
                                   return m.ssidBytes == n.ssidBytes && m.auth == n.auth;
                               });
        if (it == merged.end()) {
            merged.push_back(n);
        } else {
            if (n.signalQuality > it->signalQuality) it->signalQuality = n.signalQuality;
            it->bssidCount += n.bssidCount;
            if (it->profileName.empty()) it->profileName = n.profileName;
        }
    }
    std::sort(merged.begin(), merged.end(),
              [](const NetworkInfo& a, const NetworkInfo& b) {
                  return a.signalQuality > b.signalQuality;
              });
    return merged;
}

WLAN_CONNECTION_ATTRIBUTES Wlan::connection(const GUID& iface) {
    QueryBuffer buf(sizeof(WLAN_CONNECTION_ATTRIBUTES));
    if (!buf) throw std::runtime_error("out of memory");

    PVOID data = buf.p;
    DWORD size = sizeof(WLAN_CONNECTION_ATTRIBUTES);
    WLAN_OPCODE_VALUE_TYPE type = wlan_opcode_value_type_query_only;

    DWORD rc = WlanQueryInterface(h_, &iface, wlan_intf_opcode_current_connection,
                                  nullptr, &size, &data, &type);
    if (rc != ERROR_SUCCESS) throwWin32("WlanQueryInterface", rc);
    if (!data) throw std::runtime_error("WlanQueryInterface returned no data");

    // `data` is the service's allocation; ~QueryBuffer still frees ours.
    Owned<WLAN_CONNECTION_ATTRIBUTES> attrs(
        static_cast<WLAN_CONNECTION_ATTRIBUTES*>(data));
    WLAN_CONNECTION_ATTRIBUTES out = *attrs;
    return out;
}

void Wlan::setProfile(const GUID& iface, const std::wstring& xml, bool allUsers,
                      std::string* reasonOut, DWORD* reasonCodeOut) {
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
    if (reasonCodeOut) *reasonCodeOut = reasonCode;

    if (rc != ERROR_SUCCESS) {
        std::string msg = "WlanSetProfile: " + winError(rc);
        if (reasonCode && reasonCode != ERROR_SUCCESS)
            msg += "; reason: " + reasonCodeText(reasonCode);
        throw std::runtime_error(msg);
    }
}

void Wlan::setEapXmlUserData(const GUID& iface, const std::wstring& profileName,
                             const std::wstring& xml, bool allUsers) {
    // Flag must match how the profile was installed, otherwise Windows looks
    // for the credential blob in the wrong store.
    DWORD flags = allUsers ? 0u : static_cast<DWORD>(WLAN_PROFILE_USER);
    DWORD rc = WlanSetProfileEapXmlUserData(h_, &iface, profileName.c_str(), flags,
                                            xml.c_str(), nullptr);
    if (rc != ERROR_SUCCESS)
        throw std::runtime_error("WlanSetProfileEapXmlUserData: " + winError(rc));
}

bool Wlan::supportsEnterpriseAes(const GUID& iface) {
    try {
        for (const std::string& p : supportedAuthCipherPairs(iface)) {
            if (p.find("Enterprise") != std::string::npos &&
                p.find("CCMP (AES)") != std::string::npos)
                return true;
        }
    } catch (const std::exception&) {
        return false;
    }
    return false;
}

std::string Wlan::capabilitySummary(const GUID& iface) {
    std::string out;
    try {
        auto pairs = supportedAuthCipherPairs(iface);
        bool anyEnt = false, anyAesEnt = false;
        for (const std::string& p : pairs) {
            if (p.find("Enterprise") != std::string::npos) {
                anyEnt = true;
                if (p.find("CCMP (AES)") != std::string::npos) anyAesEnt = true;
            }
        }
        out += "auth/cipher pairs advertised: " + std::to_string(pairs.size()) + "\n";
        out += anyEnt ? "  802.1X (Enterprise): yes\n"
                      : "  802.1X (Enterprise): NO\n";
        out += anyAesEnt ? "  WPA2-Enterprise + AES: yes\n"
                         : "  WPA2-Enterprise + AES: NO\n";
    } catch (const std::exception& e) {
        out += std::string("  could not query capabilities: ") + e.what() + "\n";
    }
    return out;
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
QueryBuffer buf(kPairBufBytes);
    if (!buf) throw std::runtime_error("out of memory");
    PVOID data = buf.p;

    DWORD size = kPairBufBytes;
    WLAN_OPCODE_VALUE_TYPE type = wlan_opcode_value_type_query_only;
    DWORD rc = WlanQueryInterface(
        h_, &iface, wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs,
        nullptr, &size, &data, &type);
    if (rc != ERROR_SUCCESS)
        throwWin32("WlanQueryInterface(supported auth/cipher)", rc);
    if (!data)
        throw std::runtime_error(
            "WlanQueryInterface(supported auth/cipher) returned no data");

    // `data` is the service's allocation (freed below with WlanFreeMemory);
    // ~QueryBuffer frees our 64 KB block with free().
    Owned<WLAN_AUTH_CIPHER_PAIR_LIST> raw(
        static_cast<WLAN_AUTH_CIPHER_PAIR_LIST*>(data));

    std::vector<std::string> out;
    out.reserve(raw->dwNumberOfItems);
    for (DWORD i = 0; i < raw->dwNumberOfItems; ++i) {
        out.push_back(authName(raw->pAuthCipherPairList[i].AuthAlgoId) + " / " +
                      cipherName(raw->pAuthCipherPairList[i].CipherAlgoId));
    }
    return out;
}

WLAN_INTERFACE_STATE Wlan::waitForState(const GUID& iface,
                                       WLAN_INTERFACE_STATE want, DWORD timeoutMs) {
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    for (;;) {
        WLAN_INTERFACE_STATE s = currentState(*this, iface);
        if (s == want) return s;
        // No early exit on "disconnected" while waiting for "connected":
        // disconnected is the state a connect attempt STARTS in, so bailing out
        // on it reported failure for connections that were about to succeed.
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