// RAII wrapper over the Native Wifi API (wlanapi.dll).
//
// Scope note: on Windows the 802.1X/EAPOL exchange is performed by the
// WLAN AutoConfig service and the miniport driver, not by us. The deepest
// control a user-mode program can have is creating and activating the
// profile itself, which is exactly what this wrapper exposes.
#pragma once

#include <windows.h>
#include <wlanapi.h>

#include <string>
#include <vector>

namespace edurm {

struct InterfaceInfo {
    GUID guid{};
    // String form of `guid` ("{XXXX...}"), handy for display and persistence.
    std::string guidStr;
    std::wstring description;
    WLAN_INTERFACE_STATE state{wlan_interface_state_not_ready};
    bool operator==(const GUID& g) const { return IsEqualGUID(guid, g); }
};

struct NetworkInfo {
    // Display form: printable text, or "<hex:...>" for a non-printable SSID.
    std::string ssid;
    // The SSID bytes exactly as the radio reported them. A WLAN profile must be
    // built from THESE bytes: building it from `ssid` would encode the literal
    // text "<hex:...>" as the SSID and target a network that does not exist.
    std::string ssidBytes;
    std::wstring profileName;
    bool connectable{false};
    DWORD notConnectableReason{0};
    ULONG signalQuality{0};   // 0-100
    bool securityEnabled{false};
    DOT11_AUTH_ALGORITHM auth{DOT11_AUTH_ALGO_80211_OPEN};
    DOT11_CIPHER_ALGORITHM cipher{DOT11_CIPHER_ALGO_NONE};
    ULONG bssidCount{0};
    bool enterprise() const;
};

class Wlan {
public:
    // Opens a client handle. Throws std::runtime_error on failure.
    explicit Wlan(DWORD clientVersion = 2 /* WLAN_API_VERSION_2_0 */);
    ~Wlan();

    Wlan(const Wlan&) = delete;
    Wlan& operator=(const Wlan&) = delete;

    HANDLE handle() const { return h_; }

    std::vector<InterfaceInfo> interfaces();
    std::vector<std::wstring> profiles(const GUID& iface);
    std::vector<NetworkInfo> scan(const GUID& iface, int settleMs = 4000);
    WLAN_CONNECTION_ATTRIBUTES connection(const GUID& iface);

    // Installs or replaces a profile. Throws on failure and includes the
    // extended reason code (WLAN_REASON_CODE_*) from the OS.
    void setProfile(const GUID& iface, const std::wstring& xml,
                    bool allUsers, std::string* reasonOut,
                    DWORD* reasonCodeOut = nullptr);

    // Attaches PEAP user credentials to an already-installed profile. This is
    // how Windows stores per-user EAP data; credentials must NOT be embedded in
    // the profile XML itself. `xml` is an EapHostUserCredentials document.
    void setEapXmlUserData(const GUID& iface, const std::wstring& profileName,
                           const std::wstring& xml, bool allUsers);

    // True if the adapter advertises WPA2/WPA Enterprise (802.1X) with CCMP/AES.
    bool supportsEnterpriseAes(const GUID& iface);

    // Human-readable interface capability summary, for diagnostics.
    std::string capabilitySummary(const GUID& iface);
    void connect(const GUID& iface, const std::wstring& profileName);
    void disconnect(const GUID& iface);
    void forget(const GUID& iface, const std::wstring& profileName);

    // Reads a profile back as plain XML (password field included, so the
    // caller is responsible for redaction before printing).
    std::wstring exportProfile(const GUID& iface, const std::wstring& profileName);

    // Auth/cipher combinations the adapter itself claims to support. Useful for
    // confirming whether WPA2-Enterprise is even available on this NIC.
    std::vector<std::string> supportedAuthCipherPairs(const GUID& iface);

    // Blocks until the interface reaches `want` or the timeout expires.
    // Returns the state actually observed.
    WLAN_INTERFACE_STATE waitForState(const GUID& iface, WLAN_INTERFACE_STATE want,
                                      DWORD timeoutMs);

private:
    HANDLE h_{nullptr};
};

// Picks the interface to operate on. If `guidOpt` is non-empty it must match an
// installed interface; otherwise the first ready Wi-Fi interface is chosen.
// Throws if no suitable interface exists.
GUID pickInterface(Wlan& wlan, const std::string& guidOpt);
std::string guidToString(const GUID& g);

}  // namespace edurm