#include "util.h"

#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <vector>

namespace edurm {
namespace {

std::string narrowRaw(const wchar_t* p, int chars) {
    if (!p || chars <= 0) return {};
    int need = WideCharToMultiByte(CP_UTF8, 0, p, chars, nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out(static_cast<size_t>(need), '\0');
    WideCharToMultiByte(CP_UTF8, 0, p, chars, out.data(), need, nullptr, nullptr);
    return out;
}

}  // namespace

std::wstring widen(const std::string& utf8) {
    if (utf8.empty()) return {};
    int need = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (need <= 0) return {};
    // -1 includes the terminating NUL in `need`, so allocate `need` and drop the
    // NUL after conversion. Sizing the string to need-1 while asking the API to
    // write `need` chars wrote one wchar_t past the end of the buffer.
    std::wstring out(static_cast<size_t>(need), L'\0');
    int written = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, out.data(), need);
    if (written <= 0) return {};
    out.resize(static_cast<size_t>(written) - 1);  // drop the NUL
    return out;
}

std::string narrow(const std::wstring& utf16) {
    if (utf16.empty()) return {};
    return narrowRaw(utf16.c_str(), static_cast<int>(utf16.size()));
}

std::string winError(DWORD code) {
    LPWSTR buf = nullptr;
    DWORD n = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<LPWSTR>(&buf), 0, nullptr);

    std::string msg;
    if (n && buf) {
        msg = narrowRaw(buf, static_cast<int>(n));
        while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n' || msg.back() == ' '))
            msg.pop_back();
    } else {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "error 0x%08lX", code);
        msg = tmp;
    }
    if (buf) LocalFree(buf);

    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%lu", code);
    return msg + " (" + tmp + ")";
}

std::string reasonCodeText(DWORD code) {
    // Many WLAN_REASON_CODE_* values do live in the system message table, so try
    // that first and only fall back to the symbolic-ish hex form.
    std::string msg = winError(code);
    size_t paren = msg.find(" (");
    if (paren != std::string::npos) msg = msg.substr(0, paren);
    return msg;
}

std::string toHex(const std::string& bytes) {
    static const char* kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char c : bytes) {
        out.push_back(kDigits[c >> 4]);
        out.push_back(kDigits[c & 0x0F]);
    }
    return out;
}

std::string ssidToBytes(const DOT11_SSID& ssid) {
    if (ssid.uSSIDLength == 0) return {};
    const char* raw = reinterpret_cast<const char*>(ssid.ucSSID);
    return std::string(raw, std::min<size_t>(ssid.uSSIDLength, sizeof(ssid.ucSSID)));
}

std::string ssidToString(const DOT11_SSID& ssid) {
    if (ssid.uSSIDLength == 0) return {};

    const char* raw = reinterpret_cast<const char*>(ssid.ucSSID);
    size_t len = std::min<size_t>(ssid.uSSIDLength, sizeof(ssid.ucSSID));

    // Only treat it as text if every byte is a printable ASCII character.
    bool printable = true;
    for (size_t i = 0; i < len; ++i) {
        if (raw[i] < 0x20 || raw[i] > 0x7E) { printable = false; break; }
    }
    if (printable) return std::string(raw, len);

    char buf[80];
    snprintf(buf, sizeof(buf), "<hex:%s>", toHex(std::string(raw, len)).c_str());
    return buf;
}

std::string cipherName(DOT11_CIPHER_ALGORITHM c) {
    switch (c) {
        case DOT11_CIPHER_ALGO_NONE: return "None";
        case DOT11_CIPHER_ALGO_WEP40: return "WEP-40";
        case DOT11_CIPHER_ALGO_WEP104: return "WEP-104";
        case DOT11_CIPHER_ALGO_TKIP: return "TKIP";
        case DOT11_CIPHER_ALGO_CCMP: return "CCMP (AES)";
        case DOT11_CIPHER_ALGO_BIP: return "BIP-CMAC-128";
        case DOT11_CIPHER_ALGO_GCMP: return "GCMP-128";
        case DOT11_CIPHER_ALGO_GCMP_256: return "GCMP-256";
        case DOT11_CIPHER_ALGO_CCMP_256: return "CCMP-256";
        case DOT11_CIPHER_ALGO_BIP_GMAC_128: return "BIP-GMAC-128";
        case DOT11_CIPHER_ALGO_BIP_GMAC_256: return "BIP-GMAC-256";
        case DOT11_CIPHER_ALGO_BIP_CMAC_256: return "BIP-CMAC-256";
        case DOT11_CIPHER_ALGO_WEP: return "WEP (dynamic)";
        // NB: DOT11_CIPHER_ALGO_WPA_USE_GROUP and DOT11_CIPHER_ALGO_RSN_USE_GROUP
        // are both 0x100; a WPA2 network means RSN group keying.
        case DOT11_CIPHER_ALGO_RSN_USE_GROUP: return "RSN group key";
        default: return "Unknown";
    }
}

std::string authName(DOT11_AUTH_ALGORITHM a) {
    switch (a) {
        case DOT11_AUTH_ALGO_80211_OPEN: return "Open";
        case DOT11_AUTH_ALGO_80211_SHARED_KEY: return "802.11 Shared Key (WEP)";
        // eduroam shows up here: WPA2-Enterprise is RSNA with 802.1X keying.
        case DOT11_AUTH_ALGO_RSNA: return "WPA2-Enterprise (802.1X)";
        case DOT11_AUTH_ALGO_WPA: return "WPA-Enterprise (802.1X)";
        case DOT11_AUTH_ALGO_RSNA_PSK: return "WPA2-PSK";
        case DOT11_AUTH_ALGO_WPA_PSK: return "WPA-PSK";
        case DOT11_AUTH_ALGO_WPA_NONE: return "WPA-None (ad-hoc)";
        case DOT11_AUTH_ALGO_WPA3: return "WPA3-Enterprise 192-bit";
        case DOT11_AUTH_ALGO_WPA3_SAE: return "WPA3-SAE";
#if (NTDDI_VERSION >= NTDDI_WIN10_FE)
        case DOT11_AUTH_ALGO_WPA3_ENT: return "WPA3-Enterprise";
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
        case DOT11_AUTH_ALGO_OWE: return "OWE";
#endif
        default: return "Unknown";
    }
}

std::string stateName(WLAN_INTERFACE_STATE s) {
    switch (s) {
        case wlan_interface_state_not_ready: return "not ready";
        case wlan_interface_state_connected: return "connected";
        case wlan_interface_state_ad_hoc_network_formed: return "ad-hoc";
        case wlan_interface_state_disconnecting: return "disconnecting";
        case wlan_interface_state_disconnected: return "disconnected";
        case wlan_interface_state_discovering: return "discovering";
        case wlan_interface_state_associating: return "associating";
        case wlan_interface_state_authenticating: return "authenticating";
        default: return "unknown";
    }
}

std::string bssTypeName(DOT11_BSS_TYPE t) {
    switch (t) {
        case dot11_BSS_type_infrastructure: return "ESS";
        case dot11_BSS_type_independent: return "IBSS";
        case dot11_BSS_type_any: return "any";
        default: return "unknown";
    }
}

std::string readSecret(const char* prompt) {
    // _getwch() reads CONIN$ and BLOCKS when there is no console to read from.
    // With stdin redirected (a script, a scheduled task, a service) it never
    // returns at all, so `edurm connect` used to hang forever. Check that stdin
    // really is a console first, and refuse to prompt when it is not.
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (hIn == INVALID_HANDLE_VALUE || !GetConsoleMode(hIn, &mode)) {
        fputs("error: cannot prompt for a password - stdin is not a console.\n"
              "       use --password-stdin (echo secret | edurm connect "
              "--password-stdin)\n"
              "       or --password.\n",
              stderr);
        return {};
    }

    fputs(prompt, stdout);
    fflush(stdout);

    std::string out;
    for (;;) {
        wint_t c = _getwch();
        if (c == WEOF) break;  // console closed mid-read
        if (c == L'\r' || c == L'\n') break;
        if (c == L'\003') {  // Ctrl+C
            fputc('\n', stdout);
            return {};
        }
        if (c == L'\b' || c == 0x7F) {
            if (!out.empty()) {
                out.pop_back();
                fputs("\b \b", stdout);
                fflush(stdout);
            }
            continue;
        }
        if (c >= 0x20 && c < 0x7F) {
            out.push_back(static_cast<char>(c));
            fputc('*', stdout);
            fflush(stdout);
        }
    }
    fputc('\n', stdout);
    return out;
}

void throwWin32(const char* what, DWORD code) {
    throw std::runtime_error(std::string(what) + ": " + winError(code));
}

}  // namespace edurm