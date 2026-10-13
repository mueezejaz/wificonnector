#include "diag.h"

#include "eduroam.h"
#include "util.h"

#include <windows.h>
#include <evntcons.h>  // EVT_QUERY, EVT_LOG_CHANNEL_NAME
#include <winevt.h>    // the SDK ships the event-log API here, not wevtapi.h

#include <sstream>

namespace edurm {
namespace {

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// The Windows SDK shipped here declares only EvtClose; the modern event-log API
// (EvtQuery/EvtNext/EvtFormatMessage) lives in wevtapi.dll at runtime but has no
// header or import lib available. Rather than take a hard dependency on an
// import library this project does not otherwise need, the few entry points are
// declared here and resolved at run time from the system DLL.
namespace evtlog {

using EvtHandle = void*;

struct Query {
    wchar_t* EventChannelPath;
    wchar_t* Query;
    BOOL ReverseDirection;
    DWORD TolerateQueryErrors;
};

// Flags from evntcons.h.
constexpr DWORD kEvtOpenChannelPath = 0x1;
constexpr DWORD kEvtQueryChannelPath = 0x1;
constexpr DWORD kEvtQueryReverseDirection = 0x2;
constexpr DWORD kEvtQueryTolerateQueryErrors = 0x80;
constexpr DWORD kEvtFormatMessageEvent = 0x1;
constexpr DWORD kEvtFormatMessageAllocateBuffer = 0x4;

using PfnOpenLog = EvtHandle(WINAPI*)(LPCWSTR, DWORD);
using PfnQuery = EvtHandle(WINAPI*)(EvtHandle, const Query*, DWORD);
using PfnNext = BOOL(WINAPI*)(EvtHandle, ULONG, EvtHandle*);
using PfnFormatMessage = DWORD(WINAPI*)(EvtHandle, DWORD, LPCWSTR, DWORD, LPWSTR,
                                        DWORD, LPWSTR*);
using PfnClose = BOOL(WINAPI*)(EvtHandle);

struct Api {
    PfnOpenLog openLog{nullptr};
    PfnQuery query{nullptr};
    PfnNext next{nullptr};
    PfnFormatMessage formatMessage{nullptr};
    PfnClose close{nullptr};
    bool ok() const {
        return openLog && query && next && formatMessage && close;
    }
};

const Api& api() {
    static Api a = [] {
        Api t;
        HMODULE m = LoadLibraryW(L"wevtapi.dll");
        if (!m) return t;
        t.openLog = reinterpret_cast<PfnOpenLog>(
            reinterpret_cast<void*>(GetProcAddress(m, "EvtOpenLog")));
        t.query = reinterpret_cast<PfnQuery>(
            reinterpret_cast<void*>(GetProcAddress(m, "EvtQuery")));
        t.next = reinterpret_cast<PfnNext>(
            reinterpret_cast<void*>(GetProcAddress(m, "EvtNext")));
        t.formatMessage = reinterpret_cast<PfnFormatMessage>(
            reinterpret_cast<void*>(GetProcAddress(m, "EvtFormatMessage")));
        t.close = reinterpret_cast<PfnClose>(
            reinterpret_cast<void*>(GetProcAddress(m, "EvtClose")));
        return t;
    }();
    return a;
}

}  // namespace evtlog

// Reads the first lines of the given event log channel.
std::vector<std::string> recentEvents(const wchar_t* channel, int maxCount,
                                      const wchar_t* ids) {
    std::vector<std::string> out;
    const evtlog::Api& api = evtlog::api();
    if (!api.ok()) return out;

    evtlog::EvtHandle log = api.openLog(channel, evtlog::kEvtOpenChannelPath);
    if (!log) return out;

    std::wstring q = ids && *ids ? (L"*[(System[(EventID)=" + std::wstring(ids) + L")])")
                                 : L"*[System[(Level=2 or Level=3)]]";

    evtlog::Query query{};
    query.EventChannelPath = const_cast<LPWSTR>(channel);
    query.Query = const_cast<LPWSTR>(q.c_str());
    query.ReverseDirection = TRUE;  // newest first
    query.TolerateQueryErrors = TRUE;

    evtlog::EvtHandle res =
        api.query(log, &query, evtlog::kEvtQueryChannelPath);
    if (!res) {
        api.close(log);
        return out;
    }

    evtlog::EvtHandle ev = nullptr;
    while (out.size() < static_cast<size_t>(maxCount) && api.next(res, 1, &ev)) {
        wchar_t* buf = nullptr;
        DWORD needed = api.formatMessage(ev, evtlog::kEvtFormatMessageEvent, nullptr,
                                         0, nullptr, 0, nullptr);
        if (needed == 0) {
            api.formatMessage(ev,
                              evtlog::kEvtFormatMessageEvent |
                                  evtlog::kEvtFormatMessageAllocateBuffer,
                              nullptr, 0, nullptr, 0, &buf);
        }
        if (buf) {
            std::string line = trim(narrow(buf));
            size_t nl = line.find('\n');
            if (nl != std::string::npos) line = line.substr(0, nl);
            if (line.size() > 300) line.resize(300);
            if (!line.empty()) out.push_back(line);
            LocalFree(buf);
        }
        if (ev) { api.close(ev); ev = nullptr; }
    }

    api.close(res);
    api.close(log);
    return out;
}

bool containsAny(const std::string& hay, std::initializer_list<const char*> needles) {
    std::string lower = hay;
    for (auto& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    for (const char* n : needles) {
        std::string nn = n;
        for (auto& c : nn) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        if (lower.find(nn) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

std::string explainEapError(DWORD code) {
    switch (code) {
        case 0x80420019:
            return "EAPHost rejected the profile's EAP configuration as malformed "
                   "(EAP_E_EAPHOST_XML_MALFORMED)";
        case 0x80420011:
            return "the chosen EAP method is not installed (EAP_E_EAPHOST_METHOD_NOT_INSTALLED)";
        case 0x80420013:
            return "the EAP QEC registry key is inaccessible - see "
                   "HKLM\\SOFTWARE\\Microsoft\\EAP\\QEC";
        case 0x80420014:
            return "the EAP identity could not be resolved";
        case 0x80420012:
            return "the third-party EAP method host was reset";
        case ERROR_INVALID_FUNCTION:
            return "Windows rejected the operation as an invalid function - "
                   "usually an EAP method this build will not configure silently";
        case ERROR_INVALID_PROFILE:
            return "Windows rejected the profile as invalid (ERROR_INVALID_PROFILE)";
        default:
            break;
    }

    // Well-known EAP/TLS values.
    struct Entry { DWORD code; const char* text; };
    static const Entry kMap[] = {
        {0x80420001, "generic EAP failure"},
        {0x80420002, "EAP method not installed"},
        {0x80420003, "EAP QEC inaccessible"},
        {0x80420004, "identity unknown"},
        {0x80420007, "EAP packet invalid"},
        {0x80420008, "remote EAP packet invalid"},
        {0x80420009, "EAP XML malformed"},
        {0x80420010, "the server certificate is not trusted"},
        {0x80420011, "EAP method not installed"},
        {0x80420012, "third-party EAP host reset"},
        {0x80420013, "EAP QEC inaccessible"},
        {0x80420014, "identity unknown"},
        {0x80420015, "EAP server certificate missing"},
        {0x80420016, "EAP user certificate missing"},
        {0x80420017, "EAP packet invalid"},
        {0x80420018, "remote EAP packet invalid"},
        {0x80420019, "EAP XML malformed"},
        {0x8042001A, "EAP configuration incomplete"},
        {0x8042001B, "the server certificate name does not match the expected name"},
        {0x8042001C, "the server certificate has expired"},
        {0x8042001D, "the server certificate is not yet valid"},
        {0x8042001E, "the server certificate was revoked"},
        {0x80420101, "the server certificate is not trusted"},
        {0x80420102, "TLS handshake failed - the server may require an older TLS version or cipher"},
        {0x80420103, "the TLS certificate chain could not be built"},
        {0x80420104, "the RADIUS server did not respond"},
        {0x80420105, "authentication failed - wrong username or password"},
        {0x80420106, "the account is not authorised for this network"},
        {0x80420107, "the account has expired"},
        {0x80420108, "the account is disabled"},
        {0x8042010A, "the EAP identity does not match the requested realm"},
    };
    for (const Entry& e : kMap)
        if (e.code == code) return e.text;

    return {};
}

std::string explainWlanReason(DWORD reasonCode) {
    struct Entry { DWORD code; const char* text; };
    // A representative subset of WLAN_REASON_CODE_* (see wlanapi.h).
    static const Entry kMap[] = {
        {1, "the AP is not responding to EAPOL-Start"},
        {2, "the AP did not respond to association"},
        {3, "802.1X authentication timed out"},
        {4, "the AP refused 802.1X authentication"},
        {5, "the AP started authentication but did not finish"},
        {6, "the credentials were rejected by the RADIUS server"},
        {7, "the RADIUS server did not respond"},
        {8, "the AP sent an invalid 802.1X packet"},
        {9, "the AP sent an invalid EAP packet"},
        {10, "the AP sent an invalid EAPOL packet"},
        {11, "the user credentials are missing or invalid"},
        {12, "the network does not accept machine credentials"},
        {13, "the user certificate could not be found"},
        {14, "the user certificate has expired"},
        {15, "the user certificate was revoked"},
        {16, "the access point could not be used - blocked or blocked by policy"},
        {17, "802.1X is not enabled on the adapter"},
        {18, "the adapter does not support WPA2-Enterprise"},
        {19, "the AP is out of range or the signal is too weak"},
        {20, "the profile could not be applied"},
        {21, "no network with this SSID was found"},
        {22, "the profile is corrupt"},
        {23, "the interface is not ready"},
        {24, "the adapter is disabled"},
        {25, "the network is not allowed by policy"},
        {26, "the profile is protected by policy"},
        {27, "the EAP method is not supported"},
        {28, "the certificate was rejected"},
    };
    for (const Entry& e : kMap)
        if (e.code == reasonCode) return e.text;

    // 0x0008xxxx are EAPHost codes surfaced through the reason field.
    if ((reasonCode & 0xFFFF0000u) == 0x00080000u)
        return "EAPHost reported: " + explainEapError(reasonCode);

    return {};
}

FailureDiagnosis diagnoseLastFailure() {
    FailureDiagnosis d;

    std::vector<std::string> wlan =
        recentEvents(L"Microsoft-Windows-WLAN-AutoConfig/Operational", 12,
                     L"12012 or 11004 or 11005 or 11010 or 8002 or 8003");
    std::vector<std::string> eaphost =
        recentEvents(L"Microsoft-Windows-EapHost/Operational", 8, nullptr);

    for (const std::string& e : wlan) d.evidence.push_back("WLAN: " + e);
    for (const std::string& e : eaphost) d.evidence.push_back("EapHost: " + e);

    // One combined haystack: classify from every line, not just the first.
    std::string hay;
    for (const std::string& e : d.evidence) hay += e + "\n";

    const char* kUntrusted = "authority that is not trusted";
    const char* kName = "does not match";
    const char* kExpired = "expired";
    const char* kTls = "tls";
    const char* kCred = "wrong password";
    const char* kNoCred = "credential";
    const char* kTimeout = "timed out";

    if (containsAny(hay, {kUntrusted, "untrusted", "trust chain"})) {
        d.likelyCause = "the RADIUS server's certificate does not chain to a root "
                        "Windows trusts";
        d.suggestedAction =
            "the eduroam CA bundle is not installed. Install it from "
            "https://www.eduroam.org/ or your IT desk, then retry.";
    } else if (containsAny(hay, {kName, "name mismatch"})) {
        d.likelyCause = "the certificate presented does not match the expected server name";
        d.suggestedAction = "set the server name to the realm (for example uaf.edu.pk) "
                            "with --server-name, then retry.";
    } else if (containsAny(hay, {kExpired, "not yet valid"})) {
        d.likelyCause = "the RADIUS certificate is expired or not yet valid";
        d.suggestedAction =
            "check the system clock first ('edurm diagnose'), then retry.";
    } else if (containsAny(hay, {kTls, "handshake", "protocol version"})) {
        d.likelyCause = "the TLS handshake was refused";
        d.suggestedAction = "the server may require an older TLS version. See Level 3 "
                            "in the README before using --allow-legacy-tls.";
    } else if (containsAny(hay, {kCred, kNoCred})) {
        d.likelyCause = "authentication was rejected - credentials or realm problem";
        d.suggestedAction =
            "check the username format (usually roll-number@realm) and the password.";
    } else if (containsAny(hay, {kTimeout})) {
        d.likelyCause = "the RADIUS server did not answer in time";
        d.suggestedAction = "check signal strength and whether the AP is still in range.";
    }

    if (d.evidence.empty()) {
        d.summary = "no recent WLAN-AutoConfig events were found";
        d.likelyCause = "unknown - the event log had nothing to report";
        d.suggestedAction =
            "run 'edurm diagnose' and check Event Viewer > Applications and "
            "Services Logs > Microsoft > Windows > WLAN-AutoConfig > Operational.";
    } else {
        std::ostringstream os;
        os << d.evidence.size() << " recent event(s) captured";
        d.summary = os.str();
    }
    return d;
}

std::string checkSystemClock() {
    // Certificate validation is time-sensitive; a skewed clock breaks the chain.
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buf[64];
    sprintf_s(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u UTC", st.wYear,
              st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    std::ostringstream os;
    os << "system time  : " << buf << "\n";
    os << "verdict      : if a certificate fails to validate and this time looks "
          "wrong, fix the clock before touching anything else";
    return os.str();
}

std::string describeRootTrust() {
    CaInfo ca = checkEduroamRoots();
    std::ostringstream os;
    if (ca.found) {
        os << "eduroam roots present: " << ca.subjects.size() << "\n";
        for (const std::string& s : ca.subjects) os << "  " << s << "\n";
    } else {
        os << "eduroam roots present: none found\n";
        os << "note: this is a keyword search of certificate subjects, so it can "
              "report 'none' even when a public-CA RADIUS certificate is already "
              "trusted. Only a failed connection proves the bundle is missing.\n";
    }
    return os.str();
}

}  // namespace edurm