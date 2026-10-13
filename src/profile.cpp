#include "profile.h"

#include "util.h"

#include <wincrypt.h>  // must follow windows.h
#include <bcrypt.h>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace edurm {
namespace {

// EAP method type numbers, from the EAPHost schema.
constexpr int kEapPeap = 25;      // Microsoft PEAP (outer)
constexpr int kEapMsChapV2 = 26;  // MS-CHAP v2 (inner)

constexpr const char* kProfileNs =
    "http://www.microsoft.com/networking/WLAN/profile/v1";
constexpr const char* kOneXNs = "http://www.microsoft.com/networking/OneX/v1";
constexpr const char* kEapHostNs =
    "http://www.microsoft.com/provisioning/EapHostConfig";
constexpr const char* kEapCommonNs =
    "http://www.microsoft.com/provisioning/EapCommon";
constexpr const char* kBaseEapNs =
    "http://www.microsoft.com/provisioning/BaseEapMethodConfigV1";
constexpr const char* kMsPeapNs =
    "http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1";
constexpr const char* kMsPeapV2Ns =
    "http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2";
constexpr const char* kMsChapV2Ns =
    "http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1";
constexpr const char* kEapUserCredNs =
    "http://www.microsoft.com/provisioning/EapHostUserCredentials";

std::string b64(const unsigned char* data, DWORD len) {
    static const char* t =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (DWORD i = 0; i < len; i += 3) {
        DWORD v = data[i] << 16;
        if (i + 1 < len) v |= data[i + 1] << 8;
        if (i + 2 < len) v |= data[i + 2];
        out.push_back(t[(v >> 18) & 63]);
        out.push_back(t[(v >> 12) & 63]);
        out.push_back(i + 1 < len ? t[(v >> 6) & 63] : '=');
        out.push_back(i + 2 < len ? t[v & 63] : '=');
    }
    return out;
}

// Decodes standard base64. Returns false on malformed input.
bool unb64(const std::string& in, std::string* out) {
    static signed char rev[256];
    static bool init = false;
    if (!init) {
        for (int i = 0; i < 256; ++i) rev[i] = -1;
        const char* t =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; ++i) rev[static_cast<unsigned char>(t[i])] =
            static_cast<signed char>(i);
        init = true;
    }
    std::string acc;
    int bits = 0;
    unsigned buf = 0;
    for (char c : in) {
        if (c == '=' ) break;
        signed char d = rev[static_cast<unsigned char>(c)];
        if (d < 0) {
            if (isspace(static_cast<unsigned char>(c))) continue;
            return false;
        }
        buf = (buf << 6) | static_cast<unsigned>(d);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            acc.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }
    }
    *out = acc;
    return true;
}

}  // namespace

const char* verifyLevelName(VerifyLevel lvl) {
    switch (lvl) {
        case VerifyLevel::Strict: return "strict";
        case VerifyLevel::Pinned: return "pinned";
        case VerifyLevel::LegacyTls: return "legacy-tls";
        case VerifyLevel::NoValidation: return "no-validation";
    }
    return "strict";
}

bool parseVerifyLevel(const std::string& s, VerifyLevel* out) {
    if (s == "1" || s == "strict") { *out = VerifyLevel::Strict; return true; }
    if (s == "2" || s == "pinned") { *out = VerifyLevel::Pinned; return true; }
    if (s == "3" || s == "legacy-tls") { *out = VerifyLevel::LegacyTls; return true; }
    if (s == "4" || s == "no-validation") { *out = VerifyLevel::NoValidation; return true; }
    return false;
}

std::string xmlEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:   out += c;        break;
        }
    }
    return out;
}

std::string buildProfileXml(const ProfileOptions& o) {
    if (o.ssid.empty()) throw std::runtime_error("SSID must not be empty");
    if (o.ssid.size() > 32) throw std::runtime_error("SSID must be <= 32 bytes");
    if (o.profileName.empty())
        throw std::runtime_error("profile name must not be empty");
    if (o.level == VerifyLevel::Pinned && o.trustedRootCaBase64.empty())
        throw std::runtime_error(
            "pinned level needs a CA certificate (--ca-cert or --pin-sha256)");

    std::string xml;
    xml.reserve(8192);

    xml += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
    xml += "<WLANProfile xmlns=\"" + std::string(kProfileNs) + "\">\r\n";
    xml += "\t<name>" + xmlEscape(o.profileName) + "</name>\r\n";

    // Windows emits both hex and name; hex is what matters for non-ASCII SSIDs.
    xml += "\t<SSIDConfig>\r\n\t\t<SSID>\r\n";
    xml += "\t\t\t<hex>" + toHex(o.ssid) + "</hex>\r\n";
    xml += "\t\t\t<name>" + xmlEscape(o.ssid) + "</name>\r\n";
    xml += "\t\t</SSID>\r\n\t</SSIDConfig>\r\n";

    xml += "\t<connectionType>ESS</connectionType>\r\n";
    xml += "\t<connectionMode>manual</connectionMode>\r\n";
    // <autoSwitch> is documented as valid here but makes WlanSetProfile reject
    // the whole profile (ERROR_INVALID_PROFILE, 1206). Verified on this build.

    xml += "\t<MSM>\r\n\t\t<security>\r\n\t\t\t<authEncryption>\r\n";
    // Enterprise token is "WPA2"/"WPA"; "WPA2Enterprise" is schema-invalid.
    xml += "\t\t\t\t<authentication>";
    xml += o.pskMode ? "WPA2PSK" : "WPA2";
    xml += "</authentication>\r\n";
    xml += "\t\t\t\t<encryption>";
    xml += o.useTkip ? "TKIP" : "AES";
    xml += "</encryption>\r\n";
    xml += "\t\t\t\t<useOneX>";
    xml += o.pskMode ? "false" : "true";
    xml += "</useOneX>\r\n";
    xml += "\t\t\t</authEncryption>\r\n";

    if (o.pskMode) {
        const std::string& key = o.psk.empty() ? o.password : o.psk;
        xml += "\t\t\t<sharedKey>\r\n";
        xml += "\t\t\t\t<keyType>passPhrase</keyType>\r\n";
        xml += "\t\t\t\t<protected>false</protected>\r\n";
        xml += "\t\t\t\t<keyMaterial>" + xmlEscape(key) + "</keyMaterial>\r\n";
        xml += "\t\t\t</sharedKey>\r\n";
        xml += "\t\t</security>\r\n\t</MSM>\r\n";
        xml += "</WLANProfile>\r\n";
        return xml;
    }

    // ---------------------------------------------------------------------
    // 802.1X. The 802.1X block lives in <OneX>, which must sit immediately
    // under <security> inside <MSM>. There is no top-level <8021X> element.
    // ---------------------------------------------------------------------
    xml += "\t\t\t<OneX xmlns=\"" + std::string(kOneXNs) + "\">\r\n";
    xml += "\t\t\t\t<EAPConfig>\r\n";
    xml += "\t\t\t\t\t<EapHostConfig xmlns=\"" + std::string(kEapHostNs) +
           "\" xmlns:eapCommon=\"" + std::string(kEapCommonNs) + "\">\r\n";

    // EapMethod follows the EapMethodType XSD sequence exactly:
    //   Type, VendorId?, VendorType?, AuthorId
    // Getting this order wrong yields EAP_E_EAPHOST_XML_MALFORMED (0x80420019).
    xml += "\t\t\t\t\t\t<EapMethod>\r\n";
    xml += "\t\t\t\t\t\t\t<eapCommon:Type>" + std::to_string(kEapPeap) +
           "</eapCommon:Type>\r\n";
    xml += "\t\t\t\t\t\t\t<eapCommon:VendorId>0</eapCommon:VendorId>\r\n";
    xml += "\t\t\t\t\t\t\t<eapCommon:VendorType>0</eapCommon:VendorType>\r\n";
    xml += "\t\t\t\t\t\t\t<eapCommon:AuthorId>0</eapCommon:AuthorId>\r\n";
    xml += "\t\t\t\t\t\t</EapMethod>\r\n";

    xml += "\t\t\t\t\t\t<Config>\r\n";
    xml += "\t\t\t\t\t\t\t<baseEap:Eap xmlns:baseEap=\"" + std::string(kBaseEapNs) +
           "\">\r\n";
    xml += "\t\t\t\t\t\t\t\t<baseEap:Type>" + std::to_string(kEapPeap) +
           "</baseEap:Type>\r\n";
    xml += "\t\t\t\t\t\t\t\t<msPeap:EapType xmlns:msPeap=\"" +
           std::string(kMsPeapNs) + "\">\r\n";

    if (!o.anonymousIdentity.empty())
        xml += "\t\t\t\t\t\t\t\t\t<msPeap:RoutingIdentity>" +
               xmlEscape(o.anonymousIdentity) + "</msPeap:RoutingIdentity>\r\n";
    else
        xml += "\t\t\t\t\t\t\t\t\t<msPeap:RoutingIdentity />\r\n";

    // Server validation.
    //
    // An EMPTY <TrustedRootCA /> means "validate against the machine's trusted
    // root store" - the Windows equivalent of "CA certificate: use system
    // certificates". Level 2 puts a specific CA's base64 DER there instead.
    const bool noValidation = (o.level == VerifyLevel::NoValidation);
    xml += "\t\t\t\t\t\t\t\t\t<msPeap:ServerValidation>\r\n";
    if (noValidation) {
        // LAST RESORT: accept anything.
        xml += "\t\t\t\t\t\t\t\t\t\t<msPeap:DisableUserPromptForServerValidation>true"
               "</msPeap:DisableUserPromptForServerValidation>\r\n";
    } else {
        xml += "\t\t\t\t\t\t\t\t\t\t<msPeap:DisableUserPromptForServerValidation>false"
               "</msPeap:DisableUserPromptForServerValidation>\r\n";
    }
    if (!o.trustedRootCaBase64.empty())
        xml += "\t\t\t\t\t\t\t\t\t\t<msPeap:TrustedRootCA>" + o.trustedRootCaBase64 +
               "</msPeap:TrustedRootCA>\r\n";
    else
        xml += "\t\t\t\t\t\t\t\t\t\t<msPeap:TrustedRootCA />\r\n";
    xml += "\t\t\t\t\t\t\t\t\t</msPeap:ServerValidation>\r\n";

    xml += "\t\t\t\t\t\t\t\t\t<msPeap:FastReconnect>true</msPeap:FastReconnect>\r\n";
    // 0 = an inner EAP method is required.
    xml += "\t\t\t\t\t\t\t\t\t<msPeap:InnerEapOptional>0</msPeap:InnerEapOptional>\r\n";

    // Inner EAP method: MSCHAPv2.
    xml += "\t\t\t\t\t\t\t\t\t<baseEap:Eap>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t\t<baseEap:Type>" + std::to_string(kEapMsChapV2) +
           "</baseEap:Type>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t\t<msChapV2:EapType xmlns:msChapV2=\"" +
           std::string(kMsChapV2Ns) + "\">\r\n";
    xml += "\t\t\t\t\t\t\t\t\t\t\t<msChapV2:UseWinLogonCredentials>false"
           "</msChapV2:UseWinLogonCredentials>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t\t</msChapV2:EapType>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t</baseEap:Eap>\r\n";

    xml += "\t\t\t\t\t\t\t\t\t<msPeap:EnableQuarantineChecks>false"
           "</msPeap:EnableQuarantineChecks>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t<msPeap:RequireCryptoBinding>false"
           "</msPeap:RequireCryptoBinding>\r\n";

    // PeapExtensions carries the V2 knobs: whether to validate at all, and the
    // server name that must be accepted. An empty <PeapExtensions /> is ignored.
    xml += "\t\t\t\t\t\t\t\t\t<msPeap:PeapExtensions>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t\t<msPeapV2:PerformServerValidation xmlns:msPeapV2=\"" +
           std::string(kMsPeapV2Ns) + "\">";
    xml += noValidation ? "false" : "true";
    xml += "</msPeapV2:PerformServerValidation>\r\n";
    if (!noValidation && !o.serverName.empty()) {
        xml += "\t\t\t\t\t\t\t\t\t\t<msPeapV2:AcceptServerName xmlns:msPeapV2=\"" +
               std::string(kMsPeapV2Ns) + "\">" + xmlEscape(o.serverName) +
               "</msPeapV2:AcceptServerName>\r\n";
    }
    xml += "\t\t\t\t\t\t\t\t\t</msPeap:PeapExtensions>\r\n";

    xml += "\t\t\t\t\t\t\t\t</msPeap:EapType>\r\n";
    xml += "\t\t\t\t\t\t\t</baseEap:Eap>\r\n";
    xml += "\t\t\t\t\t\t</Config>\r\n";
    xml += "\t\t\t\t\t</EapHostConfig>\r\n";
    xml += "\t\t\t\t</EAPConfig>\r\n";
    xml += "\t\t\t</OneX>\r\n";
    xml += "\t\t</security>\r\n";
    xml += "\t</MSM>\r\n";
    xml += "</WLANProfile>\r\n";
    return xml;
}

std::string buildEapUserCredentialsXml(const ProfileOptions& o) {
    std::string xml;
    xml.reserve(2048);
    xml += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
    xml += "<EapHostUserCredentials xmlns=\"" + std::string(kEapUserCredNs) +
           "\" xmlns:baseEap=\"" + std::string(kBaseEapNs) + "\" xmlns:msPeap=\"" +
           std::string(kMsPeapNs) + "\" xmlns:msChapV2=\"" +
           std::string(kMsChapV2Ns) + "\">\r\n";
    // Mirrors the profile: PEAP (25) on the outside, MSCHAPv2 (26) inside.
    xml += "\t<baseEap:Eap>\r\n";
    xml += "\t\t<baseEap:Type>" + std::to_string(kEapPeap) + "</baseEap:Type>\r\n";
    xml += "\t\t<msPeap:EapType>\r\n";
    if (!o.anonymousIdentity.empty())
        xml += "\t\t\t<msPeap:RoamingIdentity>" + xmlEscape(o.anonymousIdentity) +
               "</msPeap:RoamingIdentity>\r\n";
    else
        xml += "\t\t\t<msPeap:RoamingIdentity />\r\n";
    xml += "\t\t\t<baseEap:Eap>\r\n";
    xml += "\t\t\t\t<baseEap:Type>" + std::to_string(kEapMsChapV2) +
           "</baseEap:Type>\r\n";
    xml += "\t\t\t\t<msChapV2:EapType>\r\n";
    xml += "\t\t\t\t\t<msChapV2:Username>" + xmlEscape(o.username) +
           "</msChapV2:Username>\r\n";
    xml += "\t\t\t\t\t<msChapV2:Password>" + xmlEscape(o.password) +
           "</msChapV2:Password>\r\n";
    // LogonDomain carries the realm (uaf.edu.pk). It is what MSCHAPv2 uses as
    // the domain/realm field, and eduroam needs it set to the realm.
    if (!o.domain.empty())
        xml += "\t\t\t\t\t<msChapV2:LogonDomain>" + xmlEscape(o.domain) +
               "</msChapV2:LogonDomain>\r\n";
    xml += "\t\t\t\t</msChapV2:EapType>\r\n";
    xml += "\t\t\t</baseEap:Eap>\r\n";
    xml += "\t\t</msPeap:EapType>\r\n";
    xml += "\t</baseEap:Eap>\r\n";
    xml += "</EapHostUserCredentials>\r\n";
    return xml;
}

std::string loadCertificateBase64(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open certificate file: " + path);
    std::string raw((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
    if (raw.empty()) throw std::runtime_error("certificate file is empty: " + path);

    // Strip PEM armour if present.
    std::string body;
    if (raw.find("-----BEGIN") != std::string::npos) {
        size_t b = raw.find("-----BEGIN");
        b = raw.find('\n', b);
        size_t e = raw.find("-----END");
        if (b == std::string::npos || e == std::string::npos || e < b)
            throw std::runtime_error("malformed PEM certificate: " + path);
        body = raw.substr(b + 1, e - b - 1);
        // strip any remaining '-' characters
        std::string cleaned;
        for (char c : body)
            if (c != '-' && c != '\r' && c != '\n' && c != ' ') cleaned.push_back(c);
        body = cleaned;
    } else {
        body = raw;
    }

    // A raw certificate is base64 already; <TrustedRootCA> wants base64 DER.
    std::string trimmed;
    for (char c : body)
        if (!isspace(static_cast<unsigned char>(c))) trimmed.push_back(c);

    std::string der;
    if (!unb64(trimmed, &der) || der.empty())
        throw std::runtime_error("could not decode certificate: " + path);
    return trimmed;  // already base64
}

std::string findCertificateBySha256(const std::string& thumbprintHex) {
    std::string want;
    for (char c : thumbprintHex)
        if (!isspace(static_cast<unsigned char>(c)) && c != ':') want.push_back(c);

    DWORD bytes = static_cast<DWORD>(want.size() / 2);
    if (bytes == 0) throw std::runtime_error("empty --pin-sha256 value");

    std::vector<unsigned char> wantBytes(bytes);
    for (DWORD i = 0; i < bytes; ++i) {
        auto hexVal = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hexVal(want[i * 2]), lo = hexVal(want[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            throw std::runtime_error("bad hex in --pin-sha256");
        wantBytes[i] = static_cast<unsigned char>((hi << 4) | lo);
    }

    const wchar_t* kStores[] = {L"ROOT", L"CA", L"MY"};
    for (const wchar_t* storeName : kStores) {
        HCERTSTORE st = CertOpenSystemStoreW(0, storeName);
        if (!st) continue;
        PCCERT_CONTEXT ctx = nullptr;
        while ((ctx = CertEnumCertificatesInStore(st, ctx)) != nullptr) {
            DWORD len = 0;
            CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr,
                                  ctx->pbCertEncoded, ctx->cbCertEncoded, nullptr,
                                  &len);
            if (len) {
                std::vector<unsigned char> digest(len);
                if (CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr,
                                          ctx->pbCertEncoded, ctx->cbCertEncoded,
                                          digest.data(), &len) &&
                    len == bytes &&
                    memcmp(digest.data(), wantBytes.data(), bytes) == 0) {
                    std::string b = b64(ctx->pbCertEncoded, ctx->cbCertEncoded);
                    CertCloseStore(st, 0);
                    return b;
                }
            }
        }
        CertCloseStore(st, 0);
    }
    throw std::runtime_error(
        "no certificate in the trust stores matches that SHA-256 thumbprint; "
        "supply the CA file with --ca-cert instead");
}

std::string redactPassword(const std::string& xml) {
    static const char* kTags[] = {"msChapV2:Password", "passwordPlaintext",
                                  "passwordMSCHAPv2", "passwordNonEapUser",
                                  "keyMaterial"};
    std::string out = xml;
    for (const char* tag : kTags) {
        std::string close = std::string("</") + tag + ">";
        std::string open = std::string("<") + tag + ">";
        size_t pos = 0;
        while ((pos = out.find(open, pos)) != std::string::npos) {
            size_t end = out.find(close, pos + open.size());
            if (end == std::string::npos) break;
            out.replace(pos + open.size(), end - pos - open.size(), "***REDACTED***");
            pos += open.size();
        }
    }
    return out;
}

}  // namespace edurm