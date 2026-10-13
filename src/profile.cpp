#include "profile.h"

#include "util.h"

#include <stdexcept>

namespace edurm {
namespace {

// EAP method type numbers, from the EAPHost schema.
constexpr int kEapPeap = 25;       // Microsoft PEAP
constexpr int kEapMsChapV2 = 26;   // MS-CHAP v2 (the PEAP inner method)

constexpr const char* kProfileNs = "http://www.microsoft.com/networking/WLAN/profile/v1";
constexpr const char* kOneXNs = "http://www.microsoft.com/networking/OneX/v1";

}  // namespace

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

    std::string xml;
    xml.reserve(8192);

    xml += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
    xml += "<WLANProfile xmlns=\"" + std::string(kProfileNs) + "\">\r\n";
    xml += "\t<name>" + xmlEscape(o.profileName) + "</name>\r\n";

    // Windows emits both hex and name; hex is what actually matters for
    // non-ASCII SSIDs, and including both matches what Windows itself writes.
    xml += "\t<SSIDConfig>\r\n\t\t<SSID>\r\n";
    xml += "\t\t\t<hex>" + toHex(o.ssid) + "</hex>\r\n";
    xml += "\t\t\t<name>" + xmlEscape(o.ssid) + "</name>\r\n";
    xml += "\t\t</SSID>\r\n\t</SSIDConfig>\r\n";

    xml += "\t<connectionType>ESS</connectionType>\r\n";
    xml += "\t<connectionMode>manual</connectionMode>\r\n";
    // NOTE: <autoSwitch> is documented as a valid child here, but emitting it
    // makes WlanSetProfile reject the whole profile with ERROR_INVALID_PROFILE
    // (1206). Verified empirically against this Windows build: the identical
    // profile installs once the element is omitted. It is optional, so drop it.

    xml += "\t<MSM>\r\n\t\t<security>\r\n\t\t\t<authEncryption>\r\n";
    xml += "\t\t\t\t<authentication>";
    xml += o.pskMode ? "WPA2PSK" : xmlEscape(o.authentication);
    xml += "</authentication>\r\n";
    xml += "\t\t\t\t<encryption>";
    xml += o.useTkip ? "TKIP" : "AES";
    xml += "</encryption>\r\n";
    // useOneX MUST be true for enterprise, otherwise the profile silently
    // degrades to PSK and can never authenticate.
    xml += "\t\t\t\t<useOneX>";
    xml += o.pskMode ? "false" : "true";
    xml += "</useOneX>\r\n";
    xml += "\t\t\t</authEncryption>\r\n";

    if (o.pskMode) {
        // Personal network: a passphrase inside <security>. Fall back to
        // `password` so the CLI (which only fills that one) works too; an empty
        // <keyMaterial> makes Windows reject the profile outright.
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
    // Enterprise (802.1X).
    //
    // The 802.1X block lives in <OneX>, which must sit *immediately under*
    // <security> inside <MSM>. There is no top-level <8021X> element in the
    // WLAN profile schema, and no <credentials> element under <MSM> either;
    // emitting either makes WlanSetProfile fail with ERROR_INVALID_PROFILE
    // (1206, "the network connection profile is corrupted").
    //
    // Inside, EAPHost carries an EapMethod plus a <Config> blob describing
    // PEAP (type 25) with an MSCHAPv2 inner method (type 26).
    // ---------------------------------------------------------------------
    xml += "\t\t\t<OneX xmlns=\"" + std::string(kOneXNs) + "\">\r\n";
    xml += "\t\t\t\t<EAPConfig>\r\n";
    xml += "\t\t\t\t\t<EapHostConfig xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\""
           " xmlns:eapCommon=\"http://www.microsoft.com/provisioning/EapCommon\">\r\n";

    xml += "\t\t\t\t\t\t<EapMethod>\r\n";
    xml += "\t\t\t\t\t\t\t<eapCommon:Type>" + std::to_string(kEapPeap) +
           "</eapCommon:Type>\r\n";
    xml += "\t\t\t\t\t\t\t<eapCommon:AuthorId>0</eapCommon:AuthorId>\r\n";
    xml += "\t\t\t\t\t\t</EapMethod>\r\n";

    xml += "\t\t\t\t\t\t<Config"
           " xmlns:baseEap=\"http://www.microsoft.com/provisioning/BaseEapMethodConfigV1\""
           " xmlns:msPeap=\"http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1\""
           " xmlns:msChapV2=\"http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1\">\r\n";
    xml += "\t\t\t\t\t\t\t<baseEap:Eap>\r\n";
    xml += "\t\t\t\t\t\t\t\t<baseEap:Type>" + std::to_string(kEapPeap) +
           "</baseEap:Type>\r\n";
    xml += "\t\t\t\t\t\t\t\t<msPeap:EapType>\r\n";

    // Server validation.
    //
    // An EMPTY <TrustedRootCA /> is exactly how you ask EAPHost to validate
    // the server against the machine's trusted root store - the Windows
    // equivalent of "CA certificate: use system certificates". Naming a CA
    // here would pin to a specific root instead.
    //
    // DisableUserPromptForServerValidation must stay false, otherwise a
    // validation failure pops a dialog instead of failing the connection.
    xml += "\t\t\t\t\t\t\t\t\t<msPeap:ServerValidation>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t\t<msPeap:DisableUserPromptForServerValidation>false"
           "</msPeap:DisableUserPromptForServerValidation>\r\n";
    if (!o.useSystemCertificates) {
        // Pinning a specific root would list it here instead of leaving the
        // element empty.
        xml += "\t\t\t\t\t\t\t\t\t\t<msPeap:TrustedRootCA>" + xmlEscape(o.domain) +
               "</msPeap:TrustedRootCA>\r\n";
    } else {
        xml += "\t\t\t\t\t\t\t\t\t\t<msPeap:TrustedRootCA />\r\n";
    }
    xml += "\t\t\t\t\t\t\t\t\t</msPeap:ServerValidation>\r\n";

    xml += "\t\t\t\t\t\t\t\t\t<msPeap:FastReconnect>true</msPeap:FastReconnect>\r\n";
    // 0 = an inner EAP method is required.
    xml += "\t\t\t\t\t\t\t\t\t<msPeap:InnerEapOptional>0</msPeap:InnerEapOptional>\r\n";

    // Inner EAP method: MSCHAPv2.
    xml += "\t\t\t\t\t\t\t\t\t<baseEap:Eap>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t\t<baseEap:Type>" + std::to_string(kEapMsChapV2) +
           "</baseEap:Type>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t\t<msChapV2:EapType>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t\t\t<msChapV2:UseWinLogonCredentials>false"
           "</msChapV2:UseWinLogonCredentials>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t\t</msChapV2:EapType>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t</baseEap:Eap>\r\n";

    xml += "\t\t\t\t\t\t\t\t\t<msPeap:EnableQuarantineChecks>false"
           "</msPeap:EnableQuarantineChecks>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t<msPeap:RequireCryptoBinding>false"
           "</msPeap:RequireCryptoBinding>\r\n";
    xml += "\t\t\t\t\t\t\t\t\t<msPeap:PeapExtensions />\r\n";
    xml += "\t\t\t\t\t\t\t\t</msPeap:EapType>\r\n";
    xml += "\t\t\t\t\t\t\t</baseEap:Eap>\r\n";
    xml += "\t\t\t\t\t\t</Config>\r\n";
    xml += "\t\t\t\t\t</EapHostConfig>\r\n";

    // Credentials. Omitted entirely when no username was supplied, which makes
    // Windows prompt at connect time instead.
    if (!o.username.empty()) {
        xml += "\t\t\t\t\t<EapHostUserCredentials"
               " xmlns=\"http://www.microsoft.com/provisioning/EapHostUserCredentials\""
               " xmlns:baseEap=\"http://www.microsoft.com/provisioning/BaseEapMethodConfigV1\""
               " xmlns:msChapV2=\"http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1\">\r\n";
        xml += "\t\t\t\t\t\t<baseEap:Eap>\r\n";
        xml += "\t\t\t\t\t\t\t<baseEap:Type>" + std::to_string(kEapMsChapV2) +
               "</baseEap:Type>\r\n";
        xml += "\t\t\t\t\t\t\t<msChapV2:EapType>\r\n";
        xml += "\t\t\t\t\t\t\t\t<msChapV2:Username>" + xmlEscape(o.username) +
               "</msChapV2:Username>\r\n";
        xml += "\t\t\t\t\t\t\t\t<msChapV2:Password>" + xmlEscape(o.password) +
               "</msChapV2:Password>\r\n";
        xml += "\t\t\t\t\t\t\t</msChapV2:EapType>\r\n";
        xml += "\t\t\t\t\t\t</baseEap:Eap>\r\n";
        xml += "\t\t\t\t\t</EapHostUserCredentials>\r\n";
    }

    xml += "\t\t\t\t</EAPConfig>\r\n";
    xml += "\t\t\t</OneX>\r\n";
    xml += "\t\t</security>\r\n";
    xml += "\t</MSM>\r\n";
    xml += "</WLANProfile>\r\n";
    return xml;
}

std::string redactPassword(const std::string& xml) {
    static const char* kTags[] = {"msChapV2:Password",   "passwordPlaintext",
                                  "passwordMSCHAPv2",    "passwordNonEapUser",
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