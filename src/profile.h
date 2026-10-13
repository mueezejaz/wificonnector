// Builds WLAN profile XML for eduroam-style WPA2-Enterprise deployments,
// plus the separate EAP credential blob.
#pragma once

#include <string>
#include <vector>

namespace edurm {

// How strictly the RADIUS server's certificate is checked. Each step down is
// weaker; the caller must never move down silently.
enum class VerifyLevel {
    Strict = 1,        // system root store + required server name
    Pinned = 2,        // system store + a specific pinned CA in <TrustedRootCA>
    LegacyTls = 3,     // as Pinned, but assumes a legacy TLS stack (see README)
    NoValidation = 4,  // PerformServerValidation=false - LAST RESORT, warns hard
};

const char* verifyLevelName(VerifyLevel lvl);
bool parseVerifyLevel(const std::string& s, VerifyLevel* out);

struct ProfileOptions {
    std::string ssid{"eduroam"};
    std::string profileName{"eduroam"};

    // A shipped tool must not hardcode one person's student ID.
    std::string username;   // e.g. 2024ag0000@student.uaf.edu.pk
    std::string password;   // never logged, never written to the command line
    std::string domain{"uaf.edu.pk"};

    // PEAP "anonymous identity" (RoutingIdentity). eduroam leaves it empty.
    std::string anonymousIdentity;

    // Level 1: the server name the RADIUS certificate must match.
    std::string serverName{"uaf.edu.pk"};

    // Level 2: base64 DER of the CA to pin into <TrustedRootCA>.
    std::string trustedRootCaBase64;

    VerifyLevel level{VerifyLevel::Strict};

    bool useTkip{false};
    bool pskMode{false};
    std::string psk;
};

// The full WLAN profile. Credentials are deliberately NOT embedded: PEAP
// credentials go through WlanSetProfileEapXmlUserData instead, which is what
// Windows itself uses for per-user EAP data.
std::string buildProfileXml(const ProfileOptions& opt);

// The EapHostUserCredentials blob for WlanSetProfileEapXmlUserData.
// Outer method is PEAP (25) wrapping MSCHAPv2 (26).
std::string buildEapUserCredentialsXml(const ProfileOptions& opt);

// Loads a CA certificate from a .der/.pem/.cer file and returns base64 DER,
// which is the form <TrustedRootCA> expects.
std::string loadCertificateBase64(const std::string& path);

// Finds a certificate in the system trust stores by SHA-256 thumbprint and
// returns it as base64 DER. Used to turn --pin-sha256 into a pin.
std::string findCertificateBySha256(const std::string& thumbprintHex);

std::string redactPassword(const std::string& xml);
std::string xmlEscape(const std::string& s);

}  // namespace edurm