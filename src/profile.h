// Builds a WLAN profile XML for an eduroam-style WPA2-Enterprise deployment.
//
// This mirrors the settings on the printed eduroam card:
//     SSID          eduroam
//     EAP method    PEAP
//     Phase 2       MSCHAPv2
//     CA certificate  use system certificates
//     Domain        uaf.edu.pk
//     Identity      your-roll-number@student.example.edu
//
// The Windows mapping of each of those is documented per-field in
// buildProfileXml() below. The two easy-to-get-wrong ones are noted inline.
#pragma once

#include <string>

namespace edurm {

struct ProfileOptions {
    std::string ssid{"eduroam"};
    std::string profileName{"eduroam"};   // must match the wpa_supplicant-era
                                           // naming; any unique name works
    // A shipped tool should not hardcode one person's student ID, so the default
    // is a placeholder you replace with your own identity.
    std::string username{"your-roll-number@student.example.edu"};
    std::string password;
    std::string domain{"uaf.edu.pk"};      // NTLM/NAS realm

    // When true no <rootCert> element is emitted, which is exactly how you ask
    // Windows to validate the server against the machine's trusted root store.
    // That is what "CA certificate: use system certificates" means.
    bool useSystemCertificates{true};

    // Server name the RADIUS/AAA certificate is issued to. When empty we fall
    // back to validating by domain suffix only.
    std::string serverName;

    // Edur roam deployments commonly need this because the RADIUS server
    // presents a certificate for the realm, not for "eduroam".
    bool suffixMatchEnabled{true};

    // WPA2-CCMP is the norm; WPA2-TKIP is kept for ancient APs.
    bool useTkip{false};

    bool autoSwitch{true};
    // NOTE: the enterprise token is "WPA2" / "WPA", NOT "WPA2Enterprise".
    // The latter is rejected by WlanSetProfile with ERROR_INVALID_PROFILE
    // ("invalid according to the schema"), verified empirically. Whether the
    // profile is enterprise is decided by useOneX=true plus the <OneX> block.
    std::string authentication{"WPA2"};

    // WPA2-PSK (personal) networks. When pskMode is set the profile is built as
    // a preshared-key profile instead of an 802.1X one. eduroam itself never
    // uses this, but it lets the tool join any ordinary network it can see.
    bool pskMode{false};
    std::string psk;  // passphrase, not a 64-hex pre-shared key
};

std::string buildProfileXml(const ProfileOptions& opt);

// Returns the password field replaced by a placeholder. Used whenever we print
// or export a profile so secrets never reach a terminal, log, or bug report.
std::string redactPassword(const std::string& xml);

// Escapes the five XML metacharacters.
std::string xmlEscape(const std::string& s);

}  // namespace edurm