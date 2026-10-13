// Shared connection logic used by both the CLI (main.cpp) and the GUI.
//
// Lives apart from the front-ends so there is exactly one implementation of
// "install the profile and connect", reporting progress through a callback
// rather than by printing. Callbacks fire on the calling thread, so a GUI must
// marshal them to its UI thread itself.
#pragma once

#include "profile.h"
#include "wlan.h"

#include <functional>
#include <string>
#include <vector>

namespace edurm {

enum class Stage {
    Installing,   // building and installing the WLAN profile
    Associating,  // profile installed, waiting for 802.1X to complete
    Succeeded,
    Failed,
};

using ProgressFn = std::function<void(Stage, const std::string&)>;

struct ConnectResult {
    bool ok{false};
    std::string message;
    // Which rung of the fallback ladder actually connected (0 if none).
    int levelUsed{0};
    std::string levelName;
    // One line per rung attempted, in order, for the test report / UI log.
    std::vector<std::string> attempts;
};

// Installs one profile at one verification level and waits for association.
// Never changes the verification level on its own.
ConnectResult installAndConnect(Wlan& wlan, const GUID& iface,
                                const ProfileOptions& opt, bool allUsers,
                                DWORD timeoutMs, const ProgressFn& onProgress);

// Tries the verification ladder in order and stops at the first success.
// `maxLevel` is the deepest rung the user has explicitly consented to; nothing
// below Strict is ever attempted unless the caller passes maxLevel >= 2.
ConnectResult connectWithLadder(Wlan& wlan, const GUID& iface,
                                const ProfileOptions& base, bool allUsers,
                                DWORD timeoutMs, int maxLevel,
                                const ProgressFn& onProgress);

// Failure guidance shown by both front-ends.
std::string troubleshootingHint();

bool isConnected(Wlan& wlan, const GUID& iface);

struct CaInfo {
    bool found{false};
    std::vector<std::string> subjects;
    std::string advice;
};

CaInfo checkEduroamRoots();

// Imports a PEM/DER certificate file into the machine's trusted ROOT store.
// Requires administrator rights. Returns the certificate subject on success.
std::string installCaIntoRootStore(const std::string& path, bool machineWide);

// TLS client legacy-enable (fallback Level 3). Records the previous registry
// values so restoreLegacyTls() can put them back.
bool enableLegacyTls(bool machineWide, std::string* note);
bool restoreLegacyTls(bool machineWide, std::string* note);

}  // namespace edurm