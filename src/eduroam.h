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
};

// Generates a profile from `opt`, installs it (per-user by default) and waits
// up to `timeoutMs` for the interface to reach `connected`.
ConnectResult installAndConnect(Wlan& wlan, const GUID& iface,
                                const ProfileOptions& opt, bool allUsers,
                                DWORD timeoutMs, const ProgressFn& onProgress);

// Failure guidance shown by both front-ends.
std::string troubleshootingHint();

// True if the interface is currently associated with a profile/SSID.
bool isConnected(Wlan& wlan, const GUID& iface);

struct CaInfo {
    bool found{false};                 // at least one eduroam-ish root present
    std::vector<std::string> subjects; // display names of the matching roots
    std::string advice;                // shown when nothing matched
};

// Looks for eduroam / RADIUS roots in the machine's trusted root store.
CaInfo checkEduroamRoots();

}  // namespace edurm