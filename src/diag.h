// Failure diagnostics: turns raw Win32 / EAP / TLS codes into plain language,
// and surfaces what the WLAN and EAPHost event logs actually said.
#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace edurm {

// Maps an EAPHost/Win32 code to a cause. Returns empty if unknown.
std::string explainEapError(DWORD code);

// Maps a WLAN AutoConfig reason code (WLAN_REASON_CODE_*) to plain language.
std::string explainWlanReason(DWORD reasonCode);

// Best-effort guess at why a connection attempt failed, from the recent
// WLAN-AutoConfig and EAPHost operational logs.
struct FailureDiagnosis {
    std::string summary;
    std::vector<std::string> evidence;  // verbatim log lines, trimmed
    std::string likelyCause;
    std::string suggestedAction;
};
FailureDiagnosis diagnoseLastFailure();

// Reads the system clock skew that matters for certificate validation.
std::string checkSystemClock();

// One line describing whether a matching eduroam CA is trusted.
std::string describeRootTrust();

}  // namespace edurm