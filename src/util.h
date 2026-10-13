// Small helpers: string conversion, Win32 error formatting, SSID decoding.
#pragma once

#include <windows.h>
#include <wlanapi.h>

#include <string>

namespace edurm {

// UTF-8 <-> UTF-16 conversion. Windows APIs are UTF-16; everything the user
// types or reads on the console is UTF-8.
std::wstring widen(const std::string& utf8);
std::string  narrow(const std::wstring& utf16);

// Human-readable text for a Win32 error code (Wlan* functions return these).
std::string winError(DWORD code);

// Human-readable text for a WLAN_REASON_CODE_* value. Not every reason code is
// in the system message table, so fall back to a hex dump.
std::string reasonCodeText(DWORD code);

// Lowercase hex of a byte range ("eduroam" -> "656475726f616d").
std::string toHex(const std::string& bytes);

// Decode a DOT11_SSID into a printable string, falling back to hex for
// non-UTF-8 or non-printable payloads.
std::string ssidToString(const DOT11_SSID& ssid);

std::string cipherName(DOT11_CIPHER_ALGORITHM c);
std::string authName(DOT11_AUTH_ALGORITHM a);
std::string stateName(WLAN_INTERFACE_STATE s);
std::string bssTypeName(DOT11_BSS_TYPE t);

// Read a password from the console without echoing it. Returns empty on EOF.
std::string readSecret(const char* prompt);

// Throw std::runtime_error with a formatted Win32 error attached.
[[noreturn]] void throwWin32(const char* what, DWORD code);

}  // namespace edurm