// edurm GUI - a native Win32/GDI front-end for the eduroam helper.
//
// The rendering approach deliberately mirrors the FindFast project: plain
// Win32 + GDI with custom painting, rather than Direct2D/DirectWrite.
//
//   * DrawTextW with DT_END_ELLIPSIS gives text truncation for free, so there
//     is no need for DirectWrite trimming or text-measurement plumbing.
//   * Colours are COLORREFs (GetRValue/GetGValue/GetBValue are friendlier than
//     D2D1_COLOR_F, which is a struct of anonymous unions).
//   * Fonts scale with MulDiv(pt, dpi, 72) and an S() helper scales layout.
//   * The accent colour comes from the user's Windows accent, and dark mode
//     from AppsUseLightTheme, matching the platform.
//
// Only user32/gdi32/comctl32/dwmapi/uxtheme are needed; there is no d2d1 or
// dwrite dependency at all. The 802.1X work is not duplicated here: everything
// goes through edurm::installAndConnect, the same call the CLI uses.
//
// Threading: scan/connect run on a worker thread. The worker never touches UI
// state; it appends to mutex-guarded queues and PostMessage()s a wake-up so the
// UI thread can drain them.

#include "../eduroam.h"
#include "../profile.h"
#include "../util.h"
#include "../wlan.h"  // brings in windows.h + wlanapi.h

#include <commctrl.h>
#include <dwmapi.h>
#include <windowsx.h>

#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")

using namespace edurm;

namespace {

constexpr UINT WM_APP_LOG = WM_APP + 1;   // log lines queued
constexpr UINT WM_APP_DONE = WM_APP + 2;  // a worker finished

constexpr int kUser = 0, kDomain = 1, kPass = 2;

enum HitId {
    kHitScan = 1,
    kHitConnect,
    kHitDisconnect,
    kHitTheme,
    kHitAdapter,
    // Dropdown items are reported as kHitAdapter + 100 + index.
    kHitAdapterBase = 200
};

// ------------------------------------------------------------------ theme ---

// --- platform theming, read straight from the user's Windows settings --------

bool IsSystemDarkMode() {
    DWORD val = 1, sz = sizeof(val);
    RegGetValueW(HKEY_CURRENT_USER,
                 L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                 L"AppsUseLightTheme", RRF_RT_REG_DWORD, NULL, &val, &sz);
    return val == 0;
}

COLORREF SystemAccentColor() {
    DWORD accent = 0xFF0078D7, sz = sizeof(accent);
    RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\DWM",
                 L"AccentColor", RRF_RT_REG_DWORD, NULL, &accent, &sz);
    return RGB(accent & 0xFF, (accent >> 8) & 0xFF, (accent >> 16) & 0xFF);
}

COLORREF Lerp(COLORREF a, COLORREF b, float t) {
    int r = static_cast<int>(GetRValue(a) + t * (GetRValue(b) - GetRValue(a)));
    int g = static_cast<int>(GetGValue(a) + t * (GetGValue(b) - GetGValue(a)));
    int bl = static_cast<int>(GetBValue(a) + t * (GetBValue(b) - GetBValue(a)));
    return RGB(r, g, bl);
}

// --------------------------------------------------------------- ui model ---

struct Hit {
    RECT rect;
    int id;
};

struct FieldView {
    int index;
    const char* caption;
    bool secret;
};

class App {
public:
    int run(HINSTANCE inst);

private:
    // lifecycle
    static LRESULT CALLBACK wndProc(HWND h, UINT m, WPARAM w, LPARAM l);
    LRESULT handle(HWND h, UINT m, WPARAM w, LPARAM l);
    void applyThemeToWindow(HWND h);

    // metrics + layout
    int S(int v) const { return static_cast<int>(v * dpiScale_); }
    void layout();
    RECT rectOf(int id) const;
    std::vector<FieldView> fieldViews() const;

    // painting
    void paint(HDC hdc);
    void drawAdapterRow(HDC hdc);
    void drawAdapterDropdown(HDC hdc);
    void paintStatus(HDC hdc);
    void paintList(HDC hdc);
    void paintFields(HDC hdc);
    void paintActions(HDC hdc);
    void paintLog(HDC hdc);
    void drawTitle(HDC hdc);
    void drawButton(HDC hdc, const std::wstring& caption, const RECT& r, int id,
                    bool primary, bool enabled);
    void drawField(HDC hdc, const FieldView& fv, const RECT& r);
    void drawRow(HDC hdc, size_t index, const RECT& r);
    void drawSignalBars(HDC hdc, const RECT& r, ULONG quality);

    // input
    int hitTest(int x, int y) const;
    void onMouseMove(HWND h, int x, int y);
    void onMouseDown(HWND h, int x, int y);
    void onChar(WCHAR c);
    void onKeyDown(HWND h, WPARAM key);
    void clampScroll();

    // work
    void refreshStatus();
    void refreshInterfaces();
    GUID currentIface() const;
    void loadIfacePref();
    void saveIfacePref() const;
    void startScan();
    void startConnect();
    void startDisconnect();
    void pushLog(std::string line);
    void drainQueue();
    void selectNetwork(int index);
    ProfileOptions currentOptions() const;

    // palette + gdi objects
    void buildPalette();
    void createGdiObjects();
    void destroyGdiObjects();

    // window
    HWND hwnd_{nullptr};
    HINSTANCE inst_{nullptr};
    float dpi_{96.0f};
    float dpiScale_{1.0f};
    int rowH_{46};

    // palette
    COLORREF cBg_{}, cSurface_{}, cSurface2_{}, cBorder_{}, cAccent_{}, cText_{},
        cSub_{}, cSel_{}, cSelText_{}, cOk_{}, cWarn_{}, cErr_{}, cLogBg_{};
    bool dark_{true};

    // gdi objects
    HBRUSH brBg_{nullptr}, brSurface_{nullptr}, brSurface2_{nullptr}, brBorder_{nullptr},
        brAccent_{nullptr}, brSel_{nullptr}, brLogBg_{nullptr};
    HFONT fTitle_{nullptr}, fHead_{nullptr}, fBody_{nullptr}, fSmall_{nullptr},
        fLabel_{nullptr}, fMono_{nullptr};

    // model
    ProfileOptions opt_{};
    std::string fields_[3];
    std::vector<NetworkInfo> nets_;
    // Adapter selection. A machine often has more than one Wi-Fi NIC (internal
    // plus a USB dongle), so scan/connect must target an explicit GUID rather
    // than whichever adapter happens to be enumerated first.
    std::vector<InterfaceInfo> ifaces_;
    int selIface_{0};
    bool dropOpen_{false};
    std::wstring statusHead_{L"Not connected"};
    std::wstring statusDetail_{L"Select a network and press Connect."};
    CaInfo ca_;
    std::deque<std::string> log_;
    std::unique_ptr<Wlan> uiWlan_;
    std::thread worker_;
    std::mutex mtx_;
    std::deque<std::string> qLog_;
    std::vector<NetworkInfo> qNets_;
    bool qHaveNets_{false};
    // A job finishing must always clear busy_. Scan, connect and disconnect all
    // report through this, otherwise busy_ would stay stuck on true and freeze
    // the text fields plus the Connect/Disconnect buttons.
    bool qJobDone_{false};
    bool qWasConnect_{false};
    bool qResultOk_{false};
    bool busy_{false};
    bool caretOn_{true};
    bool connected_{false};
    int focus_{kUser};
    int sel_{-1};
    int hover_{0};
    int firstRow_{0};
    bool showPassword_{false};

    // layout
    RECT rTitle_{}, rAdapter_{}, rStatus_{}, rListHead_{}, rListBox_{}, rFields_{},
        rActions_{}, rLog_{}, rDrop_{}, fieldRect_[3]{};
    std::vector<Hit> hits_;
    // Row rects for the open adapter dropdown, indexed like ifaces_.
    std::vector<RECT> adapterRows_;
};

// ============================================================== palette =====

void App::buildPalette() {
    COLORREF accent = SystemAccentColor();

    if (dark_) {
        cBg_ = RGB(18, 18, 24);
        cSurface_ = RGB(28, 28, 38);
        cSurface2_ = RGB(38, 38, 52);
        cBorder_ = RGB(58, 58, 78);
        cAccent_ = accent;
        cText_ = RGB(232, 232, 242);
        cSub_ = RGB(132, 132, 152);
        cSel_ = Lerp(cSurface_, accent, 0.22f);
        cSelText_ = RGB(255, 255, 255);
        cOk_ = RGB(52, 211, 153);
        cWarn_ = RGB(251, 191, 36);
        cErr_ = RGB(248, 113, 113);
        cLogBg_ = RGB(14, 14, 19);
    } else {
        cBg_ = RGB(242, 244, 248);
        cSurface_ = RGB(255, 255, 255);
        cSurface2_ = RGB(233, 236, 242);
        cBorder_ = RGB(205, 210, 220);
        cAccent_ = accent;
        cText_ = RGB(22, 22, 32);
        cSub_ = RGB(105, 112, 126);
        cSel_ = Lerp(cSurface_, accent, 0.14f);
        cSelText_ = RGB(20, 20, 30);
        cOk_ = RGB(5, 150, 90);
        cWarn_ = RGB(170, 120, 10);
        cErr_ = RGB(200, 50, 50);
        cLogBg_ = RGB(248, 249, 252);
    }
}

void App::destroyGdiObjects() {
    HBRUSH* brushes[] = {&brBg_,     &brSurface_, &brSurface2_, &brBorder_,
                         &brAccent_, &brSel_,     &brLogBg_};
    for (HBRUSH* b : brushes) {
        if (*b) { DeleteObject(*b); *b = nullptr; }
    }
    HFONT* fonts[] = {&fTitle_, &fHead_, &fBody_, &fSmall_, &fLabel_, &fMono_};
    for (HFONT* f : fonts) {
        if (*f) { DeleteObject(*f); *f = nullptr; }
    }
}

void App::createGdiObjects() {
    destroyGdiObjects();

    brBg_ = CreateSolidBrush(cBg_);
    brSurface_ = CreateSolidBrush(cSurface_);
    brSurface2_ = CreateSolidBrush(cSurface2_);
    brBorder_ = CreateSolidBrush(cBorder_);
    brAccent_ = CreateSolidBrush(cAccent_);
    brSel_ = CreateSolidBrush(cSel_);
    brLogBg_ = CreateSolidBrush(cLogBg_);

    // Negative height selects a character (em) height, which is what UIs want.
    auto makeFont = [this](int pt, int weight) {
        return CreateFontW(-MulDiv(pt, static_cast<int>(dpi_), 72), 0, 0, 0, weight, 0,
                           0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                           CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH,
                           L"Segoe UI");
    };
    fTitle_ = makeFont(20, FW_BOLD);
    fHead_ = makeFont(15, FW_SEMIBOLD);
    fBody_ = makeFont(11, FW_NORMAL);
    fSmall_ = makeFont(9, FW_NORMAL);
    fLabel_ = makeFont(9, FW_SEMIBOLD);

    fMono_ = CreateFontW(-MulDiv(9, static_cast<int>(dpi_), 72), 0, 0, 0, FW_NORMAL, 0, 0,
                         0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                         CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
}

void App::applyThemeToWindow(HWND h) {
    BOOL dark = dark_ ? TRUE : FALSE;
    // 20 on 20H1+, 19 on 1809-1903.
    if (FAILED(DwmSetWindowAttribute(h, 20, &dark, sizeof(dark))))
        DwmSetWindowAttribute(h, 19, &dark, sizeof(dark));

    buildPalette();
    createGdiObjects();
}

// ============================================================ draw helpers ==

namespace {

void FillRoundRect(HDC hdc, const RECT& r, int radius, COLORREF fill,
                   COLORREF border) {
    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HBRUSH br = CreateSolidBrush(fill);
    HPEN oldPen = static_cast<HPEN>(SelectObject(hdc, pen));
    HBRUSH oldBr = static_cast<HBRUSH>(SelectObject(hdc, br));
    RoundRect(hdc, r.left, r.top, r.right, r.bottom, radius * 2, radius * 2);
    SelectObject(hdc, oldPen);
    SelectObject(hdc, oldBr);
    DeleteObject(pen);
    DeleteObject(br);
}

void TextAt(HDC hdc, const std::wstring& s, RECT r, UINT flags, COLORREF color) {
    if (s.empty()) return;
    SetTextColor(hdc, color);
    DrawTextW(hdc, s.c_str(), -1, &r, flags);
}

}  // namespace

void App::drawSignalBars(HDC hdc, const RECT& r, ULONG quality) {
    const int bars = 4;
    int lit = static_cast<int>(quality / 26);
    if (lit > bars) lit = bars;

    const int bw = S(3), gp = S(2);
    const int total = bars * bw + (bars - 1) * gp;
    int x = r.right - total;
    const int bottom = r.bottom;

    for (int i = 0; i < bars; ++i) {
        int h = S(5) + i * S(3);
        RECT b = {x, bottom - h, x + bw, bottom};
        HBRUSH br = CreateSolidBrush(i < lit ? cAccent_ : cBorder_);
        FillRect(hdc, &b, br);
        DeleteObject(br);
        x += bw + gp;
    }
}

void App::drawButton(HDC hdc, const std::wstring& caption, const RECT& r, int id,
                     bool primary, bool enabled) {
    const bool hovered = enabled && hover_ == id;

    COLORREF bg, fg;
    if (!enabled) {
        bg = cSurface2_;
        fg = cSub_;
    } else if (primary) {
        bg = hovered ? Lerp(cAccent_, RGB(255, 255, 255), 0.18f) : cAccent_;
        fg = RGB(255, 255, 255);
    } else {
        bg = hovered ? cSurface2_ : cSurface_;
        fg = cText_;
    }

    FillRoundRect(hdc, r, S(8), bg, primary ? bg : cBorder_);

    SelectObject(hdc, fBody_);
    TextAt(hdc, caption, r, DT_CENTER | DT_VCENTER | DT_SINGLELINE, fg);
}

void App::drawField(HDC hdc, const FieldView& fv, const RECT& r) {
    const bool focused = focus_ == fv.index;

    // Caption sits to the left of the box. It is left-aligned from a fixed origin
    // on purpose: with DT_RIGHT, text even slightly wider than the box gets its
    // LEADING glyph clipped by GDI (and DT_END_ELLIPSIS does not prevent it),
    // which turned "USERNAME" into "JSERNAME". Left-aligning means the first
    // glyph can only ever be lost if the whole box is too small.
    RECT cap = {S(16), r.top, r.left - S(12), r.bottom};
    SelectObject(hdc, fLabel_);
    TextAt(hdc, widen(fv.caption), cap,
           DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
           focused ? cAccent_ : cSub_);

    FillRoundRect(hdc, r, S(7), dark_ ? RGB(16, 16, 22) : cSurface_,
                  focused ? cAccent_ : cBorder_);

    std::string shown = fields_[fv.index];
    if (fv.secret && !showPassword_) shown.assign(shown.size(), '*');
    std::wstring w = widen(shown);

    SelectObject(hdc, fBody_);
    RECT inner = {r.left + S(11), r.top, r.right - S(11), r.bottom};
    TextAt(hdc, w, inner, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS, cText_);

    if (!focused || !caretOn_ || w.empty()) return;

    // GetTextExtentPoint32 gives the caret position without any extra layout.
    SIZE sz{};
    GetTextExtentPoint32W(hdc, w.c_str(), static_cast<int>(w.size()), &sz);
    int cx = r.left + S(11) + sz.cx;
    int mid = (r.top + r.bottom) / 2;
    RECT caret = {cx, mid - S(6), cx + S(2), mid + S(6)};
    HBRUSH br = CreateSolidBrush(cText_);
    FillRect(hdc, &caret, br);
    DeleteObject(br);
}

void App::drawRow(HDC hdc, size_t index, const RECT& r) {
    const NetworkInfo& n = nets_[index];
    const int idx = static_cast<int>(index);
    const bool selected = idx == sel_;

    RECT row = {r.left + S(3), r.top + S(2), r.right - S(7), r.bottom - S(2)};
    if (selected) {
        FillRoundRect(hdc, row, S(7), cSel_, cSel_);
    } else if (hover_ == -1000 - idx) {
        FillRoundRect(hdc, row, S(7), cSurface2_, cSurface2_);
    }

    const int left = row.left + S(13);
    const int right = row.right - S(44);

    std::wstring name = widen(n.ssid);

    RECT nameR = {left, row.top + S(7), right, row.top + S(25)};
    SelectObject(hdc, fBody_);
    TextAt(hdc, name, nameR, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
           selected ? cSelText_ : cText_);

    // authName() already says "802.1X" for enterprise networks, so no extra tag.
    std::wstring sub = widen(authName(n.auth));
    if (!n.profileName.empty()) sub += L"   \xB7   saved";
    if (!n.connectable) sub += L"   \xB7   " + widen(winError(n.notConnectableReason));

    RECT subR = {left, row.top + S(24), right, row.bottom - S(4)};
    SelectObject(hdc, fSmall_);
    TextAt(hdc, sub, subR, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS, cSub_);

    RECT bars = {row.right - S(36), row.top + S(10), row.right - S(14),
                 row.bottom - S(12)};
    drawSignalBars(hdc, bars, n.signalQuality);
}

// ================================================================== layout ===

void App::layout() {
    RECT rc{};
    GetClientRect(hwnd_, &rc);
    const int W = rc.right;
    const int pad = S(16);
    const int gap = S(11);
    int y = pad;

    rTitle_ = {pad, y, W - pad, y + S(32)};
    y = rTitle_.bottom + gap;

    // Adapter selector row.
    rAdapter_ = {pad, y, W - pad, y + S(34)};
    y = rAdapter_.bottom + gap;

    rStatus_ = {pad, y, W - pad, y + S(82)};
    y = rStatus_.bottom + gap;

    rListHead_ = {pad, y, W - pad, y + S(26)};
    y = rListHead_.bottom;

    const std::vector<FieldView> fvs = fieldViews();
    const int fieldsH = static_cast<int>(fvs.size()) * S(40) + S(4);
    const int actionsH = S(40);
    const int logH = S(96);

    rLog_ = {pad, rc.bottom - pad - logH, W - pad, rc.bottom - pad};
    rActions_ = {pad, rLog_.top - gap - actionsH, W - pad, rLog_.top - gap};
    rFields_ = {pad, rActions_.top - gap - fieldsH, W - pad, rActions_.top - gap};
    rListBox_ = {pad, y, W - pad, rFields_.top - gap};

    for (size_t i = 0; i < fvs.size() && i < 3; ++i) {
        int top = rFields_.top + static_cast<int>(i) * S(40);
        fieldRect_[fvs[i].index] = {pad + S(96), top, W - pad, top + S(30)};
    }

    hits_.clear();
    const int scanW = S(96);
    hits_.push_back({{W - pad - scanW, rListHead_.top, W - pad, rListHead_.bottom},
                     kHitScan});

    const int thW = S(66);
    hits_.push_back(
        {{W - pad - thW, rTitle_.top, W - pad, rTitle_.top + S(26)}, kHitTheme});

    // Adapter combo: caption on the left, dropdown button on the right.
    // Clamp so it can never run off a narrow window.
    int selW = S(300);
    const int maxSelW = rAdapter_.right - (rAdapter_.left + S(80));
    if (selW > maxSelW) selW = maxSelW;
    if (selW < S(80)) selW = S(80);
    hits_.push_back({{rAdapter_.right - selW, rAdapter_.top, rAdapter_.right,
                      rAdapter_.bottom},
                     kHitAdapter});

    // Expanded dropdown overlay, sized to the number of adapters.
    const int rowH = S(40);
    int dropH = static_cast<int>(ifaces_.size()) * rowH + S(8);
    rDrop_ = {rAdapter_.right - selW, rAdapter_.bottom + S(2),
              rAdapter_.right, rAdapter_.bottom + S(2) + dropH};

    const int bw = S(140), bh = S(38);
    const int by = rActions_.top + (rActions_.bottom - rActions_.top - bh) / 2;
    hits_.push_back({{pad, by, pad + bw, by + bh}, kHitConnect});
    hits_.push_back(
        {{pad + bw + gap, by, pad + bw + gap + S(120), by + bh}, kHitDisconnect});
}

RECT App::rectOf(int id) const {
    for (const Hit& h : hits_)
        if (h.id == id) return h.rect;
    return RECT{0, 0, 0, 0};
}

std::vector<FieldView> App::fieldViews() const {
    if (opt_.pskMode) return {{kPass, "PASSPHRASE", true}};
    return {{kUser, "USERNAME", false},
            {kDomain, "REALM", false},
            {kPass, "PASSWORD", true}};
}

// =================================================================== paint ===

void App::drawTitle(HDC hdc) {
    SelectObject(hdc, fTitle_);
    TextAt(hdc, L"edurm", rTitle_, DT_LEFT | DT_VCENTER | DT_SINGLELINE, cText_);

    RECT th = rectOf(kHitTheme);
    const bool hovered = hover_ == kHitTheme;
    FillRoundRect(hdc, th, S(7), hovered ? cSurface2_ : cSurface_, cBorder_);
    SelectObject(hdc, fSmall_);
    TextAt(hdc, dark_ ? L"Light" : L"Dark", th, DT_CENTER | DT_VCENTER | DT_SINGLELINE,
           cSub_);
}

void App::paintStatus(HDC hdc) {
    FillRoundRect(hdc, rStatus_, S(10), cSurface_, cBorder_);

    const int x = rStatus_.left + S(17);
    const int midTop = rStatus_.top + S(24);

    HBRUSH dot = CreateSolidBrush(connected_ ? cOk_ : (busy_ ? cWarn_ : cSub_));
    RECT d = {x, midTop - S(5), x + S(10), midTop + S(5)};
    FillRect(hdc, &d, dot);
    DeleteObject(dot);

    RECT headR = {x + S(20), rStatus_.top + S(14), rStatus_.right - S(16),
                  rStatus_.top + S(37)};
    SelectObject(hdc, fHead_);
    TextAt(hdc, statusHead_, headR, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
           cText_);

    RECT detR = {x + S(20), rStatus_.top + S(36), rStatus_.right - S(16),
                 rStatus_.top + S(56)};
    SelectObject(hdc, fSmall_);
    TextAt(hdc, statusDetail_, detR, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
           cSub_);

    RECT caR = {x, rStatus_.bottom - S(26), rStatus_.right - S(16), rStatus_.bottom - S(7)};
    TextAt(hdc, ca_.found ? L"eduroam CA bundle installed"
                          : L"eduroam CA bundle NOT installed",
           caR, DT_LEFT | DT_VCENTER | DT_SINGLELINE, ca_.found ? cOk_ : cWarn_);
}

void App::paintList(HDC hdc) {
    RECT lab = {rListHead_.left, rListHead_.top, rListHead_.left + S(120),
                rListHead_.bottom};
    SelectObject(hdc, fLabel_);
    TextAt(hdc, L"NETWORKS", lab, DT_LEFT | DT_VCENTER | DT_SINGLELINE, cSub_);

    drawButton(hdc, busy_ ? L"Scanning..." : L"Scan", rectOf(kHitScan), kHitScan, false,
               !busy_);

    FillRoundRect(hdc, rListBox_, S(10), cSurface_, cBorder_);

    const int inset = S(3);
    const int listH = rListBox_.bottom - rListBox_.top - inset * 2;
    int visible = listH / rowH_;
    if (visible < 1) visible = 1;
    clampScroll();

    if (nets_.empty()) {
        RECT empty = rListBox_;
        SelectObject(hdc, fBody_);
        TextAt(hdc, L"No networks yet \x2014 press Scan", empty,
               DT_CENTER | DT_VCENTER | DT_SINGLELINE, cSub_);
        return;
    }

    for (int i = 0; i < visible; ++i) {
        long idx = static_cast<long>(firstRow_) + i;
        if (idx >= static_cast<long>(nets_.size())) break;
        RECT row = {rListBox_.left, rListBox_.top + inset + i * rowH_, rListBox_.right,
                    rListBox_.top + inset + (i + 1) * rowH_};
        drawRow(hdc, static_cast<size_t>(idx), row);
    }

    // Scroll thumb, only when there is something to scroll.
    if (visible < static_cast<int>(nets_.size())) {
        int trackH = rListBox_.bottom - rListBox_.top - S(12);
        int h = static_cast<int>(trackH * (static_cast<float>(visible) /
                                           static_cast<float>(nets_.size())));
        int y = rListBox_.top + S(6) +
                static_cast<int>((trackH - h) * (static_cast<float>(firstRow_) /
                                                 static_cast<float>(nets_.size())));
        RECT thumb = {rListBox_.right - S(5), y, rListBox_.right - S(3), y + h};
        HBRUSH br = CreateSolidBrush(cBorder_);
        FillRect(hdc, &thumb, br);
        DeleteObject(br);
    }
}

void App::paintFields(HDC hdc) {
    for (const FieldView& fv : fieldViews()) drawField(hdc, fv, fieldRect_[fv.index]);
}

void App::paintActions(HDC hdc) {
    drawButton(hdc, L"Connect", rectOf(kHitConnect), kHitConnect, true, !busy_);
    drawButton(hdc, L"Disconnect", rectOf(kHitDisconnect), kHitDisconnect, false, !busy_);
}

void App::paintLog(HDC hdc) {
    FillRoundRect(hdc, rLog_, S(10), cLogBg_, cBorder_);

    const int lh = S(14);
    const int padY = S(9);
    const int padX = S(12);
    int maxLines = (rLog_.bottom - rLog_.top - padY * 2) / lh;
    if (maxLines < 1) maxLines = 1;

    std::deque<std::string> tail;
    for (size_t i = log_.size(); i-- > 0 && static_cast<int>(tail.size()) < maxLines;)
        tail.push_front(log_[i]);

    int y = rLog_.top + padY;
    SelectObject(hdc, fMono_);
    for (const std::string& line : tail) {
        COLORREF c = cSub_;
        if (line.rfind("Error", 0) == 0) c = cErr_;
        else if (line.rfind("Warning", 0) == 0) c = cWarn_;
        else if (line.rfind("Connected", 0) == 0) c = cOk_;

        RECT lr = {rLog_.left + padX, y, rLog_.right - padX, y + lh};
        TextAt(hdc, widen(line), lr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
               c);
        y += lh;
    }
}

// Draws the adapter picker and, when open, the overlay list. Returns the list of
// item rects via `rows` so hit-testing and painting stay in sync.
void App::drawAdapterRow(HDC hdc) {
    const int x = rAdapter_.left + S(2);
    SelectObject(hdc, fLabel_);
    TextAt(hdc, L"ADAPTER", RECT{x, rAdapter_.top, x + S(80), rAdapter_.bottom},
           DT_LEFT | DT_VCENTER | DT_SINGLELINE, cSub_);

    RECT btn = rectOf(kHitAdapter);
    const bool hovered = hover_ == kHitAdapter || dropOpen_;
    FillRoundRect(hdc, btn, S(7), dropOpen_ || hovered ? cSurface2_ : cSurface_,
                  dropOpen_ ? cAccent_ : cBorder_);

    std::wstring name = L"(no adapter)";
    if (selIface_ >= 0 && selIface_ < static_cast<int>(ifaces_.size()))
        name = ifaces_[static_cast<size_t>(selIface_)].description;

    RECT tr = {btn.left + S(12), btn.top, btn.right - S(26), btn.bottom};
    SelectObject(hdc, fBody_);
    TextAt(hdc, name, tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
           cText_);

    // Small down-caret.
    int cx = btn.right - S(14), cy = (btn.top + btn.bottom) / 2;
    POINT tri[3] = {{cx - S(4), cy - S(2)}, {cx + S(4), cy - S(2)}, {cx, cy + S(3)}};
    HBRUSH br = CreateSolidBrush(cSub_);
    HGDIOBJ old = SelectObject(hdc, br);
    Polygon(hdc, tri, 3);
    SelectObject(hdc, old);
    DeleteObject(br);
}

void App::drawAdapterDropdown(HDC hdc) {
    if (!dropOpen_) return;

    FillRoundRect(hdc, rDrop_, S(8), cSurface_, cBorder_);

    const int rowH = S(40);
    int y = rDrop_.top + S(4);
    for (size_t i = 0; i < ifaces_.size(); ++i) {
        const InterfaceInfo& it = ifaces_[i];
        RECT row = {rDrop_.left + S(4), y, rDrop_.right - S(4), y + rowH - S(4)};
        adapterRows_[i] = row;
        y += rowH;

        const bool sel = static_cast<int>(i) == selIface_;
        if (sel) FillRoundRect(hdc, row, S(6), cSel_, cSel_);
        else if (hover_ == kHitAdapterBase + static_cast<int>(i))
            FillRoundRect(hdc, row, S(6), cSurface2_, cSurface2_);

        std::wstring desc = it.description;
        RECT dr = {row.left + S(10), row.top + S(3), row.right - S(10),
                   row.top + S(19)};
        SelectObject(hdc, fBody_);
        TextAt(hdc, desc, dr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
               sel ? cSelText_ : cText_);

        RECT sr = {row.left + S(10), row.top + S(19), row.right - S(10), row.bottom};
        SelectObject(hdc, fSmall_);
        TextAt(hdc, widen(stateName(it.state)), sr,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE, cSub_);
    }
}

void App::paint(HDC hdc) {
    layout();

    RECT rc{};
    GetClientRect(hwnd_, &rc);

    // Double-buffer: everything is painted into a memory DC, then blitted once.
    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
    HBITMAP oldBmp = static_cast<HBITMAP>(SelectObject(mem, bmp));
    HBRUSH oldBr = static_cast<HBRUSH>(SelectObject(mem, brBg_));
    SetBkMode(mem, TRANSPARENT);

    RECT full = {0, 0, rc.right, rc.bottom};
    FillRect(mem, &full, brBg_);

    drawTitle(mem);
    drawAdapterRow(mem);
    paintStatus(mem);
    paintList(mem);
    paintFields(mem);
    paintActions(mem);
    paintLog(mem);

    SelectObject(mem, oldBr);
    // The dropdown overlays everything, so it paints last.
    drawAdapterDropdown(mem);

    BitBlt(hdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldBmp);
    DeleteObject(bmp);
    DeleteDC(mem);
}

// =================================================================== input ===

int App::hitTest(int x, int y) const {
    auto inside = [&](const RECT& r) {
        return x >= r.left && x < r.right && y >= r.top && y < r.bottom;
    };

    // The open dropdown sits on top and swallows clicks in its own area.
    if (dropOpen_) {
        for (size_t i = 0; i < adapterRows_.size(); ++i)
            if (inside(adapterRows_[i]))
                return kHitAdapterBase + static_cast<int>(i);
        return -2;  // inside the dropdown panel but not on a row
    }

    for (const Hit& h : hits_)
        if (inside(h.rect)) return h.id;

    if (inside(rListBox_) && !nets_.empty()) {
        const int inset = S(3);
        int rel = (y - rListBox_.top - inset) / rowH_;
        long idx = static_cast<long>(firstRow_) + rel;
        if (idx >= 0 && idx < static_cast<long>(nets_.size()))
            return -1000 - static_cast<int>(idx);
        return -1;
    }
    for (int i = 0; i < 3; ++i)
        if (inside(fieldRect_[i])) return 100 + i;
    return 0;
}

void App::clampScroll() {
    // layout() may not have run yet when a worker result arrives.
    if (rListBox_.bottom <= rListBox_.top) return;

    const int inset = S(3);
    const int listH = rListBox_.bottom - rListBox_.top - inset * 2;
    int visible = listH / rowH_;
    if (visible < 1) visible = 1;

    int maxFirst = static_cast<int>(nets_.size()) - visible;
    if (maxFirst < 0) maxFirst = 0;
    if (firstRow_ > maxFirst) firstRow_ = maxFirst;
    if (firstRow_ < 0) firstRow_ = 0;

    if (sel_ >= 0) {
        if (sel_ < firstRow_) firstRow_ = sel_;
        if (sel_ >= firstRow_ + visible) firstRow_ = sel_ - visible + 1;
    }
}

void App::onMouseMove(HWND h, int x, int y) {
    int id = hitTest(x, y);
    if (id != hover_) {
        hover_ = id;
        InvalidateRect(h, nullptr, FALSE);
    }
    TRACKMOUSEEVENT tme = {sizeof(tme), TME_LEAVE, h, 0};
    TrackMouseEvent(&tme);
}

void App::onMouseDown(HWND h, int x, int y) {
    SetFocus(h);
    int id = hitTest(x, y);

    // Any click outside an open dropdown dismisses it without acting.
    if (dropOpen_ && id != kHitAdapter && id < kHitAdapterBase) {
        dropOpen_ = false;
        adapterRows_.clear();
        InvalidateRect(h, nullptr, FALSE);
        return;
    }

    switch (id) {
        case kHitAdapter:
            dropOpen_ = !dropOpen_;
            adapterRows_.clear();
            if (dropOpen_) adapterRows_.resize(ifaces_.size());
            InvalidateRect(h, nullptr, FALSE);
            return;
        case kHitScan:
            if (!busy_) startScan();
            return;
        case kHitConnect:
            if (!busy_) startConnect();
            return;
        case kHitDisconnect:
            if (!busy_) startDisconnect();
            return;
        case kHitTheme:
            dark_ = !dark_;
            applyThemeToWindow(h);
            InvalidateRect(h, nullptr, FALSE);
            return;
        default:
            break;
    }

    if (id >= kHitAdapterBase) {
        int idx = id - kHitAdapterBase;
        if (idx >= 0 && idx < static_cast<int>(ifaces_.size())) {
            selIface_ = idx;
            saveIfacePref();
            dropOpen_ = false;
            adapterRows_.clear();
            pushLog("Adapter: " + narrow(ifaces_[static_cast<size_t>(idx)].description));
            // The network list belongs to the old adapter; rescan.
            nets_.clear();
            sel_ = -1;
            firstRow_ = 0;
            InvalidateRect(h, nullptr, FALSE);
            startScan();
        }
        return;
    }

    if (id <= -1000) {
        selectNetwork(-1000 - id);
        return;
    }
    if (id >= 100) {
        // A personal network has no username/realm; keep focus on the secret.
        focus_ = opt_.pskMode ? kPass : id - 100;
        if (focus_ == kPass) showPassword_ = true;
        caretOn_ = true;
        InvalidateRect(h, nullptr, FALSE);
        return;
    }
    focus_ = -1;
    InvalidateRect(h, nullptr, FALSE);
}

void App::onChar(WCHAR c) {
    if (busy_ || focus_ < 0 || focus_ > kPass) return;
    if (c == '\r' || c == '\n' || c == '\t' || c < 0x20) return;
    // Ctrl/Alt combinations are shortcuts (e.g. Ctrl+V), never literal text.
    // TranslateMessage still emits WM_CHAR for those, so ignore them here.
    if (GetKeyState(VK_CONTROL) & 0x8000) return;

    std::wstring one(1, c);
    fields_[focus_] += narrow(one);
    caretOn_ = true;
    InvalidateRect(hwnd_, nullptr, FALSE);
}

void App::onKeyDown(HWND h, WPARAM key) {
    // Paste: nobody wants to retype a password character by character.
    if (key == 'V' && (GetKeyState(VK_CONTROL) & 0x8000)) {
        if (focus_ >= 0 && !busy_ && OpenClipboard(h)) {
            if (HANDLE hmem = GetClipboardData(CF_UNICODETEXT)) {
                const wchar_t* p = static_cast<const wchar_t*>(GlobalLock(hmem));
                if (p) {
                    fields_[focus_] += narrow(p);
                    GlobalUnlock(hmem);
                }
            }
            CloseClipboard();
            caretOn_ = true;
            InvalidateRect(h, nullptr, FALSE);
        }
        return;
    }

    if (key == VK_F5) {
        if (!busy_) startScan();
        return;
    }
    if (key == VK_ESCAPE) {
        focus_ = -1;
        InvalidateRect(h, nullptr, FALSE);
        return;
    }
    if (key == VK_RETURN) {
        if (!busy_) startConnect();
        return;
    }

    if (key == VK_BACK && focus_ >= 0 && !busy_) {
        std::string& s = fields_[focus_];
        size_t end = s.size();
        if (end > 0) {
            --end;
            // Remove a whole UTF-8 code point, not just the trailing byte.
            while (end > 0 && (static_cast<unsigned char>(s[end]) & 0xC0) == 0x80) --end;
            s.erase(end);
        }
        caretOn_ = true;
        InvalidateRect(h, nullptr, FALSE);
        return;
    }

    if (key == VK_TAB) {
        std::vector<FieldView> fvs = fieldViews();
        int cur = -1;
        for (size_t i = 0; i < fvs.size(); ++i)
            if (fvs[i].index == focus_) cur = static_cast<int>(i);
        int next = (cur + 1) % static_cast<int>(fvs.size());
        focus_ = fvs[static_cast<size_t>(next)].index;
        caretOn_ = true;
        InvalidateRect(h, nullptr, FALSE);
        return;
    }

    if ((key == VK_UP || key == VK_DOWN) && !nets_.empty()) {
        if (sel_ < 0) sel_ = 0;
        sel_ += (key == VK_DOWN) ? 1 : -1;
        if (sel_ < 0) sel_ = 0;
        if (sel_ >= static_cast<int>(nets_.size()))
            sel_ = static_cast<int>(nets_.size()) - 1;
        selectNetwork(sel_);
    }
}

void App::selectNetwork(int index) {
    if (index < 0 || index >= static_cast<int>(nets_.size())) return;
    sel_ = index;
    const NetworkInfo& n = nets_[static_cast<size_t>(index)];

    // Personal networks become PSK profiles; enterprise ones stay 802.1X.
    opt_.pskMode = !n.enterprise();
    opt_.ssid = n.ssid;
    opt_.profileName = n.ssid;
    fields_[kPass].clear();

    if (opt_.pskMode) focus_ = kPass;
    if (!opt_.pskMode && focus_ < 0) focus_ = kUser;

    clampScroll();
    InvalidateRect(hwnd_, nullptr, FALSE);
}

// ==================================================================== work ===

ProfileOptions App::currentOptions() const {
    ProfileOptions o = opt_;
    o.username = fields_[kUser];
    o.domain = fields_[kDomain];
    o.password = fields_[kPass];
    o.psk = fields_[kPass];
    return o;
}

void App::refreshInterfaces() {
    if (!uiWlan_) return;

    // Remember the current selection by GUID so a refresh keeps it.
    std::string keep;
    if (selIface_ >= 0 && selIface_ < static_cast<int>(ifaces_.size()))
        keep = ifaces_[static_cast<size_t>(selIface_)].guidStr;

    try {
        ifaces_ = uiWlan_->interfaces();
    } catch (const std::exception&) {
        return;
    }

    selIface_ = -1;
    for (size_t i = 0; i < ifaces_.size(); ++i) {
        if (ifaces_[i].guidStr == keep) {
            selIface_ = static_cast<int>(i);
            break;
        }
    }
    if (selIface_ < 0) {
        // Default to the first adapter that is not "not ready".
        selIface_ = 0;
        for (size_t i = 0; i < ifaces_.size(); ++i) {
            if (ifaces_[i].state != wlan_interface_state_not_ready) {
                selIface_ = static_cast<int>(i);
                break;
            }
        }
    }
}

GUID App::currentIface() const {
    if (selIface_ >= 0 && selIface_ < static_cast<int>(ifaces_.size()))
        return ifaces_[static_cast<size_t>(selIface_)].guid;
    throw std::runtime_error("no wireless interface available");
}

// The chosen adapter is remembered between runs so the GUI opens on the same
// NIC every time.
void App::loadIfacePref() {
    wchar_t path[MAX_PATH]{};
    if (!GetEnvironmentVariableW(L"APPDATA", path, MAX_PATH)) return;
    std::wstring file = std::wstring(path) + L"\\edurm\\adapter.txt";

    HANDLE h = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    char buf[80]{};
    DWORD n = 0;
    ReadFile(h, buf, sizeof(buf) - 1, &n, nullptr);
    CloseHandle(h);
    if (n == 0) return;

    std::string saved(buf, n);
    while (!saved.empty() && (saved.back() == '\r' || saved.back() == '\n'))
        saved.pop_back();

    for (size_t i = 0; i < ifaces_.size(); ++i) {
        if (ifaces_[i].guidStr == saved) {
            selIface_ = static_cast<int>(i);
            return;
        }
    }
}

void App::saveIfacePref() const {
    if (selIface_ < 0 || selIface_ >= static_cast<int>(ifaces_.size())) return;

    wchar_t base[MAX_PATH]{};
    if (!GetEnvironmentVariableW(L"APPDATA", base, MAX_PATH)) return;
    std::wstring dir = std::wstring(base) + L"\\edurm";
    CreateDirectoryW(dir.c_str(), nullptr);

    std::wstring file = dir + L"\\adapter.txt";
    HANDLE h = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::string guid = ifaces_[static_cast<size_t>(selIface_)].guidStr;
    DWORD written = 0;
    WriteFile(h, guid.c_str(), static_cast<DWORD>(guid.size()), &written, nullptr);
    CloseHandle(h);
}

void App::pushLog(std::string line) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        qLog_.push_back(std::move(line));
    }
    if (hwnd_) PostMessage(hwnd_, WM_APP_LOG, 0, 0);
}

void App::drainQueue() {
    std::deque<std::string> lines;
    std::vector<NetworkInfo> nets;
    bool haveNets = false;
    bool jobDone = false;
    bool wasConnect = false;
    bool resultOk = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        lines.swap(qLog_);
        if (qHaveNets_) {
            nets.swap(qNets_);
            haveNets = true;
            qHaveNets_ = false;
        }
        if (qJobDone_) {
            jobDone = true;
            wasConnect = qWasConnect_;
            resultOk = qResultOk_;
            qJobDone_ = false;
        }
    }

    for (std::string& l : lines) {
        if (log_.size() >= 200) log_.pop_front();
        log_.push_back(std::move(l));
    }

    if (haveNets) {
        // Keep the selection pointing at the same SSID after a refresh.
        std::string keep = (sel_ >= 0 && sel_ < static_cast<int>(nets_.size()))
                               ? nets_[static_cast<size_t>(sel_)].ssid
                               : std::string();
        nets_.swap(nets);
        sel_ = -1;
        if (!keep.empty()) {
            for (size_t i = 0; i < nets_.size(); ++i) {
                if (nets_[i].ssid == keep) {
                    sel_ = static_cast<int>(i);
                    break;
                }
            }
        }
        clampScroll();
    }

    if (jobDone) {
        // Always clear busy_, whatever the job was, so the fields and buttons
        // come back to life.
        busy_ = false;

        if (wasConnect) {
            if (resultOk) {
                pushLog("Connected.");
            } else {
                pushLog("Error: connection failed - see notes below");
                pushLog(troubleshootingHint());
            }
        }
    }

    InvalidateRect(hwnd_, nullptr, FALSE);
}

void App::refreshStatus() {
    if (uiWlan_) {
        try {
            GUID g = currentIface();
            WLAN_CONNECTION_ATTRIBUTES c = uiWlan_->connection(g);
            if (c.isState == wlan_interface_state_connected) {
                connected_ = true;
                statusHead_ = widen(narrow(c.strProfileName));
                statusDetail_ = widen(authName(c.wlanSecurityAttributes.dot11AuthAlgorithm) +
                                      "  \xB7  " +
                                      cipherName(c.wlanSecurityAttributes.dot11CipherAlgorithm) +
                                      (c.wlanSecurityAttributes.bOneXEnabled
                                           ? "  \xB7  802.1X"
                                           : ""));
                InvalidateRect(hwnd_, nullptr, FALSE);
                return;
            }
        } catch (const std::exception&) {
            // fall through to the disconnected state
        }
    }
    connected_ = false;
    statusHead_ = busy_ ? L"Working..." : L"Not connected";
    statusDetail_ = L"Select a network below and press Connect.";
    InvalidateRect(hwnd_, nullptr, FALSE);
}

void App::startScan() {
    if (busy_) return;
    busy_ = true;
    showPassword_ = false;
    InvalidateRect(hwnd_, nullptr, FALSE);

    if (worker_.joinable()) worker_.join();
    // Resolve the adapter on the UI thread; the worker must not touch UI state.
    const GUID gSel = currentIface();
    worker_ = std::thread([this, gSel] {
        try {
            Wlan w;
            std::vector<NetworkInfo> nets = w.scan(gSel, 3000);
            {
                std::lock_guard<std::mutex> lk(mtx_);
                qNets_ = std::move(nets);
                qHaveNets_ = true;
                qWasConnect_ = false;
                qResultOk_ = true;
                qJobDone_ = true;
            }
            pushLog("Scan finished.");
        } catch (const std::exception& e) {
            pushLog(std::string("Error: ") + e.what());
        }
        PostMessage(hwnd_, WM_APP_DONE, 0, 0);
    });
}

void App::startConnect() {
    if (busy_) return;
    if (nets_.empty()) {
        pushLog("Error: press Scan first.");
        return;
    }
    if (sel_ < 0) {
        pushLog("Error: select a network first.");
        return;
    }
    if (fields_[kPass].empty()) {
        pushLog("Error: enter a password or passphrase first.");
        focus_ = kPass;
        showPassword_ = true;
        InvalidateRect(hwnd_, nullptr, FALSE);
        return;
    }

    ProfileOptions o = currentOptions();
    busy_ = true;
    showPassword_ = false;
    statusHead_ = L"Connecting...";
    InvalidateRect(hwnd_, nullptr, FALSE);

    if (worker_.joinable()) worker_.join();
    const GUID gSel = currentIface();
    worker_ = std::thread([this, o, gSel] {
        bool ok = false;
        try {
            Wlan w;
            ConnectResult r = installAndConnect(
                w, gSel, o, /*allUsers=*/false, /*timeoutMs=*/45000,
                [this](Stage stage, const std::string& msg) {
                    pushLog(std::string(stage == Stage::Failed ? "Error: " : "") + msg);
                });
            ok = r.ok;
        } catch (const std::exception& e) {
            pushLog(std::string("Error: ") + e.what());
        }
        {
            std::lock_guard<std::mutex> lk(mtx_);
            qResultOk_ = ok;
            qWasConnect_ = true;
            qJobDone_ = true;
        }
        PostMessage(hwnd_, WM_APP_DONE, 0, 0);
    });
}

void App::startDisconnect() {
    if (busy_) return;
    busy_ = true;
    showPassword_ = false;
    InvalidateRect(hwnd_, nullptr, FALSE);

    if (worker_.joinable()) worker_.join();
    const GUID gSel = currentIface();
    worker_ = std::thread([this, gSel] {
        bool ok = false;
        try {
            Wlan w;
            w.disconnect(gSel);
            w.waitForState(gSel, wlan_interface_state_disconnected, 10000);
            ok = true;
        } catch (const std::exception& e) {
            pushLog(std::string("Error: ") + e.what());
        }
        {
            std::lock_guard<std::mutex> lk(mtx_);
            qResultOk_ = ok;
            // Not a connect: drainQueue must not print "Connected."
            qWasConnect_ = false;
            qJobDone_ = true;
        }
        PostMessage(hwnd_, WM_APP_DONE, 0, 0);
    });
}

// ================================================================ messages ===

LRESULT CALLBACK App::wndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    App* self = nullptr;
    if (m == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCT*>(l);
        self = static_cast<App*>(cs->lpCreateParams);
        self->hwnd_ = h;
        SetWindowLongPtr(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<App*>(GetWindowLongPtr(h, GWLP_USERDATA));
    }
    if (!self) return DefWindowProc(h, m, w, l);
    return self->handle(h, m, w, l);
}

LRESULT App::handle(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_CREATE: {
            dark_ = IsSystemDarkMode();
            buildPalette();
            createGdiObjects();
            rowH_ = S(46);

            try {
                uiWlan_ = std::make_unique<Wlan>();
            } catch (const std::exception&) {
                uiWlan_.reset();
            }

            fields_[kUser] = opt_.username;
            fields_[kDomain] = opt_.domain;

            // Enumerate adapters, then honour a previously saved choice.
            refreshInterfaces();
            loadIfacePref();

            ca_ = checkEduroamRoots();
            log_.push_back("edurm ready.");
            if (!ca_.found)
                log_.push_back("Warning: eduroam CA bundle not found in trusted roots.");

            applyThemeToWindow(h);
            SetTimer(h, 1, 1200, nullptr);  // status poll
            SetTimer(h, 2, 530, nullptr);   // caret blink
            refreshStatus();
            startScan();
            return 0;
        }

        case WM_TIMER:
            if (w == 1) {
                if (!busy_) {
                    refreshStatus();
                    // Adapters can be plugged in or removed at any time.
                    refreshInterfaces();
                }
                InvalidateRect(h, nullptr, FALSE);
            }
            if (w == 2) {
                caretOn_ = !caretOn_;
                if (focus_ >= 0) InvalidateRect(h, nullptr, FALSE);
            }
            return 0;

        case WM_APP_LOG:
            drainQueue();
            return 0;

        case WM_APP_DONE:
            drainQueue();
            if (!busy_ && !connected_) refreshStatus();
            return 0;

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(h, &ps);
            paint(hdc);
            EndPaint(h, &ps);
            return 0;
        }

        case WM_ERASEBKGND:
            return 1;  // fully repainted in WM_PAINT

        case WM_MOUSEMOVE:
            onMouseMove(h, GET_X_LPARAM(l), GET_Y_LPARAM(l));
            return 0;

        case WM_LBUTTONDOWN:
            onMouseDown(h, GET_X_LPARAM(l), GET_Y_LPARAM(l));
            return 0;

        case WM_MOUSELEAVE:
            if (hover_ != 0) {
                hover_ = 0;
                InvalidateRect(h, nullptr, FALSE);
            }
            return 0;

        case WM_MOUSEWHEEL: {
            if (w != 0 && !nets_.empty()) {
                int step = (GET_WHEEL_DELTA_WPARAM(w) > 0) ? -3 : 3;
                firstRow_ += step;
                clampScroll();
                InvalidateRect(h, nullptr, FALSE);
            }
            return 0;
        }

        case WM_CHAR:
            onChar(static_cast<WCHAR>(w));
            return 0;

        case WM_KEYDOWN:
            onKeyDown(h, w);
            return 0;

        case WM_SETCURSOR: {
            if (LOWORD(l) == HTCLIENT) {
                POINT p;
                GetCursorPos(&p);
                ScreenToClient(h, &p);
                SetCursor(LoadCursor(nullptr, hitTest(p.x, p.y) != 0 ? IDC_HAND : IDC_ARROW));
                return TRUE;
            }
            break;
        }

        case WM_DPICHANGED: {
            dpi_ = static_cast<float>(HIWORD(w));
            dpiScale_ = dpi_ / 96.0f;
            rowH_ = S(46);
            createGdiObjects();  // fonts are DPI-scaled, so rebuild them
            auto* rect = reinterpret_cast<RECT*>(l);
            SetWindowPos(h, nullptr, rect->left, rect->top, rect->right - rect->left,
                         rect->bottom - rect->top, SWP_NOZORDER | SWP_NOACTIVATE);
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        }

        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(l);
            mmi->ptMinTrackSize.x = static_cast<LONG>(S(430));
            mmi->ptMinTrackSize.y = static_cast<LONG>(S(580));
            return 0;
        }

        case WM_SIZE: {
            rowH_ = S(46);
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        }

        case WM_CLOSE:
            DestroyWindow(h);
            return 0;

        case WM_DESTROY:
            KillTimer(h, 1);
            KillTimer(h, 2);
            if (worker_.joinable()) worker_.join();
            destroyGdiObjects();
            uiWlan_.reset();
            PostQuitMessage(0);
            return 0;

        default:
            break;
    }
    return DefWindowProc(h, m, w, l);
}

int App::run(HINSTANCE inst) {
    inst_ = inst;

    WNDCLASSEXW wc = WNDCLASSEXW();
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = &App::wndProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"edurm.gui";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    if (!RegisterClassExW(&wc)) return 1;

    hwnd_ = CreateWindowExW(0, L"edurm.gui", L"edurm - eduroam", WS_OVERLAPPEDWINDOW,
                            CW_USEDEFAULT, CW_USEDEFAULT, S(560), S(760), nullptr,
                            nullptr, inst, this);
    if (!hwnd_) return 1;

    ShowWindow(hwnd_, SW_SHOW);
    UpdateWindow(hwnd_);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int) {
    // Opt in to per-monitor DPI before creating any window.
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_WIN95_CLASSES};
    InitCommonControlsEx(&icc);

    App app;
    return app.run(inst);
}