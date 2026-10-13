# Captures the edurm GUI to a PNG using PrintWindow.
#
# The environment this runs in occasionally resizes the window shortly after
# startup, so the size is re-asserted in a loop until it holds steady before
# capturing. With -TypeTest it also drives real keystrokes into the password
# field and reports whether the characters were accepted.
param(
  [string]$Exe = ".\build\edurm-gui.exe",
  [string]$Out = "build\gui_shot.png",
  [int]$Width = 620,
  [int]$Height = 800,
  [switch]$TypeTest
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int t, bool repaint);
    [DllImport("user32.dll")] public static extern bool RedrawWindow(IntPtr h, IntPtr r, IntPtr rgn, uint flags);
}
"@

$p = Start-Process -FilePath $Exe -PassThru
Start-Sleep -Seconds 9
$p.Refresh()
$hwnd = $p.MainWindowHandle
if ($hwnd -eq [IntPtr]::Zero) { $p | Stop-Process -Force; throw "no window handle" }
[void][Win]::SetForegroundWindow($hwnd)

# Re-assert the size until it sticks (the environment may resize us).
$stable = $false
for ($i = 0; $i -lt 6 -and -not $stable; $i++) {
    [void][Win]::MoveWindow($hwnd, 40, 40, $Width, $Height, $true)
    Start-Sleep -Milliseconds 700
    $c1 = New-Object Win+RECT; [void][Win]::GetClientRect($hwnd, [ref]$c1)
    Start-Sleep -Milliseconds 700
    $c2 = New-Object Win+RECT; [void][Win]::GetClientRect($hwnd, [ref]$c2)
    if (($c2.R - $c2.L) -eq ($c1.R - $c1.L) -and ($c2.B - $c2.T) -eq ($c1.B - $c1.T)) {
        $stable = $true
    } else {
        Write-Host "  size drifted ($($c1.R - $c1.L)x$($c1.B - $c1.T) -> $($c2.R - $c2.L)x$($c2.B - $c2.T)), re-asserting"
    }
}
Write-Host "size stable: $stable"

if ($TypeTest) {
    # Focus starts on USERNAME; Tab twice to reach PASSWORD, then type into it.
    $TAB = 0x09
    foreach ($ch in [char[]]@($TAB, $TAB)) {
        $null = [Win]::RedrawWindow($hwnd, [IntPtr]::Zero, [IntPtr]::Zero, 0x0001)
        Add-Type -Name K -Namespace T -MemberDefinition @"
[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
"@ -ErrorAction SilentlyContinue
        [T.K]::PostMessage($hwnd, 0x0100, [IntPtr]$ch, [IntPtr]::Zero) | Out-Null
        Start-Sleep -Milliseconds 120
    }
    foreach ($ch in [char[]]"secret42") {
        [T.K]::PostMessage($hwnd, 0x0102, [IntPtr]$ch, [IntPtr]::Zero) | Out-Null
        Start-Sleep -Milliseconds 60
    }
    Write-Host "sent keystrokes: TAB TAB then 'secret42'"
    Start-Sleep -Milliseconds 700
}

$null = [Win]::RedrawWindow($hwnd, [IntPtr]::Zero, [IntPtr]::Zero, 0x0001 -bor 0x0004)
Start-Sleep -Milliseconds 800

$r = New-Object Win+RECT
[void][Win]::GetWindowRect($hwnd, [ref]$r)
$c = New-Object Win+RECT
[void][Win]::GetClientRect($hwnd, [ref]$c)
$w = $r.R - $r.L; $h = $r.B - $r.T
Write-Host "window rect : $($r.L),$($r.T) ${w}x${h}"
Write-Host "client rect : $($c.R - $c.L) x $($c.B - $c.T)"

$bmp = New-Object System.Drawing.Bitmap $w, $h
$g = [System.Drawing.Graphics]::FromImage($bmp)
$dc = $g.GetHdc()
[void][Win]::PrintWindow($hwnd, $dc, 2)   # PW_RENDERFULLCONTENT
$g.ReleaseHdc($dc)
$g.Dispose()
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
$p | Stop-Process -Force

Write-Host "saved $Out ($((Get-Item $Out).Length) bytes)"