# NetGuard Watchdog Script (AC-DS3)
# Run this in a separate terminal during intercept-mode development.
# Auto-kills NetGuard if unresponsive within 10 seconds.
#
# Only processes whose executable lives under -ExpectedPathPrefix are
# watchdog targets: process NAMES are attacker-choosable (any binary can
# call itself netguard.exe), so name-only matching in an elevated shell
# would kill impostors and needlessly stop the WinDivert driver.
#
# Usage: .\scripts\watchdog.ps1 [-TimeoutSeconds 10] [-ExpectedPathPrefix <dir>]

param(
    [int]$TimeoutSeconds = 10,
    # Default covers dev builds launched from this repo (target\debug|release).
    [string]$ExpectedPathPrefix = (Join-Path (Split-Path $PSScriptRoot -Parent) "src-tauri\target")
)

# Normalize to a trailing separator so "target-evil" can't pass a "target" prefix check.
$ExpectedPathPrefix = $ExpectedPathPrefix.TrimEnd('\') + '\'

Write-Host "[WATCHDOG] NetGuard watchdog started (timeout: ${TimeoutSeconds}s)"
Write-Host "[WATCHDOG] Watching executables under: $ExpectedPathPrefix"
Write-Host "[WATCHDOG] Press Ctrl+C to stop"

$unresponsiveCount = 0

while ($true) {
    $proc = Get-Process -Name "netguard" -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Path -and $_.Path.StartsWith($ExpectedPathPrefix, [System.StringComparison]::OrdinalIgnoreCase)
        } | Select-Object -First 1
    if ($proc) {
        try {
            $handle = $proc.Handle  # Force refresh of process state
            if (!$proc.Responding) {
                $unresponsiveCount++
                Write-Host "[WATCHDOG] NetGuard (PID $($proc.Id)) unresponsive (count: $unresponsiveCount)"
                if ($unresponsiveCount -ge [math]::Max(1, [math]::Ceiling($TimeoutSeconds / 5))) {
                    Write-Host "[WATCHDOG] NetGuard unresponsive for ~${TimeoutSeconds}s, killing PID $($proc.Id)..."
                    # Kill by PID, not name: the name could match a different
                    # (or impostor) process by the time the kill fires.
                    Stop-Process -Force -Id $proc.Id -ErrorAction SilentlyContinue

                    # Also try to stop WinDivert driver if stuck
                    Write-Host "[WATCHDOG] Attempting to stop WinDivert driver..."
                    sc.exe stop WinDivert 2>$null

                    Write-Host "[WATCHDOG] NetGuard killed. Network should recover shortly."
                    $unresponsiveCount = 0
                }
            } else {
                if ($unresponsiveCount -gt 0) {
                    Write-Host "[WATCHDOG] NetGuard responding again."
                }
                $unresponsiveCount = 0
            }
        } catch {
            # Process may have exited between check and handle access
            $unresponsiveCount = 0
        }
    } else {
        if ($unresponsiveCount -gt 0) {
            Write-Host "[WATCHDOG] NetGuard process not found."
            $unresponsiveCount = 0
        }
    }
    Start-Sleep -Seconds 5
}
