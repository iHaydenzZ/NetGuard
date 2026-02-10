# NetGuard Watchdog Script (AC-DS3)
# Run this in a separate terminal during intercept-mode development.
# Auto-kills NetGuard if unresponsive within 10 seconds.
#
# Usage: .\scripts\watchdog.ps1 [-TimeoutSeconds 10]

param([int]$TimeoutSeconds = 10)

Write-Host "[WATCHDOG] NetGuard watchdog started (timeout: ${TimeoutSeconds}s)"
Write-Host "[WATCHDOG] Press Ctrl+C to stop"

$unresponsiveCount = 0

while ($true) {
    $proc = Get-Process -Name "netguard" -ErrorAction SilentlyContinue
    if ($proc) {
        try {
            $handle = $proc.Handle  # Force refresh of process state
            if (!$proc.Responding) {
                $unresponsiveCount++
                Write-Host "[WATCHDOG] NetGuard unresponsive (count: $unresponsiveCount)"
                if ($unresponsiveCount -ge ($TimeoutSeconds / 5)) {
                    Write-Host "[WATCHDOG] NetGuard unresponsive for ~${TimeoutSeconds}s, killing..."
                    Stop-Process -Force -Name "netguard"

                    # Also try to stop WinDivert driver if stuck
                    Write-Host "[WATCHDOG] Attempting to stop WinDivert driver..."
                    sc.exe stop WinDivert14 2>$null

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
