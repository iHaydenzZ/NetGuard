# NetGuard Emergency Recovery Script (AC-DS6)
# Run this if NetGuard has frozen your network.
#
# Usage: Run as Administrator
#   .\scripts\emergency-recovery.ps1

Write-Host "=== NetGuard Emergency Recovery ==="
Write-Host ""

# Step 1: Kill NetGuard
Write-Host "[1/3] Killing NetGuard process..."
$killed = $false
$proc = Get-Process -Name "netguard" -ErrorAction SilentlyContinue
if ($proc) {
    Stop-Process -Force -Name "netguard"
    Write-Host "      NetGuard killed."
    $killed = $true
} else {
    Write-Host "      NetGuard not running."
}

# Step 2: Stop WinDivert driver
Write-Host "[2/3] Stopping WinDivert driver..."
$result = sc.exe stop WinDivert14 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "      WinDivert driver stopped."
} else {
    Write-Host "      WinDivert driver not running or already stopped."
}

# Step 3: Verify network
Write-Host "[3/3] Verifying network connectivity..."
Start-Sleep -Seconds 2
$ping = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet
if ($ping) {
    Write-Host "      Network is OK!"
} else {
    Write-Host "      Network still down. Try rebooting your machine."
}

Write-Host ""
Write-Host "=== Recovery Complete ==="
