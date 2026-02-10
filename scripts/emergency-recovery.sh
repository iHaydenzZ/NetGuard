#!/bin/bash
# NetGuard Emergency Recovery Script (AC-DS6)
# Run this if NetGuard has frozen your network.
#
# Usage: sudo ./scripts/emergency-recovery.sh

echo "=== NetGuard Emergency Recovery ==="
echo ""

# Step 1: Kill NetGuard
echo "[1/4] Killing NetGuard process..."
PID=$(pgrep -x netguard)
if [ -n "$PID" ]; then
    kill -9 "$PID"
    echo "      NetGuard killed (PID $PID)."
else
    echo "      NetGuard not running."
fi

# Step 2: Flush pf rules
echo "[2/4] Flushing pf rules..."
sudo pfctl -F all 2>/dev/null
echo "      pf rules flushed."

# Step 3: Flush dummynet pipes
echo "[3/4] Flushing dummynet pipes..."
sudo dnctl -f flush 2>/dev/null
echo "      dummynet pipes flushed."

# Step 4: Verify network
echo "[4/4] Verifying network connectivity..."
sleep 2
if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
    echo "      Network is OK!"
else
    echo "      Network still down. Try rebooting your machine."
fi

echo ""
echo "=== Recovery Complete ==="
