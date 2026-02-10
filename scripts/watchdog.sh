#!/bin/bash
# NetGuard Watchdog Script (AC-DS3)
# Run this in a separate terminal during intercept-mode development.
# Auto-kills NetGuard if unresponsive within 10 seconds.
#
# Usage: ./scripts/watchdog.sh [timeout_seconds]

TIMEOUT=${1:-10}
CHECK_INTERVAL=5
MAX_MISSES=$((TIMEOUT / CHECK_INTERVAL))
MISS_COUNT=0

echo "[WATCHDOG] NetGuard watchdog started (timeout: ${TIMEOUT}s)"
echo "[WATCHDOG] Press Ctrl+C to stop"

while true; do
    PID=$(pgrep -x netguard)
    if [ -n "$PID" ]; then
        # Check if process is responsive (can receive signal 0)
        if ! kill -0 "$PID" 2>/dev/null; then
            MISS_COUNT=$((MISS_COUNT + 1))
            echo "[WATCHDOG] NetGuard (PID $PID) unresponsive (count: $MISS_COUNT)"
            if [ "$MISS_COUNT" -ge "$MAX_MISSES" ]; then
                echo "[WATCHDOG] NetGuard unresponsive for ~${TIMEOUT}s, killing..."
                kill -9 "$PID" 2>/dev/null

                # Flush macOS pf rules and dummynet pipes
                echo "[WATCHDOG] Flushing pf rules and dummynet pipes..."
                sudo pfctl -F all 2>/dev/null
                sudo dnctl -f flush 2>/dev/null

                echo "[WATCHDOG] NetGuard killed. Network should recover shortly."
                MISS_COUNT=0
            fi
        else
            if [ "$MISS_COUNT" -gt 0 ]; then
                echo "[WATCHDOG] NetGuard responding again."
            fi
            MISS_COUNT=0
        fi
    fi
    sleep "$CHECK_INTERVAL"
done
