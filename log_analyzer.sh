#!/bin/bash
# Optimized log analyzer for macOS
# Uses shorter time windows and faster methods

echo "=== Security Log Analysis ==="
echo "Analyzing last 15 minutes of system logs..."

# Much faster - only look at last 15 minutes instead of 24 hours
TIME_WINDOW="15m"

# Check for authentication failures (most critical)
echo "Checking authentication events..."
auth_events=$(log show --last ${TIME_WINDOW} --predicate 'eventMessage CONTAINS "authentication" OR eventMessage CONTAINS "login"' 2>/dev/null | grep -iE "fail|error|denied" | wc -l | tr -d ' ')

if [ "$auth_events" -gt 0 ]; then
    echo "SUSPICIOUS: Found $auth_events authentication issues"
    log show --last ${TIME_WINDOW} --predicate 'eventMessage CONTAINS "authentication" OR eventMessage CONTAINS "login"' 2>/dev/null | grep -iE "fail|error|denied" | head -3
    echo ""
else
    echo "No authentication issues detected"
fi

# Check for sudo usage
echo "Checking privilege escalation..."
sudo_events=$(log show --last ${TIME_WINDOW} --predicate 'process == "sudo"' 2>/dev/null | wc -l | tr -d ' ')

if [ "$sudo_events" -gt 0 ]; then
    echo "INFO: Detected $sudo_events sudo events"
else
    echo "No sudo activity"
fi

# Check system logs for errors (faster alternative)
echo "Checking recent system errors..."
if [ -f /var/log/system.log ]; then
    recent_errors=$(tail -100 /var/log/system.log 2>/dev/null | grep -iE "error|fail|denied|refused" | wc -l | tr -d ' ')
    if [ "$recent_errors" -gt 0 ]; then
        echo "WARNING: Found $recent_errors error messages in system log"
        tail -100 /var/log/system.log 2>/dev/null | grep -iE "error|fail|denied|refused" | tail -3
    fi
else
    echo "System log not accessible"
fi

# Quick check of recent kernel messages
echo "Checking kernel messages..."
dmesg 2>/dev/null | tail -20 | grep -iE "error|warning|fail" | wc -l | tr -d ' ' | xargs -I {} echo "Found {} kernel warnings/errors"

echo ""
echo "Log analysis completed (fast mode - last ${TIME_WINDOW})"
