#!/bin/bash
# Keylogger and Spyware Detection Script
# Scans for common macOS keyloggers, spyware, and monitoring tools

echo "=== Keylogger/Spyware Detection ==="
echo "Scan started: $(date)"
echo ""

# Common keylogger/spyware process names
KEYLOGGER_PROCS=(
    "logkitty"
    "keylogger"
    "inputlog"
    "logkeys"
    "a2k"
    "lkl"
    "refog"
    "spectro"
    "bksp"
    "keygrab"
    "loginput"
    "keycapture"
    "spy"
    "netbus"
    "backorifice"
    "subseven"
    "prokey"
    "activitylog"
    "keypress"
    "keylog"
    "logagent"
)

echo "[1/5] Checking for known keylogger processes..."
found_procs=0
for proc in "${KEYLOGGER_PROCS[@]}"; do
    if pgrep -ix "$proc" > /dev/null 2>&1; then
        echo "  WARNING: Suspicious process found: $proc"
        ps aux | grep -i "$proc" | grep -v grep
        echo ""
        found_procs=$((found_procs + 1))
    fi
done

if [ $found_procs -eq 0 ]; then
    echo "  OK: No known keylogger processes detected"
fi
echo ""

# Check for input monitoring permissions abuse
echo "[2/5] Checking apps with Input Monitoring access..."
if [ -f "/Library/Application Support/com.apple.TCC/TCC.db" ]; then
    # This requires Full Disk Access to run properly
    input_apps=$(sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "SELECT client FROM access WHERE service='kTCCServiceEventMonitoring' OR service='kTCCServicePostEvent'" 2>/dev/null)

    if [ -n "$input_apps" ]; then
        echo "  Apps with Input Monitoring:"
        echo "$input_apps"
    else
        echo "  INFO: Could not read TCC database (requires Full Disk Access)"
        echo "  Check manually: System Settings > Privacy & Security > Input Monitoring"
    fi
else
    echo "  INFO: TCC database not accessible"
fi
echo ""

# Check for suspicious launch agents/daemons
echo "[3/5] Checking LaunchAgents/Daemons for suspicious entries..."
suspicious_count=0

for dir in ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons; do
    if [ -d "$dir" ]; then
        echo "  Checking: $dir"
        find "$dir" -name "*.plist" -type f 2>/dev/null | while read plist; do
            # Get the executable path
            binary=$(/usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null)
            label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null)

            # Skip if no binary or Apple/signed binaries
            if [ -z "$binary" ] || [ ! -f "$binary" ]; then
                continue
            fi

            # Check for suspicious labels
            if echo "$label" | grep -qiE "(update|daemon|service|agent|helper|start|load)" && \
               ! echo "$label" | grep -qi "com.apple"; then
                # Check if binary is unsigned
                if codesign -dv "$binary" 2>&1 | grep -q "code object is not signed"; then
                    echo "    WARNING: UNSIGNED autostart: $label"
                    echo "      Path: $binary"
                    echo "      Plist: $plist"
                    suspicious_count=$((suspicious_count + 1))
                fi
            fi
        done
    fi
done

if [ $suspicious_count -eq 0 ]; then
    echo "  OK: No suspicious unsigned autostart agents found"
fi
echo ""

# Check for suspicious files in common locations
echo "[4/5] Checking for suspicious files in common locations..."
suspicious_files=0

# Common drop locations for malware
CHECK_DIRS=(
    "~/Library/ScriptingAdditions"
    "/Library/ScriptingAdditions"
    "~/Library/StartupItems"
    "/Library/StartupItems"
    "/private/var/tmp"
    "/tmp"
    "~/.hidden"
    "~/Library/Preferences"
)

for dir in "${CHECK_DIRS[@]}"; do
    expanded_dir="${dir/#\~/$HOME}"
    if [ -d "$expanded_dir" ]; then
        # Look for recently modified executables
        find "$expanded_dir" -type f \( -name "*.app" -o -perm +111 \) -mtime -7 2>/dev/null | while read file; do
            # Check if it's not from Apple
            if ! codesign -dv "$file" 2>&1 | grep -q "Authority=Apple"; then
                echo "  WARNING: Recently modified executable: $file"
                ls -lh "$file"
                suspicious_files=$((suspicious_files + 1))
            fi
        done
    fi
done

if [ $suspicious_files -eq 0 ]; then
    echo "  OK: No suspicious files found in common locations"
fi
echo ""

# Check for keyboard event taps (advanced keylogger technique)
echo "[5/5] Checking for event tap processes..."
event_tap_procs=$(ps aux | grep -i "CGEvent" | grep -v grep | wc -l | tr -d ' ')
if [ "$event_tap_procs" -gt 0 ]; then
    echo "  INFO: Found $event_tap_procs processes using CGEvent (could be legitimate)"
    echo "  Processes:"
    ps aux | grep -i "CGEvent" | grep -v grep | head -5
else
    echo "  OK: No CGEvent tap processes detected"
fi
echo ""

# Summary
echo "=== Scan Complete ==="
echo "Suspicious findings: $((found_procs + suspicious_count + suspicious_files))"
echo ""

if [ $((found_procs + suspicious_count + suspicious_files)) -gt 0 ]; then
    echo "ALERT: Potential threats detected. Review the warnings above."
    exit 1
else
    echo "OK: No immediate keylogger or spyware threats detected."
    exit 0
fi
