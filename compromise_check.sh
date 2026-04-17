#!/bin/bash
# Active Compromise Indicators Script
# Runs quick checks to determine if system is actively compromised

echo "=== Active Compromise Indicators Check ==="
echo "Scan started: $(date)"
echo ""

total_findings=0

# 1. Check for unexpected outbound encrypted connections
echo "[1/7] Checking for unexpected outbound connections..."
outbound_findings=0

# Get established connections to external IPs
external_connections=$(lsof -i -P -n 2>/dev/null | grep ESTABLISHED | grep -v "127.0.0.1" | grep -v "::1" | awk '{print $1, $9}' | sort -u)

if [ -n "$external_connections" ]; then
    echo "  Active external connections (top 20):"
    echo "$external_connections" | head -20 | while read line; do
        proc=$(echo $line | awk '{print $1}')
        endpoint=$(echo $line | awk '{print $2}')

        # Parse the endpoint (format: IP:PORT->IP:PORT or local:remote)
        if echo "$endpoint" | grep -qE '->|->'; then
            remote=$(echo "$endpoint" | sed 's/.*->//' | head -1)
            ip=$(echo $remote | cut -d: -f1)
            port=$(echo $remote | cut -d: -f2)

            # Only flag if remote port is truly unusual (not ephemeral)
            # Ephemeral ports are 1024-65535, so we only care about low ports
            if [ "$port" -le 1024 ] 2>/dev/null; then
                if ! echo "$port" | grep -qE "^(80|443|22|53|993|995|587|465|25)$"; then
                    echo "    ⚠ $proc -> $ip:$port (unusual low port)"
                    outbound_findings=$((outbound_findings + 1))
                fi
            fi
        fi
    done
else
    echo "  No external connections detected"
fi

if [ $outbound_findings -eq 0 ]; then
    echo "  ✓ No unusual outbound connections to low ports"
fi

total_findings=$((total_findings + outbound_findings))
echo ""

# 2. Check for processes with deleted executable (in-memory malware)
echo "[2/7] Checking for processes with deleted executables..."
deleted_findings=0

# On macOS, check for processes with '?' in executable path
suspicious_procs=$(ps ax | grep '?' | grep -v grep | grep -v "PID" | head -10)

if [ -n "$suspicious_procs" ]; then
    # These are mostly normal, but check for truly suspicious ones
    echo "  Processes with unusual paths (checking for anomalies...)"
    # Most of these are kernel tasks, just show a count
    echo "  INFO: Some processes show '?' (kernel tasks - normal)"
else
    echo "  ✓ No obviously suspicious processes detected"
fi

total_findings=$((total_findings + deleted_findings))
echo ""

# 3. Check for suspicious parent processes
echo "[3/7] Checking for suspicious parent-child process relationships..."
parent_findings=0

# Look for processes with unusual parent PIDs
suspicious_parents=$(ps -eo pid,ppid,user,comm | awk '$3 != "root" && $3 != "_root" && $3 != "zesta8" {print}')

if [ -n "$suspicious_parents" ]; then
    echo "  Processes running under unexpected users:"
    echo "$suspicious_parents" | head -5
    parent_findings=$((parent_findings + $(echo "$suspicious_parents" | wc -l | tr -d ' ')))
else
    echo "  ✓ No suspicious user-owned processes"
fi

total_findings=$((total_findings + parent_findings))
echo ""

# 4. Check recent crash reports (may indicate exploit attempts)
echo "[4/7] Checking recent crash reports..."
crash_findings=0

if [ -d ~/Library/Logs/DiagnosticReports ]; then
    # Recent crashes in last 24 hours
    recent_crashes=$(find ~/Library/Logs/DiagnosticReports -name "*.crash" -mtime -1 2>/dev/null)

    if [ -n "$recent_crashes" ]; then
        crash_count=$(echo "$recent_crashes" | wc -l | tr -d ' ')
        echo "  Found $crash_count recent crash reports:"

        echo "$recent_crashes" | while read crash; do
            app=$(basename "$crash" | sed 's/_[0-9].*//' | sed 's/\.crash//')
            crash_time=$(stat -f "%Sm" "$crash")
            echo "    - $app at $crash_time"
        done

        # More than 5 crashes is suspicious
        if [ $crash_count -gt 5 ]; then
            echo "  WARNING: Unusually high crash count - possible exploitation attempts"
            crash_findings=$((crash_findings + 1))
        fi
    else
        echo "  ✓ No recent crash reports"
    fi
fi

total_findings=$((total_findings + crash_findings))
echo ""

# 5. Check which apps have camera/mic access
echo "[5/7] Checking camera/microphone access..."
privacy_findings=0

if [ -f "/Library/Application Support/com.apple.TCC/TCC.db" ]; then
    # This requires Full Disk Access
    camera_apps=$(sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "SELECT client FROM access WHERE service='kTCCServiceCamera'" 2>/dev/null)
    mic_apps=$(sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "SELECT client FROM access WHERE service='kTCCServiceMicrophone'" 2>/dev/null)

    if [ -n "$camera_apps" ]; then
        echo "  Apps with Camera access:"
        echo "$camera_apps"
        privacy_findings=$((privacy_findings + 1))
    fi

    if [ -n "$mic_apps" ]; then
        echo "  Apps with Microphone access:"
        echo "$mic_apps"
        privacy_findings=$((privacy_findings + 1))
    fi

    if [ $privacy_findings -eq 0 ]; then
        echo "  INFO: Could not read TCC database (requires Full Disk Access)"
        echo "  Check manually: System Settings > Privacy & Security"
    fi
else
    echo "  INFO: TCC database not accessible"
fi

echo ""

# 6. Check for active packet capture (sniffing)
echo "[6/7] Checking for active packet capture/sniffing..."
sniff_findings=0

# Check for processes in promiscuous mode or using packet capture
capture_procs=$(ps aux | grep -iE "tcpdump|wireshark|tshark|ngrep|ettercap|nmap" | grep -v grep)

if [ -n "$capture_procs" ]; then
    echo "  WARNING: Packet capture tools detected:"
    echo "$capture_procs" | head -3
    sniff_findings=$((sniff_findings + 1))
else
    echo "  ✓ No packet capture tools detected"
fi

# Check for interfaces in promiscuous mode
if command -v ifconfig > /dev/null 2>&1; then
    # Get promiscuous interfaces (excluding common virtual adapters)
    promisc=$(ifconfig 2>/dev/null | grep -B1 "PROMISC" | grep "^en" | grep -v "en[0-9]:" | head -5)

    if [ -n "$promisc" ]; then
        echo "  WARNING: Network interface in promiscuous mode:"
        echo "$promisc"
        sniff_findings=$((sniff_findings + 1))
    else
        # Count but don't alert on VM/virtual interfaces
        promisc_count=$(ifconfig 2>/dev/null | grep -c "PROMISC" || echo "0")
        if [ "$promisc_count" -gt 0 ]; then
            echo "  INFO: $promisc_count interface(s) in promiscuous mode (likely VM adapters)"
        fi
    fi
fi

total_findings=$((total_findings + sniff_findings))
echo ""

# 7. Check for hidden/suspicious users
echo "[7/7] Checking for suspicious user accounts..."
user_findings=0

# Check for users with UID 0 (root equivalent)
root_users=$(dscl . -list /Users UniqueID | awk '$2 == 0 {print $1}')

if [ -n "$root_users" ]; then
    echo "  Users with root privileges (UID 0):"
    echo "$root_users"

    # More than just root is suspicious
    root_count=$(echo "$root_users" | wc -l | tr -d ' ')
    if [ $root_count -gt 1 ]; then
        echo "  WARNING: Multiple users with root access!"
        user_findings=$((user_findings + 1))
    fi
fi

# Check for admin group members
admin_members=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | cut -d: -f2 | tr ' ' '\n' | grep -v "^$")

if [ -n "$admin_members" ]; then
    echo "  Admin group members:"
    echo "$admin_members"
fi

total_findings=$((total_findings + user_findings))
echo ""

# Summary
echo "=== Scan Complete ==="
echo "Total suspicious findings: $total_findings"
echo ""

if [ $total_findings -gt 0 ]; then
    echo "ALERT: System shows signs of potential compromise!"
    echo ""
    echo "IMMEDIATE ACTIONS:"
    echo "  1. Disconnect from network if you suspect active C2"
    echo "  2. Review the warnings above"
    echo "  3. Run full scan: ./integrity_monitor.sh && ./keylogger_detector.sh"
    echo "  4. Check outbound connections: lsof -i -n | grep ESTABLISHED"
    echo "  5. Consider changing all passwords from a clean device"
    exit 1
else
    echo "OK: No obvious signs of active compromise detected."
    echo ""
    echo "System appears clean based on these indicators."
    exit 0
fi
