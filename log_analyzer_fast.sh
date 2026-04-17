#!/bin/bash
# Ultra-fast log analyzer - no log show command
# Uses only local file analysis for speed

echo "=== Security Log Analysis (Fast Mode) ==="

# Check auth logs if available
if [ -f /var/log/auth.log ]; then
    echo "Checking authentication logs..."
    auth_fails=$(tail -100 /var/log/auth.log | grep -i "failed" | wc -l | tr -d ' ')
    echo "Found $auth_fails failed authentication attempts"
elif [ -d /private/var/log/asl ]; then
    echo "Checking ASL logs..."
    auth_fails=$(strings /private/var/log/asl/*.asl 2>/dev/null | grep -iE "authentication|failed|denied" | tail -10 | wc -l | tr -d ' ')
    echo "Found $auth_fails potential auth issues"
else
    echo "No accessible auth logs"
fi

# Check for recent sudo usage via lastcomm if available
if command -v last &> /dev/null; then
    echo "Checking recent user logins..."
    recent_logins=$(last -10 2>/dev/null | head -5 | wc -l | tr -d ' ')
    echo "Recent login sessions: $recent_logins"
fi

# Check process list for suspicious activity
echo "Checking running processes..."
suspicious_procs=$(ps aux | grep -iE "nc|netcat|nmap|tcpdump|wireshark" | grep -v grep | wc -l | tr -d ' ')
if [ "$suspicious_procs" -gt 0 ]; then
    echo "WARNING: Found $suspicious_procs potentially suspicious processes"
    ps aux | grep -iE "nc|netcat|nmap|tcpdump|wireshark" | grep -v grep | head -3
else
    echo "No suspicious processes detected"
fi

# Check for unusual network connections
echo "Checking network connections..."
established_connections=$(lsof -i -P -n 2>/dev/null | grep ESTABLISHED | wc -l | tr -d ' ')
echo "Active connections: $established_connections"

# Check for suspicious open ports (C2, backdoors, etc.)
echo "Checking for suspicious open ports..."
# Common C2/backdoor ports
BAD_PORTS=(4444 5555 6666 31337 12345 12346 1337 443 8443 9999 10000 10001 10002 1433 1434 3306 3389 5432 5900 8080 8443 9200 27017)
port_findings=0

for port in "${BAD_PORTS[@]}"; do
    listener=$(lsof -i ":$port" 2>/dev/null | grep LISTEN)
    if [ -n "$listener" ]; then
        proc=$(echo "$listener" | awk 'NR==1 {print $1}')
        pid=$(echo "$listener" | awk 'NR==1 {print $2}')
        echo "  WARNING: Process listening on suspicious port $port:"
        echo "    $listener"
        port_findings=$((port_findings + 1))

        # Get process details
        if [ -n "$pid" ]; then
            path=$(ps -p "$pid" -o executable= 2>/dev/null)
            if [ -n "$path" ]; then
                echo "    Executable: $path"
                ls -lh "$path"
            fi
        fi
    fi
done

if [ $port_findings -eq 0 ]; then
    echo "  OK: No suspicious port listeners detected"
fi

# Check disk usage (could indicate log flooding)
echo "Checking disk usage..."
log_size=$(du -sh /var/log 2>/dev/null | awk '{print $1}')
echo "Log directory size: ${log_size:-unknown}"

# Check for recent crashes
echo "Checking crash reports..."
if [ -d ~/Library/Logs/DiagnosticReports ]; then
    recent_crashes=$(find ~/Library/Logs/DiagnosticReports -name "*.crash" -mtime -1 2>/dev/null | wc -l | tr -d ' ')
    if [ "$recent_crashes" -gt 0 ]; then
        echo "WARNING: Found $recent_crashes recent crash reports"
    else
        echo "No recent crash reports"
    fi
fi

echo ""
echo "Fast log analysis completed in seconds"
