#!/bin/bash
# Advanced Threat Detection Script
# Enhanced version with comprehensive threat detection capabilities

# Enable strict error handling
set -euo pipefail

# Configuration
THRESHOLD="${THRESHOLD:-5}"
LOG_DIR="${LOG_DIR:-./logs}"
MAX_LOG_SIZE="${MAX_LOG_SIZE:-10485760}" # 10MB

# Initialize logging
init_logging() {
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/threat_detection_$(date +%Y%m%d_%H%M%S).log"
    exec > >(tee -a "$LOG_FILE")
    exec 2>&1

    echo "=== Advanced Threat Detection Started ==="
    echo "Timestamp: $(date)"
    echo "Configuration Threshold: $THRESHOLD"
    echo "Max Log Size: $MAX_LOG_SIZE bytes"
    echo "Log Directory: $LOG_DIR"
    echo ""
}

# Check and rotate logs
rotate_logs() {
    if [ -f "$LOG_FILE" ] && [ $(stat -f%z "$LOG_FILE") -gt $MAX_LOG_SIZE ]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
        echo "Log file rotated: $(date)"
    fi
}

# Enhanced process monitoring
monitor_processes() {
    echo "[1/8] Advanced Process Monitoring..."

    # Get recent processes
    echo "  Analyzing running processes..."

    # Check for suspicious parent-child relationships
    suspicious_pids=$(ps -eo pid,ppid,comm | awk -v threshold=$THRESHOLD '
        NR > 1 {
            parent=$2
            if(parent > 1000 && parent < 20000) {
                cmdlines[parent] = cmdlines[parent] " " $3
            }
        }
        END {
            for(pid in cmdlines) {
                gsub(/[^a-zA-Z0-9]/, " ", cmdlines[pid])
                count = split(cmdlines[pid], arr)
                if(count > threshold) {
                    print pid
                }
            }
        }'
    )

    if [ -n "$suspicious_pids" ]; then
        echo "  WARNING: Suspicious process trees detected:"
        echo "$suspicious_pids" | while read pid; do
            ps -p "$pid" -o pid,ppid,cmd,etime | grep -v PID || echo "  Could not process PID: $pid"
        done
    else
        echo "  OK: No unusual process trees detected"
    fi
    echo ""

    # Check for hidden processes
    echo "  Checking for hidden processes..."
    hidden_processes=$(ps -ef | grep -v grep | awk '$1 !~ /^[0-9]+$/{print $1}' || true)

    if [ -n "$hidden_processes" ]; then
        echo "  WARNING: Possible hidden processes found:"
        echo "$hidden_processes" | sort | uniq | while process do
            echo "    $process"
        done
    else
        echo "  OK: No hidden processes detected"
    fi
    echo ""

    # Check for processes with high CPU usage
    echo "  Checking high CPU usage processes..."
    cpu_processes=$(top -l 1 -o cpu | head -n 15 | tail -n +6 | awk '{print $2, $1, $11}' || true)

    total_cpu=0
    while read -r pid cpu cmd; do
        # Skip system processes
        if [[ $cpu =~ ^[0-9]+\.[0-9]+$ ]] && (( $(echo "$cpu > 50.0" | bc -l) )); then
            echo "  WARNING: High CPU usage - PID $pid: $cpu% $cmd"
            total_cpu=$(echo "$total_cpu + $cpu" | bc -l)
        fi
    done <<< "$cpu_processes"

    if (( $(echo "$total_cpu > 100" | bc -l) )); then
        echo "  ALERT: Total CPU usage exceeds threshold: $total_cpu%"
    else
        echo "  OK: CPU usage within normal range"
    fi
}

# Enhanced network monitoring
monitor_network() {
    echo "[2/8] Advanced Network Monitoring..."

    # Check for suspicious connections
    echo "  Analyzing network connections..."

    # Get established connections
    established_connections=$(lsof -i -P -n | grep ESTABLISHED || true)
    connection_count=$(echo "$established_connections" | wc -l | awk '{print $1}' || echo 0)

    if [ "$connection_count" -gt 100 ]; then
        echo "  WARNING: High number of established connections: $connection_count"

        # Find top remote IPs
        echo "  Top remote connections:"
        echo "$established_connections" | awk '{print $9}' | awk -F: '{print $1}' | sort | uniq -c | sort -nr | head -10
    else
        echo "  OK: Normal connection count: $connection_count"
    fi
    echo ""

    # Check for listening ports
    echo "  Checking listening ports..."
    listening_ports=$(lsof -i -P -n | grep LISTEN || true)
    listening_count=$(echo "$listening_ports" | wc -l | awk '{print $1}' || echo 0)

    if [ "$listening_count" -gt 20 ]; then
        echo "  WARNING: High number of listening ports: $listening_count"
        echo "  Listening ports:"
        echo "$listening_ports" | awk '{print $1, $9}' | sort | uniq
    else
        echo "  OK: Normal listening port count: $listening_count"
    fi
    echo ""

    # Check for unusual outbound connections
    echo "  Checking for unusual outbound connections..."

    # Get recent network traffic
    recent_traffic=$(netstat -i | tail -n +3 | awk '{print $1, $3, $4, $6, $9}' || true)

    while read -r interface rx tx coll drop errs; do
        if [[ "$tx" =~ ^[0-9]+$ ]] && [ "$tx" -gt 1000000 ]; then
            echo "  WARNING: High TX traffic on $interface: $tx bytes"
        fi
        if [[ "$rx" =~ ^[0-9]+$ ]] && [ "$rx" -gt 1000000 ]; then
            echo "  WARNING: High RX traffic on $interface: $rx bytes"
        fi
    done <<< "$recent_traffic"

    # Check for DNS queries
    echo "  Checking DNS query patterns..."
    dns_server=$(networksetup -getdnsservers Wi-Fi 2>/dev/null | head -1 || echo "8.8.8.8")
    echo "  Current DNS server: $dns_server"

    if [[ "$dns_server" =~ 127\.0\.0\.1|localhost ]]; then
        echo "  WARNING: Using localhost DNS - possible DNS hijacking"
    fi
}

# Enhanced file system monitoring
monitor_filesystem() {
    echo "[3/8] Advanced File System Monitoring..."

    # Check for recently modified system files
    echo "  Checking recently modified system files..."
    recent_modifications=$(find /Library/Preferences /Library/Application Support -name "*.plist" -type f -mtime -7 -exec ls -la {} \; 2>/dev/null || true)

    if [ -n "$recent_modifications" ]; then
        echo "  WARNING: Recently modified system files:"
        echo "$recent_modifications" | head -10
    else
        echo "  OK: No recent system file modifications"
    fi
    echo ""

    # Check for suspicious files
    echo "  Checking for suspicious files..."
    suspicious_locations=(
        "/tmp"
        "/var/tmp"
        "/private/var/tmp"
        "/Library/ScriptingAdditions"
        "~/.local"
        "/Library/Application Support"
    )

    for location in "${suspicious_locations[@]}";
    do
        expanded_location="${location/#\~/$HOME}"
        if [ -d "$expanded_location" ]; then
            echo "  Checking: $expanded_location"

            # Find executable files
            executable_files=$(find "$expanded_location" -type f -perm +111 -mtime -7 2>/dev/null || true)
            if [ -n "$executable_files" ]; then
                echo "    Found executable files:"
                echo "$executable_files" | head -5
                echo "    (Show first 5, total: $(echo "$executable_files" | wc -l))"
            fi

            # Find recently created files
            recent_files=$(find "$expanded_location" -type f -mtime -3 -name "*.sh" -o -name "*.py" -o -name "*.app" 2>/dev/null || true)
            if [ -n "$recent_files" ]; then
                echo "    WARNING: Recently created scripts/apps:"
                echo "$recent_files" | head -3
            fi
        fi
    done

    echo ""
    echo "  OK: File system scan complete"
}

# Enhanced memory analysis
analyze_memory() {
    echo "[4/8] Advanced Memory Analysis..."

    # Check system memory usage
    memory_info=$(vm_stat | grep -E "(free|active|inactive|wired)" || true)
    echo "  Memory Information:"
    echo "$memory_info" | while read -r line; do
        echo "    $line"
    done

    # Check for memory-heavy processes
    echo "  Memory-intensive processes:"
    ps -e -o pid,ppid,pcpu,pmem,comm,etime | grep -v PID | sort -nr -k4 | head -10 | while read pid pcpu pmem comm etime; do
        if (( $(echo "$pmem > 5.0" | bc -l) )); then
            echo "    PID $pid: ${pmem}% memory - $comm (running $etime)"
        fi
    done

    # Check for memory dump analysis (if available)
    if command -v vmmap >/dev/null 2>&1; then
        echo "  Checking memory regions (sample)..."
        vmmap 1 2>/dev/null | grep -E "(mapped|region)" | head -10
    fi
}

# Enhanced persistence detection
detect_persistence() {
    echo "[5/8] Persistence Detection..."

    # Check LaunchDaemons
    echo "  Checking LaunchDaemons..."
    daemon_count=$(find /Library/LaunchDaemons -name "*.plist" 2>/dev/null | wc -l || echo 0)
    echo "    Found $daemon_count LaunchDaemons"

    # Check LaunchAgents
    echo "  Checking LaunchAgents..."
    agent_count=$(find ~/Library/LaunchAgents -name "*.plist" 2>/dev/null | wc -l || echo 0)
    echo "    Found $agent_count LaunchAgents"

    # Check login items
    echo "  Checking login items..."
    if osascript -e 'tell application "System Events" to get the name of every login item' >/dev/null 2>&1; then
        login_items=$(osascript -e 'tell application "System Events" to get the name of every login item')
        if [ -n "$login_items" ]; then
            echo "    Login items:"
            echo "$login_items" | while read item; do
                echo "      - $item"
            done
        else
            echo "    No login items found"
        fi
    fi

    # Check cron jobs
    echo "  Checking cron jobs..."
    crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" || echo "    No user cron jobs found"

    # Check for startup scripts
    startup_dirs=(
        "/etc/profile.d"
        "/etc/launchd.conf"
        "~/.bashrc"
        "~/.zshrc"
        "~/.profile"
    )

    for dir in "${startup_dirs[@]}"; do
        expanded_dir="${dir/#\~/$HOME}"
        if [ -f "$expanded_dir" ]; then
            echo "    Found startup file: $expanded_dir"
        fi
    done
}

# Advanced network traffic analysis
analyze_network_traffic() {
    echo "[6/8] Network Traffic Analysis..."

    # Check for unusual TCP/UDP traffic
    echo "  Checking protocol distribution..."
    protocol_stats=$(netstat -an | awk '/^tcp|^udp/ {print $1}' | sort | uniq -c | sort -nr || true)
    echo "$protocol_stats" | while read count proto; do
        echo "    $count $proto connections"
    done

    # Check for failed connections
    failed_connections=$(netstat -an | grep -E "TIME_WAIT|CLOSE_WAIT" | wc -l || echo 0)
    if [ "$failed_connections" -gt 50 ]; then
        echo "  WARNING: High number of failed connections: $failed_connections"
    else
        echo "  OK: Normal failed connection count: $failed_connections"
    fi

    # Check for SYN flood
    syn_count=$(netstat -an | grep SYN | wc -l || echo 0)
    if [ "$syn_count" -gt 100 ]; then
        echo "  WARNING: High SYN count possible flood: $syn_count"
    else
        echo "  OK: Normal SYN count: $syn_count"
    fi

    # Check for established connections by state
    echo "  Connection states:"
    states=$(netstat -an | awk '/^tcp/ {print $6}' | sort | uniq -c | sort -nr || true)
    echo "$states" | while read count state; do
        echo "    $count connections in $state state"
    done
}

# Enhanced security checks
security_checks() {
    echo "[7/8] Security Configuration Checks..."

    # Check system updates
    echo "  Checking system updates..."
    if command -v softwareupdate >/dev/null 2>&1; then
        softwareupdate --list 2>/dev/null | grep -i "available" | head -5 || echo "  System appears up to date"
    fi

    # Check file system permissions
    echo "  Checking critical file permissions..."
    critical_files=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/sudoers"
        "/etc/hosts"
        "/etc/hosts.allow"
        "/etc/hosts.deny"
    )

    for file in "${critical_files[@]}"; do
        if [ -f "$file" ]; then
            perm=$(stat -f "%A" "$file" 2>/dev/null || echo "UNKNOWN")
            owner=$(stat -f "%Su" "$file" 2>/dev/null || echo "UNKNOWN")
            echo "    $file: $perm ($owner)"
        fi
    done

    # Check for unauthorized SSH keys
    echo "  Checking SSH keys..."
    ssh_dir="$HOME/.ssh"
    if [ -d "$ssh_dir" ]; then
        ssh_keys=$(find "$ssh_dir" -name "id_*" -type f 2>/dev/null | wc -l)
        echo "    Found $ssh_keys SSH key(s)"

        # Check for world-readable private keys
        for key in "$ssh_dir"/id_*; do
            if [ -f "$key" ] && [ "$(stat -f "%A" "$key" 2>/dev/null)" != "600" ]; then
                echo "    WARNING: World-readable private key: $key"
            fi
        done
    fi

    # Check for root processes
    echo "  Checking for root processes..."
    root_processes=$(ps -U root -o pid,comm 2>/dev/null | grep -v PID || true)
    if [ -n "$root_processes" ]; then
        echo "    Root processes found:"
        echo "$root_processes" | while read pid comm; do
            echo "      PID $pid: $comm"
        done
    else
        echo "    No root processes found"
    fi
}

# Cleanup and reporting
cleanup_and_report() {
    echo "[8/8] Generating Report..."

    # Rotate logs
    rotate_logs

    # Generate summary
    echo ""
    echo "=== THREAT DETECTION SUMMARY ==="
    echo "Start Time: $(date -r $1)"
    echo "End Time: $(date)"
    echo "Duration: $(( ($(date +%s) - $1) / 60 )) minutes"
    echo ""
    echo "Logs saved to: $LOG_FILE"
    echo ""
    echo "Please review the warnings above and take appropriate action."
    echo "For detailed analysis, check the log file: $LOG_FILE"

    # Check if any warnings were generated
    warning_count=$(grep -i "WARNING\|ALERT" "$LOG_FILE" | wc -l || echo 0)
    if [ "$warning_count" -gt 0 ]; then
        echo ""
        echo "!!! SECURITY ALERT !!!"
        echo "Found $warning_count security warnings requiring attention."
        exit 1
    else
        echo "No critical security issues detected."
        exit 0
    fi
}

# Main execution
main() {
    start_time=$(date +%s)

    # Initialize
    init_logging

    # Run detection modules
    monitor_processes
    monitor_network
    monitor_filesystem
    analyze_memory
    detect_persistence
    analyze_network_traffic
    security_checks

    # Cleanup and report
    cleanup_and_report "$start_time"
}

# Handle script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi