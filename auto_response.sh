#!/bin/bash
# Automated Incident Response Script
# Takes automated actions when threats are detected

THREAT_TYPE="$1"
THREAT_DETAILS="$2"
LOG_DIR="${LOG_DIR:-./logs}"
RESPONSE_LOG="$LOG_DIR/auto_response.log"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Function to log actions
log_action() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$RESPONSE_LOG"
    echo "$message"
}

# Function to verify action before executing
confirm_action() {
    local action="$1"
    log_action "ACTION PROPOSED: $action"

    # In automated mode, skip confirmation
    if [ "$AUTO_RESPONSE" = "true" ]; then
        return 0
    fi

    # Otherwise, ask for confirmation
    read -p "Execute this action? (y/n): " answer
    if [ "$answer" = "y" ]; then
        return 0
    else
        log_action "ACTION CANCELLED by user"
        return 1
    fi
}

# Function to kill process by name or PID
kill_malicious_process() {
    local identifier="$1"  # Can be PID or process name

    log_action "Attempting to terminate process: $identifier"

    # Check if it's a PID or name
    if [[ "$identifier" =~ ^[0-9]+$ ]]; then
        # It's a PID
        if kill -0 "$identifier" 2>/dev/null; then
            if confirm_action "Kill PID $identifier"; then
                # Try graceful kill first
                kill "$identifier"
                sleep 2
                # If still running, force kill
                if kill -0 "$identifier" 2>/dev/null; then
                    kill -9 "$identifier"
                    log_action "Force killed PID: $identifier"
                else
                    log_action "Terminated PID: $identifier"
                fi
            fi
        else
            log_action "ERROR: PID $identifier not found"
            return 1
        fi
    else
        # It's a process name
        pids=$(pgrep -x "$identifier")
        if [ -n "$pids" ]; then
            echo "$pids" | while read pid; do
                kill_malicious_process "$pid"
            done
        else
            log_action "ERROR: No process found matching: $identifier"
            return 1
        fi
    fi
}

# Function to quarantine a file
quarantine_file() {
    local file_path="$1"
    local quarantine_dir="$HOME/.quarantine"

    log_action "Quarantining file: $file_path"

    if [ ! -f "$file_path" ]; then
        log_action "ERROR: File not found: $file_path"
        return 1
    fi

    # Create quarantine directory
    mkdir -p "$quarantine_dir"

    # Generate quarantine filename
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local filename=$(basename "$file_path")
    local quarantine_path="$quarantine_dir/${timestamp}_${filename}"

    if confirm_action "Move $file_path to quarantine"; then
        # Move file to quarantine
        mv "$file_path" "$quarantine_path"
        # Remove execute permissions
        chmod -x "$quarantine_path"
        log_action "Quarantined: $file_path -> $quarantine_path"
    fi
}

# Function to block network connection (using pfctl)
block_network_connection() {
    local ip_address="$1"

    log_action "Attempting to block IP: $ip_address"

    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        log_action "ERROR: Root privileges required for firewall rules"
        log_action "Run with sudo to enable this feature"
        return 1
    fi

    if confirm_action "Block IP address $ip_address in firewall"; then
        # Add to pf table
        echo "table <bad_hosts> persist" | pfctl -f - 2>/dev/null
        echo "table <bad_hosts> add $ip_address" | pfctl -f - 2>/dev/null

        # Check if successful
        if pfctl -t bad_hosts -T show 2>/dev/null | grep -q "$ip_address"; then
            log_action "Blocked IP: $ip_address"
        else
            log_action "ERROR: Failed to block IP: $ip_address"
            return 1
        fi
    fi
}

# Function to disable network interface
disable_network() {
    local interface="${1:-en0}"  # Default to en0

    log_action "Attempting to disable network interface: $interface"

    if [ "$EUID" -ne 0 ]; then
        log_action "ERROR: Root privileges required"
        return 1
    fi

    if confirm_action "Disable network interface $interface (DANGEROUS!)"; then
        ifconfig "$interface" down
        log_action "DISABLED network interface: $interface"
        log_action "WARNING: System is now isolated from network"
    fi
}

# Function to reset DNS to safe values
reset_dns() {
    local interface="${1:-Wi-Fi}"

    log_action "Resetting DNS for interface: $interface"

    if [ "$EUID" -ne 0 ]; then
        log_action "ERROR: Root privileges required"
        return 1
    fi

    if confirm_action "Reset DNS to Cloudflare (1.1.1.1, 1.0.0.1)"; then
        networksetup -setdnsservers "$interface" 1.1.1.1 1.0.0.1
        log_action "DNS reset to safe values"
    fi
}

# Function to kill all processes by user
kill_user_processes() {
    local target_user="$1"

    log_action "Attempting to kill all processes for user: $target_user"

    if [ "$EUID" -ne 0 ]; then
        log_action "ERROR: Root privileges required"
        return 1
    fi

    if confirm_action "Kill ALL processes for user $target_user"; then
        pkill -u "$target_user"
        log_action "Killed all processes for user: $target_user"
    fi
}

# Function to create system snapshot for forensics
create_snapshot() {
    local snapshot_dir="$LOG_DIR/snapshot_$(date +%Y%m%d_%H%M%S)"

    log_action "Creating system snapshot in: $snapshot_dir"
    mkdir -p "$snapshot_dir"

    # Save running processes
    ps aux > "$snapshot_dir/processes.txt"
    log_action "Saved process list"

    # Save network connections
    lsof -i -P -n > "$snapshot_dir/network_connections.txt"
    log_action "Saved network connections"

    # Save open files
    lsof > "$snapshot_dir/open_files.txt"
    log_action "Saved open files list"

    # Save mount points
    mount > "$snapshot_dir/mount_points.txt"
    log_action "Saved mount points"

    # Save recent logs
    if [ -d /var/log ]; then
        tail -n 100 /var/log/system.log > "$snapshot_dir/system.log" 2>/dev/null
        tail -n 100 /var/log/install.log > "$snapshot_dir/install.log" 2>/dev/null
    fi

    # Save launch agents/daemons
    find ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons -name "*.plist" > "$snapshot_dir/launch_items.txt" 2>/dev/null
    log_action "Saved launch items list"

    log_action "Snapshot complete: $snapshot_dir"
}

# Main response handler based on threat type
case "$THREAT_TYPE" in
    "suspicious_process"|"malware")
        log_action "THREAT: Suspicious process detected - $THREAT_DETAILS"
        # Extract PID from details if provided
        if echo "$THREAT_DETAILS" | grep -qE "PID:[0-9]+"; then
            pid=$(echo "$THREAT_DETAILS" | grep -oE "PID:[0-9]+" | cut -d: -f2)
            kill_malicious_process "$pid"
        else
            # Try to extract process name
            proc_name=$(echo "$THREAT_DETAILS" | grep -oE "process: [a-zA-Z0-9_-]+" | cut -d' ' -f2)
            kill_malicious_process "$proc_name"
        fi
        create_snapshot
        ;;

    "suspicious_network"|"c2_connection")
        log_action "THREAT: Suspicious network activity - $THREAT_DETAILS"
        # Extract IP from details
        if echo "$THREAT_DETAILS" | grep -qE "IP:[0-9.]+"; then
            ip=$(echo "$THREAT_DETAILS" | grep -oE "IP:[0-9.]+" | cut -d: -f2)
            block_network_connection "$ip"
        fi
        ;;

    "dns_hijack")
        log_action "THREAT: DNS hijacking detected - $THREAT_DETAILS"
        reset_dns "Wi-Fi"
        ;;

    "file_modification"|"integrity_violation")
        log_action "THREAT: File integrity violation - $THREAT_DETAILS"
        # Extract file path from details
        if echo "$THREAT_DETAILS" | grep -qE "path:.*"; then
            file_path=$(echo "$THREAT_DETAILS" | grep -oE "path:.*" | cut -d: -f2- | xargs)
            quarantine_file "$file_path"
        fi
        create_snapshot
        ;;

    "active_compromise"|"emergency")
        log_action "THREAT: ACTIVE COMPROMISE - $THREAT_DETAILS"
        log_action "EMERGENCY PROTOCOLS INITIATED"

        # Create snapshot first
        create_snapshot

        # Ask for confirmation before taking drastic action
        echo "=== EMERGENCY RESPONSE REQUIRED ==="
        echo "System shows signs of active compromise."
        echo ""
        echo "Available actions:"
        echo "  1) Disable network (isolate system)"
        echo "  2) Kill suspicious process"
        echo "  3) Quarantine malicious file"
        echo "  4) Take snapshot only (manual investigation)"
        echo ""
        read -p "Choose action (1-4): " choice

        case "$choice" in
            1) disable_network "en0" ;;
            2) read -p "Enter process name/PID: " proc; kill_malicious_process "$proc" ;;
            3) read -p "Enter file path: " file; quarantine_file "$file" ;;
            4) log_action "Manual investigation chosen - snapshot taken" ;;
        esac
        ;;

    *)
        log_action "UNKNOWN threat type: $THREAT_TYPE"
        log_action "Details: $THREAT_DETAILS"
        echo "Unknown threat type. Manual intervention required."
        exit 1
        ;;
esac

log_action "Response actions complete"
exit 0
