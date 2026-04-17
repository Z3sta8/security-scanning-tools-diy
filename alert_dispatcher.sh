#!/bin/bash
# Real-Time Alert Dispatcher
# Checks for recent security findings and sends notifications

# Configuration
LOG_DIR="${LOG_DIR:-./logs}"
ALERT_LOG="$LOG_DIR/alerts.log"
ALERT_THRESHOLD="HIGH"
CHECK_INTERVAL_MINUTES=5

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Alert Dispatcher ==="
echo "Checking for security alerts..."
echo ""

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Function to send macOS notification
send_notification() {
    local title="$1"
    local message="$2"
    local sound="${3:-Blasso}"  # Default sound

    osascript -e "display notification \"$message\" with title \"$title\" sound name \"$sound\""
}

# Function to log alert
log_alert() {
    local severity="$1"
    local message="$2"

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$severity] $message" >> "$ALERT_LOG"
}

# Function to check for alerts in monitor log
check_monitor_log() {
    local monitor_log="$SCRIPT_DIR/logs/monitor.log"
    local alert_count=0

    if [ ! -f "$monitor_log" ]; then
        return 0
    fi

    # Get current time in minutes
    current_min=$(date +%s | awk '{print int($1/60)}')
    check_min=$((current_min - CHECK_INTERVAL_MINUTES))

    # Check for HIGH severity findings in the last N minutes
    recent_alerts=$(tail -n 500 "$monitor_log" | while read -r line; do
        # Extract timestamp and check if recent
        log_timestamp=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}')
        if [ -n "$log_timestamp" ]; then
            log_min=$(date -j -f "%Y-%m-%d %H:%M:%S" "$log_timestamp" "+%s" 2>/dev/null | awk '{print int($1/60)}')
            if [ -n "$log_min" ] && [ "$log_min" -ge "$check_min" ]; then
                # Check line contains HIGH severity
                if echo "$line" | grep -qiE "(HIGH|CRITICAL|VIOLATION|SUSPICIOUS|ALERT)"; then
                    echo "$line"
                fi
            fi
        fi
    done)

    if [ -n "$recent_alerts" ]; then
        alert_count=$(echo "$recent_alerts" | wc -l | tr -d ' ')

        # Get unique alert types
        alert_types=$(echo "$recent_alerts" | grep -oE "(file_modification|suspicious_process|network_anomaly|integrity_violation)" | sort -u)

        if [ $alert_count -gt 0 ]; then
            send_notification "🚨 Security Alert" "$alert_count HIGH severity findings detected in the last $CHECK_INTERVAL_MINUTES minutes" "Blasso"
            log_alert "HIGH" "Found $alert_count alerts: $alert_types"

            # Show summary
            echo "ALERT: $alert_count findings detected:"
            echo "$recent_alerts" | head -5
            if [ $(echo "$recent_alerts" | wc -l) -gt 5 ]; then
                echo "... and more"
            fi
        fi
    fi

    return $alert_count
}

# Function to check individual scan logs
check_scan_logs() {
    local alert_count=0

    # Check recent scan logs for findings
    for scan_log in "$LOG_DIR"/*_*.log; do
        if [ -f "$scan_log" ]; then
            # Only check logs modified in last CHECK_INTERVAL_MINUTES
            log_age=$(( $(date +%s) - $(stat -f "%m" "$scan_log") ))
            log_age_min=$((log_age / 60))

            if [ $log_age_min -le $CHECK_INTERVAL_MINUTES ]; then
                # Check for keywords
                findings=$(grep -iE "(WARNING|ERROR|VIOLATION|SUSPICIOUS|ALERT|threat)" "$scan_log" 2>/dev/null | tail -5)

                if [ -n "$findings" ]; then
                    alert_count=$((alert_count + $(echo "$findings" | wc -l | tr -d ' ')))
                    scan_name=$(basename "$scan_log" | sed 's/_[0-9].*//')

                    send_notification "⚠️ Scan Alert: $scan_name" "Findings detected in recent scan" "Blasso"
                    log_alert "MEDIUM" "Scan $scan_name found issues"

                    echo "Alert from $scan_name:"
                    echo "$findings" | head -3
                fi
            fi
        fi
    done

    return $alert_count
}

# Function to check system-level indicators
check_system_indicators() {
    local alert_count=0

    # Check for unsigned processes with network connections
    unsigned_net=$(lsof -i -P -n 2>/dev/null | grep ESTABLISHED | awk '{print $1}' | sort -u | while read proc; do
        pid=$(pgrep -x "$proc" | head -1)
        if [ -n "$pid" ]; then
            path=$(ps -p "$pid" -o executable= 2>/dev/null)
            if [ -n "$path" ] && [ -f "$path" ]; then
                if codesign -dv "$path" 2>&1 | grep -q "not signed"; then
                    echo "$proc ($path)"
                fi
            fi
        fi
    done)

    if [ -n "$unsigned_net" ]; then
        alert_count=$((alert_count + $(echo "$unsigned_net" | wc -l | tr -d ' ')))
        send_notification "⚠️ Unsigned Network Activity" "Unsigned processes with network connections detected" "Blasso"
        log_alert "MEDIUM" "Unsigned processes with network: $unsigned_net"
        echo "WARNING: Unsigned processes with network connections:"
        echo "$unsigned_net" | head -3
    fi

    return $alert_count
}

# Function to send external notifications (optional)
send_external_alert() {
    local severity="$1"
    local message="$2"

    # Pushover notification (if configured)
    if [ -n "$PUSHOVER_TOKEN" ] && [ -n "$PUSHOVER_USER" ]; then
        curl -s "https://api.pushover.net/1/messages.json" \
            -d "token=$PUSHOVER_TOKEN" \
            -d "user=$PUSHOVER_USER" \
            -d "message=$message" \
            -d "title=Security Alert [$severity]" \
            -d "priority=1" > /dev/null 2>&1
    fi

    # Telegram notification (if configured)
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        curl -s "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
            -d "chat_id=$TELEGRAM_CHAT_ID" \
            -d "text=🚨 Security Alert [$severity]: $message" > /dev/null 2>&1
    fi

    # Slack webhook (if configured)
    if [ -n "$SLACK_WEBHOOK_URL" ]; then
        curl -s -X POST "$SLACK_WEBHOOK_URL" \
            -H 'Content-Type: application/json' \
            -d "{\"text\":\"🚨 Security Alert [$severity]: $message\"}" > /dev/null 2>&1
    fi
}

# Run all checks
echo "Checking monitor log..."
check_monitor_log
monitor_status=$?

echo ""
echo "Checking scan logs..."
check_scan_logs
scan_status=$?

echo ""
echo "Checking system indicators..."
check_system_indicators
system_status=$?

# Total alerts
total_alerts=$((monitor_status + scan_status + system_status))

echo ""
echo "=== Alert Check Complete ==="

if [ $total_alerts -gt 0 ]; then
    echo "Total alerts found: $total_alerts"
    echo "Alerts logged to: $ALERT_LOG"

    # Send external notification if configured
    send_external_alert "HIGH" "$total_alerts security alerts detected on $(hostname)"

    exit 1
else
    echo "No new alerts detected in the last $CHECK_INTERVAL_MINUTES minutes"
    exit 0
fi
