#!/bin/bash
# Save as ~/bin/network_anomaly_detector.sh

BASELINE_FILE="$HOME/.security/network_baseline.txt"
ALERT_FILE="$HOME/.security/network_alerts.txt"

# Create baseline if it doesn't exist
if [ ! -f "$BASELINE_FILE" ]; then
    echo "Creating network baseline..."
    mkdir -p "$HOME/.security"
    
    # Capture 5 minutes of normal network activity
    for i in {1..5}; do
        lsof -i -P -n | grep ESTABLISHED | awk '{print $1, $9}' >> "$BASELINE_FILE"
        sleep 60
    done
    
    # Process baseline
    sort "$BASELINE_FILE" | uniq -c | sort -nr > "${BASELINE_FILE}.processed"
    echo "Baseline created. Run again to start monitoring."
    exit 0
fi

# Monitor for anomalies
while true; do
    current_connections=$(lsof -i -P -n | grep ESTABLISHED | awk '{print $1, $9}')
    
    echo "$current_connections" | while read line; do
        if [ ! -z "$line" ]; then
            # Check if this connection pattern exists in baseline
            if ! grep -q "$line" "$BASELINE_FILE"; then
                echo "$(date): ANOMALY DETECTED: $line" >> "$ALERT_FILE"
                echo "NETWORK ANOMALY: $line"
                
                # Get process details
                process=$(echo $line | awk '{print $1}')
                pid=$(pgrep "$process" | head -1)
                if [ ! -z "$pid" ]; then
                    echo "Process details:"
                    ps -p $pid -o pid,ppid,user,args
                    echo "All connections for this process:"
                    lsof -i -P -n -p $pid
                fi
            fi
        fi
    done
    
    sleep 30
done
