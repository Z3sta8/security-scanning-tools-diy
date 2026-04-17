# Create a comprehensive monitoring script
#!/bin/bash
# Save as ~/bin/deep_monitor.sh

# Function to get process details
get_process_context() {
    local pid=$1
    echo "=== Process Context for PID $pid ==="
    ps -p $pid -o pid,ppid,user,args
    echo "Network connections:"
    lsof -i -P -n -p $pid 2>/dev/null
    echo "Open files:"
    lsof -p $pid 2>/dev/null | head -10
    echo "Working directory:"
    lsof -p $pid | grep cwd 2>/dev/null
    echo ""
}

# Monitor new processes
sudo fs_usage -w -f exec | while read line; do
    if echo $line | grep -q "exec"; then
        pid=$(echo $line | awk '{print $6}')
        process_name=$(echo $line | awk '{print $NF}')
        
        # Filter out known good processes
        if ! echo $process_name | grep -qE "(kernel_task|launchd|mdworker|UserEventAgent)"; then
            echo "NEW PROCESS DETECTED: $process_name (PID: $pid)"
            get_process_context $pid
        fi
    fi
done
