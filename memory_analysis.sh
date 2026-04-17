#!/bin/bash
# Save as ~/bin/memory_analysis.sh

echo "=== Memory Analysis for Rootkits ==="

# Check for unusual memory mappings
ps aux | grep -v grep | while read line; do
    pid=$(echo $line | awk '{print $2}')
    process=$(echo $line | awk '{print $11}')
    
    # Skip system processes
    if echo $process | grep -qE "(kernel_task|launchd|kextd)"; then
        continue
    fi
    
    # Check memory mappings
    suspicious_mappings=$(sudo vmmap $pid 2>/dev/null | grep -iE "(rwx|executable|suspicious|temp|cache)" | wc -l)
    
    if [ "$suspicious_mappings" -gt 5 ]; then
        echo "SUSPICIOUS MEMORY PATTERNS in $process (PID: $pid)"
        sudo vmmap $pid 2>/dev/null | grep -iE "(rwx|executable)" | head -5
        echo ""
    fi
done
