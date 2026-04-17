#!/bin/bash
# Persistence Mechanism Detection Script
# Scans for malware persistence mechanisms on macOS

echo "=== Persistence Mechanism Detection ==="
echo "Scan started: $(date)"
echo ""

total_findings=0

# 1. Cron Jobs
echo "[1/8] Checking cron jobs..."
cron_findings=0

# User crontab
user_cron=$(crontab -l 2>/dev/null)
if [ -n "$user_cron" ]; then
    echo "  User crontab entries:"
    echo "$user_cron"
    # Check for suspicious patterns
    if echo "$user_cron" | grep -qE "(curl|wget|bash|sh|python|perl|ruby|nc|ncat|telnet)"; then
        echo "  WARNING: Cron contains suspicious commands (download/execute)"
        cron_findings=$((cron_findings + 1))
    fi
fi

# System crontab
if [ -f /etc/crontab ]; then
    echo "  System crontab:"
    cat /etc/crontab
fi

# Check /etc/cron.* directories
for cron_dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$cron_dir" ]; then
        echo "  Contents of $cron_dir:"
        ls -la "$cron_dir"
    fi
done

if [ $cron_findings -eq 0 ]; then
    echo "  OK: No suspicious cron entries detected"
else
    total_findings=$((total_findings + cron_findings))
fi
echo ""

# 2. DYLD Environment Variable Injection (dylib hijacking)
echo "[2/8] Checking for dylib injection via DYLD variables..."
dyld_findings=0

# Check all processes for DYLD_INSERT_LIBRARIES
dyld_inject=$(ps eww -ax | grep -o "DYLD_INSERT_LIBRARIES=[^ ]*" | cut -d= -f2 | sort -u)

if [ -n "$dyld_inject" ]; then
    echo "  WARNING: DYLD_INSERT_LIBRARIES detected in processes:"
    echo "$dyld_inject" | while read lib; do
        if [ -f "$lib" ]; then
            echo "    Library: $lib"
            ls -lh "$lib"
            dyld_findings=$((dyld_findings + 1))
        fi
    done
else
    echo "  OK: No DYLD injection detected"
fi

total_findings=$((total_findings + dyld_findings))
echo ""

# 3. Recently Modified System Binaries
echo "[3/8] Checking for recently modified system binaries..."
binary_findings=0

# Find binaries modified in last 7 days
modified_binaries=$(find /usr/bin /usr/sbin /bin /sbin -type f -mtime -7 2>/dev/null | head -20)

if [ -n "$modified_binaries" ]; then
    echo "  Recently modified system binaries (last 7 days):"
    echo "$modified_binaries" | while read binary; do
        ls -lh "$binary"
        # Check if signed by Apple
        if ! codesign -dv "$binary" 2>&1 | grep -q "Authority=Apple"; then
            echo "    WARNING: Binary not signed by Apple!"
            binary_findings=$((binary_findings + 1))
        fi
    done
else
    echo "  OK: No recently modified system binaries"
fi

total_findings=$((total_findings + binary_findings))
echo ""

# 4. Temp Directories for Executable Payloads
echo "[4/8] Checking temp directories for executables..."
temp_findings=0

# Check /tmp, /private/var/tmp, /private/var/folders for executables
for temp_dir in /tmp /private/var/tmp /private/var/folders; do
    if [ -d "$temp_dir" ]; then
        executables=$(find "$temp_dir" -type f -perm +111 -mtime -3 2>/dev/null | head -10)
        if [ -n "$executables" ]; then
            echo "  Executables found in $temp_dir:"
            echo "$executables" | while read exe; do
                ls -lh "$exe"
                temp_findings=$((temp_findings + 1))
            done
        fi
    fi
done

if [ $temp_findings -eq 0 ]; then
    echo "  OK: No executable payloads in temp directories"
fi

total_findings=$((total_findings + temp_findings))
echo ""

# 5. Hidden Network Listeners (non-Apple, unsigned)
echo "[5/8] Checking for hidden/suspicious network listeners..."
network_findings=0

# Get all listening processes
lsof -i -P -n 2>/dev/null | grep LISTEN | awk '{print $1, $9}' | sort -u | while read line; do
    proc=$(echo $line | awk '{print $1}')
    port=$(echo $line | awk '{print $2}' | cut -d: -f2)

    # Skip Apple processes
    if echo "$proc" | grep -qiE "(com.apple|kernel|launchd)"; then
        continue
    fi

    # Get PID
    pid=$(pgrep -x "$proc" | head -1)
    if [ -n "$pid" ]; then
        path=$(ps -p "$pid" -o executable= 2>/dev/null)
        if [ -n "$path" ] && [ -f "$path" ]; then
            # Check if unsigned
            if codesign -dv "$path" 2>&1 | grep -q "not signed"; then
                echo "  WARNING: UNSIGNED listener: $proc on $port"
                echo "    Path: $path"
                ls -lh "$path"
                network_findings=$((network_findings + 1))
            fi
        fi
    fi
done

if [ $network_findings -eq 0 ]; then
    echo "  OK: No suspicious unsigned listeners detected"
fi

total_findings=$((total_findings + network_findings))
echo ""

# 6. Login Items Persistence
echo "[6/8] Checking login items..."
login_findings=0

# Check for login items via osascript
login_items=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null)

if [ -n "$login_items" ] && [ "$login_items" != "" ]; then
    echo "  Login items found:"
    echo "$login_items" | tr ',' '\n' | while read item; do
        item=$(echo "$item" | xargs)
        echo "    - $item"
    done
else
    echo "  OK: No login items (or couldn't read)"
fi
echo ""

# 7. Check for Browser Extensions (potential spyware)
echo "[7/8] Checking for suspicious browser extensions..."
ext_findings=0

# Safari Extensions
if [ -d "$HOME/Library/Safari/Applications" ]; then
    echo "  Safari Extensions:"
    ls -la "$HOME/Library/Safari/Applications/" 2>/dev/null
fi

# Chrome Extensions
if [ -d "$HOME/Library/Application Support/Google/Chrome/Default/Extensions" ]; then
    echo "  Chrome Extensions (count):"
    find "$HOME/Library/Application Support/Google/Chrome/Default/Extensions" -maxdepth 1 -type d | wc -l
fi

# Firefox Extensions
if [ -d "$HOME/Library/Application Support/Firefox/Profiles" ]; then
    echo "  Firefox Extensions:"
    find "$HOME/Library/Application Support/Firefox/Profiles" -name "extensions" -type d
fi
echo ""

# 8. Check for Suspicious Parent Processes
echo "[8/8] Checking for suspicious parent-child process relationships..."
process_findings=0

# Look for processes with parent PID 1 (launchd) that aren't launch agents/daemons
# This could indicate manually started persistence
suspicious_children=$(ps -eo pid,ppid,user,comm | awk '$3 != "root" && $2 == 1 && $4 !~ /^(launchd|Terminal|iTunes|Spotlight)/ {print $0}')

if [ -n "$suspicious_children" ]; then
    echo "  WARNING: Non-root processes parented by launchd (manually started persistence?):"
    echo "$suspicious_children"
    process_findings=$((process_findings + 1))
else
    echo "  OK: No suspicious parent-child relationships detected"
fi

total_findings=$((total_findings + process_findings))
echo ""

# Summary
echo "=== Scan Complete ==="
echo "Total suspicious findings: $total_findings"
echo ""

if [ $total_findings -gt 0 ]; then
    echo "ALERT: Potential persistence mechanisms detected."
    echo "Review the warnings above and investigate suspicious items."
    exit 1
else
    echo "OK: No obvious persistence mechanisms detected."
    exit 0
fi
