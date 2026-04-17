#!/bin/bash
# Save as ~/bin/integrity_monitor.sh

INTEGRITY_DB="$HOME/.security/integrity.db"
CRITICAL_PATHS=(
    "/usr/bin"
    "/usr/sbin"
    "/bin"
    "/sbin"
    "/System/Library/LaunchDaemons"
    "/Library/LaunchDaemons"
    "/Library/LaunchAgents"
    "/etc"
)

# Initialize database
if [ ! -f "$INTEGRITY_DB" ]; then
    echo "Creating integrity database..."
    mkdir -p "$HOME/.security"
    
    for path in "${CRITICAL_PATHS[@]}"; do
        if [ -d "$path" ]; then
            find "$path" -type f -exec shasum {} \; >> "$INTEGRITY_DB"
        fi
    done
    
    echo "Integrity database created."
    exit 0
fi

# Check integrity
echo "Checking file integrity..."
temp_file=$(mktemp)

for path in "${CRITICAL_PATHS[@]}"; do
    if [ -d "$path" ]; then
        find "$path" -type f -exec shasum {} \; >> "$temp_file"
    fi
done

# Compare with baseline
if ! diff -q "$INTEGRITY_DB" "$temp_file" > /dev/null; then
    echo "INTEGRITY VIOLATIONS DETECTED:"
    echo ""

    # Get detailed differences
    added_files=$(diff "$INTEGRITY_DB" "$temp_file" | grep "^>" | wc -l)
    removed_files=$(diff "$INTEGRITY_DB" "$temp_file" | grep "^<" | wc -l)

    echo "Summary: $added_files files added/modified, $removed_files files removed/missing"
    echo ""

    if [ "$added_files" -gt 0 ]; then
        echo "=== New or Modified Files ==="
        diff "$INTEGRITY_DB" "$temp_file" | grep "^>" | sed 's/^> //' | while read hash file; do
            if [ -f "$file" ]; then
                size=$(ls -lh "$file" 2>/dev/null | awk '{print $5}')
                modified=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$file" 2>/dev/null)
                echo "VIOLATION: File modified or added: $file"
                echo "  New hash: $hash"
                echo "  Size: $size"
                echo "  Modified: $modified"
                echo ""
            fi
        done | head -30
    fi

    if [ "$removed_files" -gt 0 ]; then
        echo "=== Removed or Missing Files ==="
        diff "$INTEGRITY_DB" "$temp_file" | grep "^<" | sed 's/^< //' | while read hash file; do
            echo "VIOLATION: File removed or missing: $file"
            echo "  Previous hash: $hash"
            echo ""
        done | head -10
    fi

    # Non-interactive mode for automation
    if [ -t 0 ]; then
        # Ask if user wants to update baseline (only if interactive)
        echo "Update baseline? (y/n)"
        read answer
        if [ "$answer" = "y" ]; then
            cp "$temp_file" "$INTEGRITY_DB"
            echo "Baseline updated."
        fi
    else
        echo "Running in non-interactive mode - baseline not updated"
    fi
fi

rm "$temp_file"
