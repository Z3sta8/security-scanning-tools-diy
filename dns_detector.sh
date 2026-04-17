#!/bin/bash
# DNS Hijacking and Poisoning Detection Script
# Detects if DNS settings have been tampered with

echo "=== DNS Security Check ==="
echo "Scan started: $(date)"
echo ""

findings=0

# 1. Get current DNS servers
echo "[1/6] Checking current DNS configuration..."
dns_servers=$(scutil --dns | grep "nameserver\[0\]" | awk '{print $3}' | sort -u)

if [ -z "$dns_servers" ]; then
    echo "  WARNING: Could not determine DNS servers"
    findings=$((findings + 1))
else
    echo "  Current DNS servers:"
    echo "$dns_servers" | while read dns; do
        echo "    - $dns"
    done
fi
echo ""

# 2. Known safe DNS providers
echo "[2/6] Comparing against known safe DNS providers..."
SAFE_DNS=(
    "1.1.1.1"        # Cloudflare
    "1.0.0.1"
    "8.8.8.8"        # Google
    "8.8.4.4"
    "9.9.9.9"        # Quad9
    "149.112.112.112"
    "208.67.222.222" # OpenDNS
    "208.67.220.220"
    "2606:4700:4700::1111"  # Cloudflare IPv6
    "2606:4700:4700::1001"
    "2001:4860:4860::8888"  # Google IPv6
)

# Check if any current DNS matches safe list
safe_count=0
echo "$dns_servers" | while read dns; do
    is_safe=0
    for safe in "${SAFE_DNS[@]}"; do
        if [ "$dns" = "$safe" ]; then
            echo "  ✓ $dns is a known safe provider"
            is_safe=1
            break
        fi
    done

    if [ $is_safe -eq 0 ]; then
        echo "  ⚠ $dns is NOT a standard public DNS provider"
        echo "    This could be your router, ISP, or potentially malicious"
        findings=$((findings + 1))
    fi
done
echo ""

# 3. DNS Resolution Test
echo "[3/6] Testing DNS resolution against known good..."
if command -v dig > /dev/null 2>&1; then
    # Test with current DNS
    test_domain="example.com"
    primary_dns=$(echo "$dns_servers" | head -1)

    if [ -n "$primary_dns" ]; then
        current_result=$(dig @"$primary_dns" +short "$test_domain" 2>/dev/null | head -1)
        known_good=$(dig @1.1.1.1 +short "$test_domain" 2>/dev/null | head -1)

        if [ -n "$current_result" ] && [ -n "$known_good" ]; then
            if [ "$current_result" != "$known_good" ]; then
                echo "  WARNING: DNS resolution mismatch!"
                echo "  Your DNS ($primary_dns) returned: $current_result"
                echo "  Known good (1.1.1.1) returned: $known_good"
                echo "  This could indicate DNS poisoning"
                findings=$((findings + 1))
            else
                echo "  ✓ DNS resolution matches known good"
            fi
        else
            echo "  INFO: Could not complete DNS resolution test"
        fi
    fi
else
    echo "  INFO: 'dig' not available, skipping resolution test"
fi
echo ""

# 4. Check /etc/hosts for malicious redirects
echo "[4/6] Checking /etc/hosts for suspicious redirects..."
hosts_findings=0

# Known legitimate entries to ignore
LEGIT_HOSTS=(
    "localhost"
    "broadcasthost"
    "local"
    "ip6-localhost"
    "ip6-loopback"
    "ip6-localnet"
    "ip6-mcastprefix"
    "ip6-allnodes"
    "ip6-allrouters"
    "ip6-allhosts"
)

# Check for non-localhost entries with IP addresses
while read -r ip hostname; do
    # Skip comments and empty lines
    [[ "$ip" =~ ^#.*$ ]] && continue
    [ -z "$ip" ] && continue

    # Skip localhost entries
    is_legit=0
    for legit in "${LEGIT_HOSTS[@]}"; do
        if [[ "$hostname" == *"$legit"* ]]; then
            is_legit=1
            break
        fi
    done

    # Check if it's an IP address pointing to a non-standard domain
    if [[ $ip =~ ^[0-9] ]] && [ $is_legit -eq 0 ]; then
        # Check for common domains being redirected
        if [[ "$hostname" =~ (apple|google|microsoft|amazon|facebook|paypal|bank|crypto) ]]; then
            echo "  WARNING: Suspicious /etc/hosts entry:"
            echo "    $ip $hostname"
            hosts_findings=$((hosts_findings + 1))
        fi
    fi
done < /etc/hosts

if [ $hosts_findings -eq 0 ]; then
    echo "  ✓ No suspicious /etc/hosts redirects detected"
else
    findings=$((findings + findings + hosts_findings))
fi
echo ""

# 5. Check for DNS-related LaunchAgents/Daemons
echo "[5/6] Checking for DNS-related system components..."
dns_config_count=0

# Look for DNS-related plist files
for dir in /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents; do
    expanded_dir="${dir/#\~/$HOME}"
    if [ -d "$expanded_dir" ]; then
        dns_plists=$(find "$expanded_dir" -name "*dns*" -o -name "*DNS*" 2>/dev/null)
        if [ -n "$dns_plists" ]; then
            echo "  DNS-related plist files:"
            echo "$dns_plists" | while read plist; do
                ls -lh "$plist"
                dns_config_count=$((dns_config_count + 1))
            done
        fi
    fi
done

if [ $dns_config_count -eq 0 ]; then
    echo "  ✓ No unusual DNS-related launch agents found"
fi
echo ""

# 6. Check for active DNS tunneling indicators
echo "[6/6] Checking for DNS tunneling indicators..."
tunneling_findings=0

# Check for high volume of DNS queries to single domain
if command -v netstat > /dev/null 2>&1; then
    # Look for many DNS connections
    dns_connections=$(netstat -an | grep ".53 " | grep ESTABLISHED | wc -l | tr -d ' ')

    if [ "$dns_connections" -gt 50 ]; then
        echo "  WARNING: Unusually high number of DNS connections: $dns_connections"
        echo "  This could indicate DNS tunneling"
        tunneling_findings=$((tunneling_findings + 1))
    else
        echo "  ✓ Normal number of DNS connections: $dns_connections"
    fi
fi

# Check for processes with many outbound connections on port 53
if command -v lsof > /dev/null 2>&1; then
    dns_processes=$(lsof -i :53 -P -n 2>/dev/null | grep ESTABLISHED | awk '{print $1}' | sort -u)

    if [ -n "$dns_processes" ]; then
        echo "  Processes with DNS connections:"
        echo "$dns_processes" | while read proc; do
            count=$(lsof -i :53 -P -n 2>/dev/null | grep "$proc" | wc -l | tr -d ' ')
            echo "    $proc: $count connections"
            if [ "$count" -gt 10 ]; then
                echo "      WARNING: High connection count - possible tunneling"
                tunneling_findings=$((tunneling_findings + 1))
            fi
        done
    fi
fi

findings=$((findings + tunneling_findings))
echo ""

# Summary
echo "=== Scan Complete ==="
echo "Total findings: $findings"
echo ""

if [ $findings -gt 0 ]; then
    echo "ALERT: Potential DNS issues detected."
    echo ""
    echo "Recommended actions:"
    echo "  1. Verify DNS settings in: System Settings > Network > Wi-Fi/Ethernet > Details > DNS"
    echo "  2. Consider using known-safe DNS: Cloudflare (1.1.1.1) or Google (8.8.8.8)"
    echo "  3. Review /etc/hosts for suspicious entries"
    echo "  4. Flush DNS cache: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder"
    exit 1
else
    echo "OK: No DNS hijacking detected."
    echo ""
    echo "Your DNS appears to be properly configured."
    exit 0
fi
