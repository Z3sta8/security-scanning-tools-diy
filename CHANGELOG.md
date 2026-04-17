# Security Monitoring System - Change Log

## Date: 2025-02-01
## Changes: Enhanced Threat Detection & Response Capabilities

---

## 🆕 New Scripts Added

### 1. `keylogger_detector.sh`
**Purpose**: Detect keyloggers and spyware on macOS

**Features**:
- Scans for known keylogger process names
- Checks apps with Input Monitoring permissions
- Inspects LaunchAgents/Daemons for suspicious unsigned entries
- Scans common malware drop locations
- Detects event tap processes (CGEvent)

**Usage**:
```bash
./keylogger_detector.sh
```

**Scan Intervals**:
- Recommended: Every 10 minutes (600 seconds)
- Timeout: 2 minutes

**What It Detects**:
- Known keylogger processes (logkitty, keylogger, inputlog, etc.)
- Suspicious unsigned LaunchAgents that auto-start
- Executables in ScriptingAdditions and temp directories
- Processes using CGEvent taps (advanced keylogging)

---

### 2. `persistence_detector.sh`
**Purpose**: Detect malware persistence mechanisms

**Features**:
- Analyzes cron jobs for suspicious commands
- Detects DYLD environment variable injection (dylib hijacking)
- Finds recently modified system binaries
- Scans temp directories for executable payloads
- Identifies unsigned network listeners
- Lists all login items and browser extensions

**Usage**:
```bash
./persistence_detector.sh
```

**Scan Intervals**:
- Recommended: Every 15 minutes (900 seconds)
- Timeout: 3 minutes

**What It Detects**:
- Cron jobs with download/execute commands
- Processes injecting libraries via DYLD_INSERT_LIBRARIES
- System binaries modified in last 7 days
- Executables in /tmp, /var/tmp
- Processes parented by launchd unexpectedly

---

### 3. `dns_detector.sh`
**Purpose**: Detect DNS hijacking and poisoning

**Features**:
- Lists current DNS servers
- Compares against known safe providers (Cloudflare, Google, Quad9)
- Tests DNS resolution against known-good
- Checks /etc/hosts for malicious redirects
- Identifies DNS-related LaunchAgents/Daemons
- Detects potential DNS tunneling

**Usage**:
```bash
./dns_detector.sh
```

**Scan Intervals**:
- Recommended: Every 30 minutes (1800 seconds)
- Timeout: 2 minutes

**What It Detects**:
- DNS servers not matching known public providers
- DNS resolution mismatches (possible poisoning)
- Suspicious /etc/hosts entries
- Unusual DNS connection volumes (tunneling)

---

### 4. `alert_dispatcher.sh`
**Purpose**: Real-time alert notification system

**Features**:
- Checks monitor log for recent HIGH severity findings
- Sends macOS notifications for alerts
- Logs all alerts to dedicated file
- Supports external notifications (Pushover, Telegram, Slack)
- Checks individual scan logs for findings
- Monitors for unsigned processes with network access

**Usage**:
```bash
./alert_dispatcher.sh
```

**Configuration** (Optional):
```bash
export PUSHOVER_TOKEN="your_token"
export PUSHOVER_USER="your_user_key"
export TELEGRAM_BOT_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"
export SLACK_WEBHOOK_URL="your_webhook_url"
```

**Check Interval**: Last 5 minutes of logs

---

### 5. `compromise_check.sh`
**Purpose**: Quick check for active compromise indicators

**Features**:
- Identifies unusual outbound connections to low ports
- Checks for processes with suspicious characteristics
- Reviews recent crash reports
- Lists apps with camera/mic access
- Detects packet capture/sniffing tools
- Checks for suspicious user accounts

**Usage**:
```bash
./compromise_check.sh
```

**Scan Intervals**:
- Recommended: Every 20 minutes (1200 seconds)
- Timeout: 3 minutes

**What It Detects**:
- Connections to non-standard low ports (< 1024)
- Multiple recent crash reports (exploit attempts)
- Running packet capture tools (tcpdump, wireshark)
- Users with root privileges beyond expected
- More than 5 admin group members

---

### 6. `auto_response.sh`
**Purpose**: Automated incident response actions

**Features**:
- Kill malicious processes by PID or name
- Quarantine suspicious files
- Block IP addresses via firewall (pfctl)
- Disable network interfaces (system isolation)
- Reset DNS to safe values
- Create forensic snapshots
- Emergency response protocols

**Usage**:
```bash
# Manual usage
./auto_response.sh "threat_type" "threat_details"

# Examples:
./auto_response.sh "suspicious_process" "PID:12345"
./auto_response.sh "suspicious_network" "IP:192.168.1.100"
./auto_response.sh "dns_hijack" "DNS poisoned"
./auto_response.sh "file_modification" "path:/tmp/suspicious"
./auto_response.sh "emergency" "Active C2 detected"
```

**Safety**: Requires confirmation by default (unless `AUTO_RESPONSE=true`)

**Root Requirements**:
- Blocking IPs: `sudo`
- Network disable: `sudo`
- DNS reset: `sudo`

---

## 🔄 Modified Scripts

### `log_analyzer_fast.sh`
**Changes**:
- Fixed ASL log check bug (changed `-f` to `-d` for directory check)
- Added suspicious port scanning functionality

**New Features**:
- Checks for listeners on common C2/backdoor ports:
  - 4444, 5555, 6666, 31337, 12345, 12346, 1337
  - 9999, 10000, 10001, 10002
  - Common service ports: 1433, 1434, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017
- Reports process details including executable path

---

## ⚙️ Configuration Updates

### `security_monitor.py`
**Added to CONFIG["scans"]**:
```python
"log_analysis_fast": {
    "script": "./log_analyzer_fast.sh",
    "enabled": True,
    "interval": 300,
    "timeout": 60
},
"keylogger_detection": {
    "script": "./keylogger_detector.sh",
    "enabled": True,
    "interval": 600,
    "timeout": 120
},
"persistence_detection": {
    "script": "./persistence_detector.sh",
    "enabled": True,
    "interval": 900,
    "timeout": 180
},
"dns_detection": {
    "script": "./dns_detector.sh",
    "enabled": True,
    "interval": 1800,
    "timeout": 120
},
"compromise_check": {
    "script": "./compromise_check.sh",
    "enabled": True,
    "interval": 1200,
    "timeout": 180
}
```

### `config.json`
**Updated to match Python configuration**:
- Added all new scans with descriptions
- Added `auto_response` section (disabled by default for safety)
- Changed paths from `/var/log/...` to `./logs` and `./data` for local usage

---

## 📋 Complete Scan Schedule

| Scan | Interval | Purpose | Duration |
|------|----------|---------|----------|
| log_analysis | 5 min | Full log analysis | ~2 min |
| log_analysis_fast | 5 min | Fast log + port scan | ~1 min |
| keylogger_detection | 10 min | Keylogger/spyware scan | ~2 min |
| persistence_detection | 15 min | Persistence mechanisms | ~3 min |
| compromise_check | 20 min | Active compromise indicators | ~3 min |
| memory_analysis | 30 min | Memory/rootkit scan | ~5 min |
| dns_detection | 30 min | DNS hijacking check | ~2 min |
| integrity_check | 60 min | File integrity verification | ~5 min |

---

## 🚀 Quick Start Guide

### 1. Initial Setup
```bash
cd ~/security_scanning_tools_diy

# Make all scripts executable (if not already)
chmod +x *.sh

# Update integrity baseline
rm ~/.security/integrity.db
./integrity_monitor.sh
```

### 2. Run Full Scan Suite
```bash
# Run all new detection scripts
./keylogger_detector.sh
./persistence_detector.sh
./dns_detector.sh
./compromise_check.sh
```

### 3. Start Continuous Monitoring
```bash
# Start the main orchestrator
python3 security_monitor.py
```

### 4. View Dashboard
```bash
# Start web dashboard (in another terminal)
python3 web_dashboard.py

# Open in browser
open http://localhost:8080
```

### 5. Configure Alert Dispatcher (Optional)
```bash
# Run manually to check for alerts
./alert_dispatcher.sh

# Or set up in cron for regular checks
# */5 * * * * /Users/zesta8/security_scanning_tools_diy/alert_dispatcher.sh
```

---

## ⚠️ Important Notes

### False Positives
Some detections may trigger on legitimate software:
- **Promiscuous network interfaces**: Virtual adapters (VMware, VirtualBox, VPN)
- **Ephemeral ports**: Normal outbound connections use high ports
- **Unsigned LaunchAgents**: GPG Tools, some developer tools
- **Multiple admin users**: Legitimate if you have multiple admin accounts

Always review findings before taking action.

### Auto-Response Safety
The `auto_response.sh` script:
- Requires confirmation by default
- Needs sudo privileges for network/firewall actions
- Creates forensic snapshots before taking action
- Should be used carefully to avoid disrupting legitimate operations

### Resource Usage
With all scripts enabled:
- **CPU**: ~15-25% average (spikes during scans)
- **Memory**: ~300-400MB
- **Disk**: ~100MB for logs and database (grows over time)

---

## 🔧 Troubleshooting

### Script Won't Execute
```bash
# Check permissions
ls -la *.sh

# Make executable
chmod +x script_name.sh
```

### Permission Denied Errors
Some checks require Full Disk Access:
1. System Settings > Privacy & Security
2. Full Disk Access > Add Terminal or your script
3. Restart the script

### Database Locked Errors
```bash
# Stop the monitor
# Backup database
cp data/scans.db data/scans.db.backup

# Restart
python3 security_monitor.py
```

### Alerts Not Triggering
Check:
1. Alert dispatcher is running
2. Log files are being written to `./logs/`
3. Monitor log has recent entries
4. macOS notifications are enabled

---

## 📊 Summary of Enhancements

| Category | Before | After |
|----------|--------|-------|
| Detection Scripts | 4 | 8 |
| Threat Types Covered | ~6 | ~15 |
| Scans per Hour | ~12 | ~20 |
| Detection Capabilities | Basic | Advanced |
| Response Capabilities | None | Automated |
| Alerting | Logs only | Real-time notifications |

---

## 📝 Next Steps (Optional Enhancements)

These are not implemented but could be added later:

1. **Machine Learning Anomaly Detection**: Train on normal behavior
2. **YARA Rule Scanning**: Add YARA-based malware detection
3. **Process Whitelisting**: Allow known-good processes
4. **Cloud SIEM Integration**: Send logs to external SIEM
5. **Honeypot Integration**: Detect network scanning
6. **USB Device Monitoring**: Track USB device changes
7. **Certificate Validation**: Check code signing more thoroughly
8. **SIP Status Check**: Verify System Integrity Protection status

---

## 🎯 Key Improvements

1. **Comprehensive Coverage**: Now detects 15+ threat categories vs. 6 before
2. **Faster Detection**: Keylogger and persistence scans run every 10-15 min
3. **Real-Time Alerts**: Get notified immediately when threats are detected
4. **Automated Response**: Option to automatically contain threats
5. **Better False Positive Handling**: Refined detection logic
6. **Enhanced Logging**: All actions logged to `./logs/alerts.log`

---

## ✅ Testing Checklist

After installation, verify:
- [ ] All scripts are executable
- [ ] `security_monitor.py` starts without errors
- [ ] Dashboard loads at http://localhost:8080
- [ ] Database is created in `./data/scans.db`
- [ ] Log files are written to `./logs/`
- [ ] Run `./keylogger_detector.sh` - completes without errors
- [ ] Run `./persistence_detector.sh` - completes without errors
- [ ] Run `./dns_detector.sh` - completes without errors
- [ ] Run `./compromise_check.sh` - completes without errors
- [ ] Alert dispatcher sends test notification (if configured)

---

## 📞 Support

For issues or questions:
1. Check individual script logs in `./logs/`
2. Review the main monitor log: `./logs/monitor.log`
3. Test scripts individually before running in orchestrator
4. Check macOS permissions in System Settings

---

**Document Version**: 1.0
**Last Updated**: 2025-02-01
**Maintained By**: Atlas
