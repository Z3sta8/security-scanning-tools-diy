#!/usr/bin/env python3
"""
Enhanced web dashboard for security monitoring with actionable recommendations
"""

from flask import Flask, jsonify, render_template_string
import sqlite3
import json
import subprocess
from datetime import datetime
import os

app = Flask(__name__)

DB_PATH = os.getenv("DB_PATH", "./data/scans.db")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Actionable recommendations database
ACTION_RECOMMENDATIONS = {
    "file_modification": {
        "title": "File Modified or Added",
        "severity": "HIGH",
        "description": "A monitored system file has been changed or added",
        "actions": [
            "Verify the change was intentional",
            "Check the file: `ls -l <file_path>`",
            "Verify signature: `codesign -dv <file_path>`",
            "If suspicious: `./auto_response.sh 'file_modification' 'path:<file_path>'`"
        ]
    },
    "file_removal": {
        "title": "File Removed or Missing",
        "severity": "HIGH",
        "description": "A monitored system file has been deleted",
        "actions": [
            "Check if deletion was intentional",
            "Restore from backup if needed",
            "Scan for malware: `./keylogger_detector.sh`",
            "Review logs: `tail -100 ~/security_scanning_tools_diy/logs/monitor.log`"
        ]
    },
    "suspicious_process": {
        "title": "Suspicious Process Detected",
        "severity": "HIGH",
        "description": "A process matching suspicious patterns was found",
        "actions": [
            "Investigate the process: `ps aux | grep <process_name>`",
            "Check open files: `lsof -p <PID>`",
            "Check network connections: `lsof -i -P -n -p <PID>`",
            "If malicious: `sudo kill -9 <PID>`",
            "Quarantine binary: `./auto_response.sh 'suspicious_process' 'PID:<PID>'`"
        ]
    },
    "network_anomaly": {
        "title": "Network Anomaly Detected",
        "severity": "MEDIUM",
        "description": "Unusual network activity detected",
        "actions": [
            "Identify the process: `lsof -i -P -n | grep <port>`",
            "Check the remote address: `whois <IP>`",
            "Block if malicious: `./auto_response.sh 'suspicious_network' 'IP:<IP>'`",
            "Monitor for more: `./network_anomaly_detector.sh`"
        ]
    },
    "integrity_violation": {
        "title": "Integrity Check Violation",
        "severity": "HIGH",
        "description": "File integrity check failed",
        "actions": [
            "Review changes: `./integrity_monitor.sh`",
            "Compare with baseline: `diff ~/.security/integrity.db /tmp/current`",
            "Update baseline if changes are legitimate",
            "Investigate further: `./persistence_detector.sh`"
        ]
    },
    "warning": {
        "title": "Security Warning",
        "severity": "MEDIUM",
        "description": "A security warning was generated",
        "actions": [
            "Review the specific warning details",
            "Check logs: `tail -50 ~/security_scanning_tools_diy/logs/*.log`",
            "Run additional scans: `./compromise_check.sh`",
            "Monitor for recurrence"
        ]
    },
    "alert": {
        "title": "Security Alert",
        "severity": "HIGH",
        "description": "A security alert was triggered",
        "actions": [
            "IMMEDIATE: Review alert details",
            "Run full scan suite: `./keylogger_detector.sh && ./persistence_detector.sh`",
            "Check for compromise: `./compromise_check.sh`",
            "Isolate system if confirmed threat: `sudo ifconfig en0 down`"
        ]
    },
    "dns_hijack": {
        "title": "DNS Hijacking Attempt",
        "severity": "HIGH",
        "description": "DNS settings may have been tampered with",
        "actions": [
            "Check current DNS: `scutil --dns`",
            "Reset to safe DNS: `./auto_response.sh 'dns_hijack' 'DNS poisoned'`",
            "Flush DNS cache: `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`",
            "Run DNS check: `./dns_detector.sh`"
        ]
    },
    "keylogger_detected": {
        "title": "Potential Keylogger Detected",
        "severity": "CRITICAL",
        "description": "Signs of keylogger or spyware activity",
        "actions": [
            "CRITICAL: Disconnect from network",
            "Review Input Monitoring: System Settings > Privacy & Security",
            "Scan for spyware: `./keylogger_detector.sh`",
            "Check LaunchAgents: `ls -la ~/Library/LaunchAgents/ /Library/LaunchAgents/`",
            "Change passwords from clean device"
        ]
    },
    "persistence_mechanism": {
        "title": "Persistence Mechanism Detected",
        "severity": "HIGH",
        "description": "Malware persistence mechanism found",
        "actions": [
            "Review persistence details: `./persistence_detector.sh`",
            "Check cron jobs: `crontab -l`",
            "Review LaunchAgents: `find ~/Library/LaunchAgents/ -name '*.plist'`",
            "Remove if malicious: Delete the plist file",
            "Restart in Safe Mode if needed"
        ]
    }
}

# HTML Template with Action Items
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Monitor Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        h1 {
            color: white;
            text-align: center;
            margin-bottom: 30px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.15);
        }
        .stat-label {
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        .stat-value {
            font-size: 36px;
            font-weight: bold;
            color: #333;
        }
        .severity-high { color: #e74c3c; }
        .severity-medium { color: #f39c12; }
        .severity-low { color: #3498db; }
        .severity-clean { color: #2ecc71; }
        .severity-critical { color: #8b0000; }

        .section {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        h2 {
            margin-bottom: 20px;
            color: #333;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #eee;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .status-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .status-completed { background: #d4edda; color: #155724; }
        .status-running { background: #cce5ff; color: #004085; }
        .status-failed { background: #f8d7da; color: #721c24; }
        .status-timeout { background: #fff3cd; color: #856404; }

        .finding-item {
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid;
            background: #f8f9fa;
            border-radius: 4px;
        }
        .finding-high { border-left-color: #e74c3c; background: #fee; }
        .finding-medium { border-left-color: #f39c12; background: #fef5e7; }
        .finding-low { border-left-color: #3498db; background: #eaf2f8; }
        .finding-critical { border-left-color: #8b0000; background: #fdd; }

        .action-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
        }
        .action-title {
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
        }
        .action-command {
            background: #2d3748;
            color: #48bb78;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 13px;
            margin: 5px 0;
            display: block;
        }
        .action-description {
            color: #666;
            font-size: 14px;
            margin: 5px 0;
        }

        .refresh-info {
            color: white;
            text-align: center;
            margin-top: 20px;
            font-size: 14px;
        }

        .priority-high {
            border-left: 4px solid #e74c3c;
            background: #fff5f5;
        }
        .priority-medium {
            border-left: 4px solid #f39c12;
            background: #fffbf0;
        }
        .priority-low {
            border-left: 4px solid #3498db;
            background: #f0f7ff;
        }
    </style>
    <script>
        function refreshData() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    updateDashboard(data);
                })
                .catch(error => console.error('Error:', error));
        }

        function updateDashboard(data) {
            document.getElementById('total-scans').innerText = data.statistics.total_scans || 0;
            document.getElementById('completed-scans').innerText = data.statistics.completed || 0;
            document.getElementById('failed-scans').innerText = data.statistics.failed || 0;
            document.getElementById('total-findings').innerText = data.statistics.total_findings || 0;

            // Update timestamp
            document.getElementById('last-update').innerText = new Date().toLocaleString();
        }

        // Refresh every 30 seconds
        setInterval(refreshData, 30000);

        // Initial load
        window.onload = refreshData;
    </script>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Monitor Dashboard</h1>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Scans</div>
                <div class="stat-value" id="total-scans">{{ stats.total_scans }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Completed</div>
                <div class="stat-value severity-clean" id="completed-scans">{{ stats.completed }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Failed</div>
                <div class="stat-value severity-high" id="failed-scans">{{ stats.failed }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value severity-medium" id="total-findings">{{ stats.total_findings }}</div>
            </div>
        </div>

        <div class="section">
            <h2>🚨 Action Items & Recommendations</h2>
            {% if action_items %}
                {% for item in action_items %}
                <div class="action-card priority-{{ item.priority }}">
                    <div class="action-title">{{ item.title }}</div>
                    <div class="action-description">{{ item.description }}</div>
                    {% for action in item.actions %}
                    <div class="action-command">{{ action }}</div>
                    {% endfor %}
                </div>
                {% endfor %}
            {% else %}
                <p style="color: #2ecc71;">✅ No current action items - System appears secure!</p>
            {% endif %}
        </div>

        <div class="section">
            <h2>📋 Recent Scans</h2>
            <table>
                <thead>
                    <tr>
                        <th>Scan Type</th>
                        <th>Start Time</th>
                        <th>Status</th>
                        <th>Findings</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    {% for scan in recent_scans %}
                    <tr>
                        <td><strong>{{ scan[0] }}</strong></td>
                        <td>{{ scan[1] }}</td>
                        <td><span class="status-badge status-{{ scan[2] }}">{{ scan[2] }}</span></td>
                        <td>{{ scan[3] }}</td>
                        <td><span class="severity-{{ scan[4]|lower }}">{{ scan[4] }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>🔍 Recent Findings</h2>
            {% for finding in recent_findings %}
            <div class="finding-item finding-{{ finding[3]|lower }}">
                <strong>{{ finding[2] }}</strong> - {{ finding[1] }}<br>
                <small>{{ finding[4] }}</small>
            </div>
            {% endfor %}
        </div>

        <div class="refresh-info">
            Auto-refresh every 30 seconds | Last updated: <span id="last-update">{{ now }}</span>
        </div>
    </div>
</body>
</html>
"""


def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_action_items():
    """Generate actionable items based on recent findings"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get recent findings from last 24 hours
        cursor.execute('''
            SELECT f.finding_type, f.severity, f.description, COUNT(*) as count
            FROM findings f
            WHERE f.timestamp > datetime('now', '-1 day')
            GROUP BY f.finding_type, f.severity
            ORDER BY
                CASE f.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                COUNT(*) DESC
        ''')

        recent_findings = cursor.fetchall()
        conn.close()

        action_items = []

        for finding in recent_findings:
            finding_type = finding[0]
            severity = finding[1]
            description = finding[2]
            count = finding[3]

            # Get recommendation for this finding type
            if finding_type in ACTION_RECOMMENDATIONS:
                rec = ACTION_RECOMMENDATIONS[finding_type]
                priority = 'high' if severity in ['CRITICAL', 'HIGH'] else 'medium' if severity == 'MEDIUM' else 'low'

                action_items.append({
                    'title': f"⚠️ {rec['title']} ({count} occurrence{'s' if count > 1 else ''})",
                    'description': f"{rec['description']}. Details: {description}",
                    'priority': priority,
                    'actions': rec['actions']
                })

        return action_items
    except Exception as e:
        print(f"Error getting action items: {e}")
        return []


@app.route('/')
def dashboard():
    """Main dashboard page"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get statistics
        cursor.execute('''
            SELECT
                COUNT(*) as total_scans,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                SUM(findings_count) as total_findings
            FROM scans
        ''')
        stats_row = cursor.fetchone()
        stats = {
            'total_scans': stats_row[0] or 0,
            'completed': stats_row[1] or 0,
            'failed': stats_row[2] or 0,
            'total_findings': stats_row[3] or 0
        }

        # Get recent scans
        cursor.execute('''
            SELECT scan_type, start_time, status, findings_count, severity
            FROM scans
            ORDER BY start_time DESC
            LIMIT 20
        ''')
        recent_scans = cursor.fetchall()

        # Get recent findings
        cursor.execute('''
            SELECT f.id, f.timestamp, f.finding_type, f.severity, f.description
            FROM findings f
            ORDER BY f.timestamp DESC
            LIMIT 10
        ''')
        recent_findings = cursor.fetchall()

        # Get action items
        action_items = get_action_items()

        conn.close()

        return render_template_string(
            DASHBOARD_TEMPLATE,
            stats=stats,
            recent_scans=recent_scans,
            recent_findings=recent_findings,
            action_items=action_items,
            now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )

    except Exception as e:
        return f"<h1>Error loading dashboard</h1><p>{str(e)}</p>", 500


@app.route('/api/status')
def api_status():
    """API endpoint for status"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get statistics
        cursor.execute('''
            SELECT
                COUNT(*) as total_scans,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                SUM(findings_count) as total_findings
            FROM scans
        ''')
        stats_row = cursor.fetchone()

        # Get recent scans
        cursor.execute('''
            SELECT scan_type, start_time, status, findings_count, severity
            FROM scans
            ORDER BY start_time DESC
            LIMIT 10
        ''')
        recent_scans = cursor.fetchall()

        conn.close()

        return jsonify({
            'statistics': {
                'total_scans': stats_row[0] or 0,
                'completed': stats_row[1] or 0,
                'failed': stats_row[2] or 0,
                'total_findings': stats_row[3] or 0
            },
            'recent_scans': [
                {
                    'scan_type': row[0],
                    'start_time': row[1],
                    'status': row[2],
                    'findings_count': row[3],
                    'severity': row[4]
                }
                for row in recent_scans
            ]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/action-items')
def api_action_items():
    """Get current action items"""
    try:
        action_items = get_action_items()
        return jsonify(action_items)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/findings')
def api_findings():
    """Get all findings"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT f.id, f.scan_id, f.timestamp, f.finding_type,
                   f.description, f.severity, s.scan_type
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            ORDER BY f.timestamp DESC
            LIMIT 100
        ''')
        findings = cursor.fetchall()

        conn.close()

        return jsonify([dict(row) for row in findings])

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
