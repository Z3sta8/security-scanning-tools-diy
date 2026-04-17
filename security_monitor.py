#!/usr/bin/env python3
"""
Security Monitoring Orchestrator
Coordinates and executes security scans with logging and persistence
"""

import os
import json
import sqlite3
import subprocess
import logging
import time
from datetime import datetime
from pathlib import Path
import threading
import signal
import sys

# Configuration
CONFIG = {
    "scan_interval": 300,  # 5 minutes
    "log_dir": os.getenv("LOG_DIR", "./logs"),
    "db_path": os.getenv("DB_PATH", "./data/scans.db"),
    "scans": {
        "integrity_check": {
            "script": "./integrity_monitor.sh",
            "enabled": True,
            "interval": 3600,  # 1 hour
            "timeout": 300
        },
        "log_analysis": {
            "script": "./log_analyzer.sh",
            "enabled": True,
            "interval": 300,  # 5 minutes
            "timeout": 120
        },
        "log_analysis_fast": {
            "script": "./log_analyzer_fast.sh",
            "enabled": True,
            "interval": 300,  # 5 minutes
            "timeout": 60
        },
        "memory_analysis": {
            "script": "./memory_analysis.sh",
            "enabled": True,
            "interval": 1800,  # 30 minutes
            "timeout": 300
        },
        "keylogger_detection": {
            "script": "./keylogger_detector.sh",
            "enabled": True,
            "interval": 600,  # 10 minutes
            "timeout": 120
        },
        "persistence_detection": {
            "script": "./persistence_detector.sh",
            "enabled": True,
            "interval": 900,  # 15 minutes
            "timeout": 180
        },
        "dns_detection": {
            "script": "./dns_detector.sh",
            "enabled": True,
            "interval": 1800,  # 30 minutes
            "timeout": 120
        },
        "compromise_check": {
            "script": "./compromise_check.sh",
            "enabled": True,
            "interval": 1200,  # 20 minutes
            "timeout": 180
        },
        "network_monitoring": {
            "script": "./network_anomaly_detector.sh",
            "enabled": False,  # Runs continuously, handle separately
            "interval": 0,
            "timeout": 0
        },
        "deep_monitor": {
            "script": "./deep_monitor.sh",
            "enabled": False,  # Runs continuously, handle separately
            "interval": 0,
            "timeout": 0
        }
    }
}


class SecurityMonitor:
    def __init__(self, config):
        self.config = config
        self.running = True
        self.last_run_times = {}

        # Setup directories
        Path(config["log_dir"]).mkdir(parents=True, exist_ok=True)
        Path(os.path.dirname(config["db_path"])).mkdir(parents=True, exist_ok=True)

        # Setup logging
        self.setup_logging()

        # Setup database
        self.setup_database()

        # Register signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def setup_logging(self):
        """Configure structured logging"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter(log_format))

        # File handler
        file_handler = logging.FileHandler(
            f"{self.config['log_dir']}/monitor.log"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(log_format))

        # Configure root logger
        self.logger = logging.getLogger('SecurityMonitor')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

        self.logger.info("Logging system initialized")

    def setup_database(self):
        """Initialize SQLite database for scan results"""
        self.conn = sqlite3.connect(
            self.config["db_path"],
            check_same_thread=False
        )
        self.cursor = self.conn.cursor()

        # Create tables
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                status TEXT NOT NULL,
                output TEXT,
                error TEXT,
                findings_count INTEGER DEFAULT 0,
                severity TEXT
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                finding_type TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT DEFAULT 'INFO',
                details TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT
            )
        ''')

        self.conn.commit()
        self.logger.info("Database initialized")

        # Log startup event
        self.log_system_event("startup", "Security Monitor started")

    def log_system_event(self, event_type, message, details=None):
        """Log system events to database"""
        try:
            self.cursor.execute('''
                INSERT INTO system_events (timestamp, event_type, message, details)
                VALUES (?, ?, ?, ?)
            ''', (datetime.now(), event_type, message, json.dumps(details) if details else None))
            self.conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to log system event: {e}")

    def run_scan(self, scan_name, scan_config):
        """Execute a security scan and capture results"""
        self.logger.info(f"Starting scan: {scan_name}")

        start_time = datetime.now()
        scan_id = None

        try:
            # Insert scan record
            self.cursor.execute('''
                INSERT INTO scans (scan_type, start_time, status)
                VALUES (?, ?, ?)
            ''', (scan_name, start_time, 'running'))
            self.conn.commit()
            scan_id = self.cursor.lastrowid

            # Execute scan script
            script_path = scan_config["script"]
            if not os.path.exists(script_path):
                raise FileNotFoundError(f"Script not found: {script_path}")

            result = subprocess.run(
                ['bash', script_path],
                capture_output=True,
                text=True,
                timeout=scan_config.get("timeout", 300)
            )

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            # Parse output for findings
            findings = self.parse_scan_output(scan_name, result.stdout, scan_id)
            findings_count = len(findings)

            # Determine severity
            severity = self.determine_severity(findings)

            # Update scan record
            self.cursor.execute('''
                UPDATE scans
                SET end_time = ?, status = ?, output = ?, error = ?,
                    findings_count = ?, severity = ?
                WHERE id = ?
            ''', (end_time, 'completed', result.stdout, result.stderr,
                  findings_count, severity, scan_id))
            self.conn.commit()

            # Log results
            self.logger.info(
                f"Scan completed: {scan_name} | "
                f"Duration: {duration:.2f}s | "
                f"Findings: {findings_count} | "
                f"Severity: {severity}"
            )

            # Save detailed output to file
            output_file = f"{self.config['log_dir']}/{scan_name}_{start_time.strftime('%Y%m%d_%H%M%S')}.log"
            with open(output_file, 'w') as f:
                f.write(f"Scan: {scan_name}\n")
                f.write(f"Start: {start_time}\n")
                f.write(f"End: {end_time}\n")
                f.write(f"Duration: {duration:.2f}s\n")
                f.write(f"Findings: {findings_count}\n")
                f.write(f"Severity: {severity}\n")
                f.write("\n--- Output ---\n")
                f.write(result.stdout)
                if result.stderr:
                    f.write("\n--- Errors ---\n")
                    f.write(result.stderr)

            return True

        except subprocess.TimeoutExpired:
            self.logger.error(f"Scan timeout: {scan_name}")
            if scan_id:
                self.cursor.execute('''
                    UPDATE scans SET status = ?, error = ? WHERE id = ?
                ''', ('timeout', 'Scan exceeded timeout limit', scan_id))
                self.conn.commit()
            return False

        except Exception as e:
            self.logger.error(f"Scan failed: {scan_name} - {str(e)}")
            if scan_id:
                self.cursor.execute('''
                    UPDATE scans SET status = ?, error = ? WHERE id = ?
                ''', ('failed', str(e), scan_id))
                self.conn.commit()
            return False

    def parse_scan_output(self, scan_name, output, scan_id):
        """Parse scan output to extract findings with detailed context"""
        findings = []

        if not output:
            return findings

        lines = output.split('\n')
        i = 0

        while i < len(lines):
            line = lines[i].strip()

            # Parse integrity violations with file details
            if 'VIOLATION: File modified or added:' in line:
                file_path = line.split('File modified or added:')[1].strip()
                details = []

                # Capture next few lines for details
                for j in range(i+1, min(i+5, len(lines))):
                    if lines[j].strip().startswith('New hash:') or \
                       lines[j].strip().startswith('Size:') or \
                       lines[j].strip().startswith('Modified:'):
                        details.append(lines[j].strip())
                    elif not lines[j].strip():
                        break

                description = f"File modified or added: {file_path}"
                if details:
                    description += " | " + " | ".join(details)

                finding = {
                    'type': 'file_modification',
                    'description': description,
                    'severity': 'HIGH',
                    'file_path': file_path
                }
                findings.append(finding)
                self._insert_finding(scan_id, 'file_modification', description, 'HIGH',
                                    {'file_path': file_path, 'details': details})
                i += 5
                continue

            # Parse removed/missing files
            elif 'VIOLATION: File removed or missing:' in line:
                file_path = line.split('File removed or missing:')[1].strip()
                description = f"File removed or missing: {file_path}"

                finding = {
                    'type': 'file_removal',
                    'description': description,
                    'severity': 'HIGH',
                    'file_path': file_path
                }
                findings.append(finding)
                self._insert_finding(scan_id, 'file_removal', description, 'HIGH',
                                    {'file_path': file_path})
                i += 3
                continue

            # Parse suspicious processes with details
            elif 'SUSPICIOUS' in line.upper() and 'process' in line.lower():
                description = line.strip()
                # Capture process details from next lines
                details = []
                for j in range(i+1, min(i+4, len(lines))):
                    if lines[j].strip() and not lines[j].strip().startswith('==='):
                        details.append(lines[j].strip())
                    else:
                        break

                if details:
                    description += " | " + " | ".join(details[:2])

                finding = {
                    'type': 'suspicious_process',
                    'description': description,
                    'severity': 'HIGH'
                }
                findings.append(finding)
                self._insert_finding(scan_id, 'suspicious_process', description, 'HIGH',
                                    {'details': details})

            # Parse network anomalies
            elif 'ANOMALY' in line.upper() or 'NETWORK ANOMALY' in line.upper():
                description = line.strip()
                # Capture connection details
                for j in range(i+1, min(i+3, len(lines))):
                    if lines[j].strip():
                        description += " | " + lines[j].strip()
                    else:
                        break

                finding = {
                    'type': 'network_anomaly',
                    'description': description,
                    'severity': 'MEDIUM'
                }
                findings.append(finding)
                self._insert_finding(scan_id, 'network_anomaly', description, 'MEDIUM')

            # Parse warnings
            elif 'WARNING:' in line.upper():
                description = line.strip()
                finding = {
                    'type': 'warning',
                    'description': description,
                    'severity': 'MEDIUM'
                }
                findings.append(finding)
                self._insert_finding(scan_id, 'warning', description, 'MEDIUM')

            # Generic suspicious/alert patterns
            elif any(keyword in line.upper() for keyword in ['SUSPICIOUS', 'ALERT', 'DETECTED', 'FAILED']):
                description = line.strip()
                if description and len(description) > 10:  # Avoid noise
                    severity = 'HIGH' if any(k in line.upper() for k in ['SUSPICIOUS', 'ALERT']) else 'MEDIUM'
                    finding = {
                        'type': 'alert',
                        'description': description,
                        'severity': severity
                    }
                    findings.append(finding)
                    self._insert_finding(scan_id, 'alert', description, severity)

            i += 1

        if findings:
            self.conn.commit()

        return findings

    def _insert_finding(self, scan_id, finding_type, description, severity, details=None):
        """Helper to insert finding into database"""
        try:
            self.cursor.execute('''
                INSERT INTO findings
                (scan_id, timestamp, finding_type, description, severity, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (scan_id, datetime.now(), finding_type, description, severity,
                  json.dumps(details) if details else None))
        except Exception as e:
            self.logger.error(f"Failed to insert finding: {e}")

    def determine_severity(self, findings):
        """Determine overall severity from findings"""
        if not findings:
            return 'CLEAN'

        severities = [f.get('severity', 'LOW') for f in findings]

        if 'HIGH' in severities:
            return 'HIGH'
        elif 'MEDIUM' in severities:
            return 'MEDIUM'
        elif 'LOW' in severities:
            return 'LOW'
        else:
            return 'INFO'

    def should_run_scan(self, scan_name, scan_config):
        """Determine if a scan should run based on interval"""
        if not scan_config.get("enabled", True):
            return False

        interval = scan_config.get("interval", self.config["scan_interval"])
        last_run = self.last_run_times.get(scan_name, 0)
        current_time = time.time()

        return (current_time - last_run) >= interval

    def run_monitoring_loop(self):
        """Main monitoring loop"""
        self.logger.info("Starting monitoring loop")

        while self.running:
            try:
                for scan_name, scan_config in self.config["scans"].items():
                    if self.should_run_scan(scan_name, scan_config):
                        self.run_scan(scan_name, scan_config)
                        self.last_run_times[scan_name] = time.time()

                # Sleep for a short interval
                time.sleep(10)

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)

        self.logger.info("Monitoring loop stopped")

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        self.log_system_event("shutdown", "Security Monitor shutting down")
        self.cleanup()

    def cleanup(self):
        """Cleanup resources"""
        try:
            if hasattr(self, 'conn'):
                self.conn.close()
            self.logger.info("Cleanup completed")
        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")

    def get_status(self):
        """Get current monitoring status"""
        try:
            # Get recent scans
            self.cursor.execute('''
                SELECT scan_type, start_time, status, findings_count, severity
                FROM scans
                ORDER BY start_time DESC
                LIMIT 10
            ''')
            recent_scans = self.cursor.fetchall()

            # Get statistics
            self.cursor.execute('''
                SELECT
                    COUNT(*) as total_scans,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                    SUM(findings_count) as total_findings
                FROM scans
            ''')
            stats = self.cursor.fetchone()

            status = {
                'running': self.running,
                'recent_scans': recent_scans,
                'statistics': {
                    'total_scans': stats[0],
                    'completed': stats[1],
                    'failed': stats[2],
                    'total_findings': stats[3]
                }
            }

            return status

        except Exception as e:
            self.logger.error(f"Failed to get status: {e}")
            return {'error': str(e)}

    def run(self):
        """Start the security monitor"""
        self.logger.info("=" * 60)
        self.logger.info("Security Monitor Starting")
        self.logger.info("=" * 60)
        self.logger.info(f"Log directory: {self.config['log_dir']}")
        self.logger.info(f"Database: {self.config['db_path']}")
        self.logger.info(f"Scan interval: {self.config['scan_interval']}s")

        # Print enabled scans
        enabled_scans = [name for name, cfg in self.config['scans'].items()
                        if cfg.get('enabled', True)]
        self.logger.info(f"Enabled scans: {', '.join(enabled_scans)}")

        try:
            self.run_monitoring_loop()
        except KeyboardInterrupt:
            self.logger.info("Interrupted by user")
        finally:
            self.cleanup()


def main():
    """Main entry point"""
    monitor = SecurityMonitor(CONFIG)
    monitor.run()


if __name__ == "__main__":
    main()
