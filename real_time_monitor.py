#!/usr/bin/env python3
"""
Real-time Security Monitor
Continuously monitor system for security events and threats
"""

import os
import json
import time
import threading
import signal
import sys
import logging
import psutil
import subprocess
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
import queue
import hashlib
import socket
import dns.resolver
import ipaddress
from collections import defaultdict, deque
import re

class RealTimeMonitor:
    """Real-time security monitoring system"""

    def __init__(self, config_path: str = "./realtime_config.json"):
        self.config = self._load_config(config_path)
        self.running = False
        self.event_queue = queue.Queue()
        self.alert_handlers = []
        self.process_history = defaultdict(deque)
        self.file_monitors = {}
        self.network_monitors = {}

        # Initialize logging
        self._setup_logging()

        # Initialize database
        self._init_database()

        # Load signatures
        self._load_signatures()

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration"""
        default_config = {
            "scan_interval": 5,  # seconds
            "alert_threshold": 3,  # events per minute
            "log_retention_days": 30,
            "max_queue_size": 1000,
            "enable_real_time_analysis": True,
            "suspicious_processes": [
                "python", "bash", "sh", "curl", "wget", "nc", "netcat",
                "socat", "telnet", "ssh", "scp", "rsync", "ftp"
            ],
            "suspicious_ips": [],
            "monitor_directories": [
                "/tmp", "/var/tmp", "/private/var/tmp",
                "/Library/Application Support", "~/.local"
            ],
            "critical_paths": [
                "/etc/passwd", "/etc/shadow", "/etc/sudoers",
                "/Library/LaunchAgents", "/Library/LaunchDaemons"
            ],
            "alert_channels": {
                "email": {"enabled": False},
                "slack": {"enabled": False},
                "pushover": {"enabled": False}
            }
        }

        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    default_config.update(config)
        except Exception as e:
            logging.error(f"Error loading config: {e}")

        return default_config

    def _setup_logging(self):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

        # File handler with rotation
        log_file = "./logs/realtime_monitor.log"
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter(log_format))

        self.logger = logging.getLogger('RealTimeMonitor')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(handler)

        # Console handler
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(log_format))
        self.logger.addHandler(console)

    def _init_database(self):
        """Initialize SQLite database for event storage"""
        db_path = "./logs/realtime_monitor.db"
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()

        # Create tables
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT,
                details TEXT,
                source_ip TEXT,
                process_info TEXT
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT,
                resolved BOOLEAN DEFAULT 0
            )
        ''')

        self.conn.commit()

    def _load_signatures(self):
        """Load threat signatures and patterns"""
        self.signatures = {
            "malware_hashes": set(),
            "suspicious_commands": [
                r"python\s+.*--exec",
                r"bash\s+-c.*\\",
                r"sh\s+-c.*\\",
                r"curl\s+-.*eval",
                r"wget\s+-.*-O.*-|",
                r"nc\s+-l",
                r"netcat\s+-l",
                r"chmod\s+\+.*",
                r"chown\s+root.*",
                r"/bin/bash.*-c.*\\"
            ],
            "suspicious_filenames": [
                "reverse", "shell", "backdoor", "rootkit",
                "keylogger", "spyware", "trojan", "malware"
            ],
            "suspicious_ips": [],
            "c2_domains": [
                "malware.cz", "evil-rats.net", "botnet-control.org",
                "data-exfiltrate.com", "stealer-data.com"
            ]
        }

    def start(self):
        """Start the real-time monitor"""
        self.logger.info("Starting Real-time Security Monitor...")
        self.running = True

        # Start monitoring threads
        threads = [
            threading.Thread(target=self._monitor_processes, daemon=True),
            threading.Thread(target=self._monitor_network, daemon=True),
            threading.Thread(target=self._monitor_files, daemon=True),
            threading.Thread(target=self._monitor_system, daemon=True),
            threading.Thread(target=self._analyze_events, daemon=True)
        ]

        for thread in threads:
            thread.start()

        # Start main loop
        self._main_loop()

    def stop(self):
        """Stop the real-time monitor"""
        self.logger.info("Stopping Real-time Security Monitor...")
        self.running = False
        self.conn.close()

    def _main_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Process events from queue
                self._process_event_queue()

                # Check system health
                self._check_system_health()

                # Clean old logs
                self._cleanup_logs()

                time.sleep(self.config["scan_interval"])
            except KeyboardInterrupt:
                self.stop()
                break
            except Exception as e:
                self.logger.error(f"Main loop error: {e}")
                time.sleep(self.config["scan_interval"])

    def _monitor_processes(self):
        """Monitor running processes"""
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
                    try:
                        proc_info = proc.info

                        # Check for suspicious processes
                        if self._is_suspicious_process(proc_info):
                            self._log_event(
                                "suspicious_process",
                                "HIGH",
                                f"Suspicious process detected: {proc_info['name']} (PID: {proc_info['pid']})",
                                json.dumps(proc_info)
                            )

                        # Track process history
                        self.process_history[proc_info['pid']].append({
                            'timestamp': datetime.now(),
                            'cpu': proc_info['cpu_percent'],
                            'memory': proc_info['memory_percent']
                        })

                        # Keep only last 100 entries
                        if len(self.process_history[proc_info['pid']]) > 100:
                            self.process_history[proc_info['pid']].popleft()

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

            except Exception as e:
                self.logger.error(f"Process monitoring error: {e}")
            time.sleep(self.config["scan_interval"] * 2)

    def _monitor_network(self):
        """Monitor network connections and traffic"""
        while self.running:
            try:
                # Check network connections
                for conn in psutil.net_connections():
                    if conn.status == 'ESTABLISHED':
                        remote_addr = conn.raddr

                        if remote_addr:
                            ip, port = remote_addr

                            # Check for suspicious IPs
                            if self._is_suspicious_ip(ip):
                                self._log_event(
                                    "suspicious_connection",
                                    "MEDIUM",
                                    f"Suspicious connection to {ip}:{port}",
                                    json.dumps({
                                        'local_addr': conn.laddr,
                                        'remote_addr': remote_addr,
                                        'pid': conn.pid,
                                        'status': conn.status
                                    })
                                )

                            # Check for C2 domains
                            try:
                                reverse_dns = socket.gethostbyaddr(ip)[0]
                                for domain in self.signatures["c2_domains"]:
                                    if domain in reverse_dns.lower():
                                        self._log_event(
                                            "c2_connection",
                                            "HIGH",
                                            f"C2 connection detected: {ip} -> {reverse_dns}",
                                            json.dumps({
                                                'ip': ip,
                                                'domain': reverse_dns,
                                                'port': port
                                            })
                                        )
                            except:
                                pass

                # Monitor DNS queries
                self._monitor_dns()

            except Exception as e:
                self.logger.error(f"Network monitoring error: {e}")
            time.sleep(self.config["scan_interval"] * 5)

    def _monitor_files(self):
        """Monitor file system changes"""
        while self.running:
            try:
                # Monitor critical paths
                for path in self.config["critical_paths"]:
                    if os.path.exists(path):
                        self._monitor_directory(path)

                # Monitor suspicious directories
                for directory in self.config["monitor_directories"]:
                    expanded_dir = os.path.expanduser(directory)
                    if os.path.exists(expanded_dir):
                        self._monitor_directory(expanded_dir)

            except Exception as e:
                self.logger.error(f"File monitoring error: {e}")
            time.sleep(self.config["scan_interval"])

    def _monitor_system(self):
        """Monitor system resources and integrity"""
        while self.running:
            try:
                # Check CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > 90:
                    self._log_event(
                        "high_cpu_usage",
                        "MEDIUM",
                        f"High CPU usage: {cpu_percent}%",
                        json.dumps({'cpu_percent': cpu_percent})
                    )

                # Check memory usage
                memory = psutil.virtual_memory()
                if memory.percent > 85:
                    self._log_event(
                        "high_memory_usage",
                        "MEDIUM",
                        f"High memory usage: {memory.percent}%",
                        json.dumps(memory._asdict())
                    )

                # Check disk usage
                disk = psutil.disk_usage('/')
                if disk.percent > 90:
                    self._log_event(
                        "high_disk_usage",
                        "MEDIUM",
                        f"High disk usage: {disk.percent}%",
                        json.dumps(disk._asdict())
                    )

            except Exception as e:
                self.logger.error(f"System monitoring error: {e}")
            time.sleep(self.config["scan_interval"] * 10)

    def _monitor_dns(self):
        """Monitor DNS queries"""
        try:
            # Check DNS configuration
            dns_servers = self._get_dns_servers()
            for server in dns_servers:
                if self._is_suspicious_ip(server):
                    self._log_event(
                        "suspicious_dns",
                        "HIGH",
                        f"Suspicious DNS server: {server}",
                        json.dumps({'dns_server': server})
                    )
        except Exception as e:
            self.logger.error(f"DNS monitoring error: {e}")

    def _get_dns_servers(self) -> List[str]:
        """Get current DNS servers"""
        servers = []

        # Try to get from networksetup
        try:
            result = subprocess.run(['networksetup', '-getdnsservers', 'Wi-Fi'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip() and not line.startswith('DNS servers'):
                        servers.append(line.strip())
        except:
            pass

        return servers

    def _is_suspicious_process(self, proc_info: Dict) -> bool:
        """Check if process is suspicious"""
        if not proc_info.get('cmdline'):
            return False

        cmdline = ' '.join(proc_info['cmdline']).lower()
        process_name = proc_info.get('name', '').lower()

        # Check for suspicious command patterns
        for pattern in self.signatures["suspicious_commands"]:
            if re.search(pattern, cmdline):
                return True

        # Check for suspicious process names
        for suspicious in self.signatures["suspicious_filenames"]:
            if suspicious in process_name:
                return True

        # Check for high resource usage
        if proc_info.get('cpu_percent', 0) > 80 or proc_info.get('memory_percent', 0) > 80:
            return True

        return False

    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious"""
        try:
            # Check if it's a private IP
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return False

            # Check against known suspicious IPs
            if ip in self.signatures["suspicious_ips"]:
                return True

            # Check for unusual ports or patterns
            return False
        except ValueError:
            return False

    def _monitor_directory(self, directory: str):
        """Monitor directory for changes"""
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)

                    # Get file stats
                    stat = os.stat(file_path)
                    mtime = datetime.fromtimestamp(stat.st_mtime)

                    # Check for recently modified files
                    if mtime > datetime.now() - timedelta(minutes=5):
                        # Check file properties
                        if self._is_suspicious_file(file_path, stat):
                            self._log_event(
                                "suspicious_file",
                                "MEDIUM",
                                f"Suspicious file: {file_path}",
                                json.dumps({
                                    'path': file_path,
                                    'size': stat.st_size,
                                    'mode': stat.st_mode,
                                    'mtime': mtime.isoformat()
                                })
                            )
        except Exception as e:
            self.logger.error(f"Directory monitoring error for {directory}: {e}")

    def _is_suspicious_file(self, file_path: str, stat) -> bool:
        """Check if file is suspicious"""
        file_name = os.path.basename(file_path).lower()

        # Check for executable files in suspicious locations
        for suspicious in self.signatures["suspicious_filenames"]:
            if suspicious in file_name:
                return True

        # Check for unusually large files
        if stat.st_size > 10 * 1024 * 1024:  # 10MB
            return True

        # Check for world-writable executables
        if os.access(file_path, os.X_OK) and os.access(file_path, os.W_OK):
            return True

        return False

    def _log_event(self, event_type: str, severity: str, message: str, details: str = ""):
        """Log security event"""
        event = {
            'timestamp': datetime.now(),
            'event_type': event_type,
            'severity': severity,
            'message': message,
            'details': details,
            'source_ip': socket.gethostbyname(socket.gethostname())
        }

        # Add to queue
        if self.event_queue.qsize() < self.config["max_queue_size"]:
            self.event_queue.put(event)

        # Check for alert conditions
        self._check_alert_conditions(event)

    def _process_event_queue(self):
        """Process events from queue"""
        while not self.event_queue.empty():
            try:
                event = self.event_queue.get()

                # Save to database
                self.cursor.execute('''
                    INSERT INTO events (timestamp, event_type, severity, message, details, source_ip)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    event['timestamp'],
                    event['event_type'],
                    event['severity'],
                    event['message'],
                    event['details'],
                    event['source_ip']
                ))
                self.conn.commit()

                # Log event
                self.logger.log(
                    getattr(logging, event['severity']),
                    f"{event['event_type']}: {event['message']}"
                )

            except Exception as e:
                self.logger.error(f"Error processing event: {e}")

    def _check_alert_conditions(self, event: Dict):
        """Check if event should trigger an alert"""
        # Simple threshold-based alerting
        threshold = self.config["alert_threshold"]

        # Count events in the last minute
        recent_events = self.cursor.execute('''
            SELECT COUNT(*) FROM events
            WHERE timestamp > datetime('now', '-1 minute')
            AND event_type = ?
        ''', (event['event_type'],)).fetchone()[0]

        if recent_events >= threshold:
            self._create_alert(event['event_type'], event['severity'], event['message'])

    def _create_alert(self, alert_type: str, severity: str, message: str):
        """Create security alert"""
        alert = {
            'timestamp': datetime.now(),
            'alert_type': alert_type,
            'severity': severity,
            'message': message,
            'resolved': False
        }

        # Save to database
        self.cursor.execute('''
            INSERT INTO alerts (timestamp, alert_type, severity, message, resolved)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            alert['timestamp'],
            alert['alert_type'],
            alert['severity'],
            alert['message'],
            alert['resolved']
        ))
        self.conn.commit()

        # Send alerts to configured channels
        self._send_alert(alert)

    def _send_alert(self, alert: Dict):
        """Send alert through configured channels"""
        # Email alerts
        if self.config["alert_channels"]["email"]["enabled"]:
            self._send_email_alert(alert)

        # Slack alerts
        if self.config["alert_channels"]["slack"]["enabled"]:
            self._send_slack_alert(alert)

        # Pushover alerts
        if self.config["alert_channels"]["pushover"]["enabled"]:
            self._send_pushover_alert(alert)

    def _send_email_alert(self, alert: Dict):
        """Send email alert"""
        # Implementation would use smtplib to send email
        pass

    def _send_slack_alert(self, alert: Dict):
        """Send Slack alert"""
        # Implementation would use Slack webhook
        pass

    def _send_pushover_alert(self, alert: Dict):
        """Send Pushover alert"""
        # Implementation would use Pushover API
        pass

    def _analyze_events(self):
        """Analyze events for patterns"""
        while self.running:
            try:
                # Simple pattern detection
                self._detect_event_patterns()
                time.sleep(60)  # Run every minute
            except Exception as e:
                self.logger.error(f"Event analysis error: {e}")

    def _detect_event_patterns(self):
        """Detect event patterns"""
        # Get recent events
        recent_events = self.cursor.execute('''
            SELECT event_type, severity, COUNT(*) as count
            FROM events
            WHERE timestamp > datetime('now', '-1 hour')
            GROUP BY event_type, severity
            HAVING count > 5
        ''').fetchall()

        for event_type, severity, count in recent_events:
            self.logger.warning(f"Pattern detected: {event_type} ({severity}) - {count} events in 1 hour")

    def _check_system_health(self):
        """Check overall system health"""
        try:
            # Check for critical errors
            critical_events = self.cursor.execute('''
                SELECT COUNT(*) FROM events
                WHERE severity = 'CRITICAL'
                AND timestamp > datetime('now', '-5 minutes')
            ''').fetchone()[0]

            if critical_events > 0:
                self.logger.error(f"Critical events detected: {critical_events}")

        except Exception as e:
            self.logger.error(f"System health check error: {e}")

    def _cleanup_logs(self):
        """Clean up old logs"""
        try:
            # Delete events older than retention period
            retention_days = self.config["log_retention_days"]
            self.cursor.execute('''
                DELETE FROM events
                WHERE timestamp < datetime('now', '-{} days')
            ''', (retention_days,))
            self.conn.commit()

        except Exception as e:
            self.logger.error(f"Log cleanup error: {e}")

    def get_system_status(self) -> Dict:
        """Get current system status"""
        try:
            # Get event counts
            event_counts = self.cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM events
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY severity
            ''').fetchall()

            # Get alert counts
            alert_counts = self.cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM alerts
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY severity
            ''').fetchall()

            return {
                'timestamp': datetime.now().isoformat(),
                'event_counts': {severity: count for severity, count in event_counts},
                'alert_counts': {severity: count for severity, count in alert_counts},
                'queue_size': self.event_queue.qsize(),
                'running': self.running
            }

        except Exception as e:
            self.logger.error(f"Error getting system status: {e}")
            return {'error': str(e)}

def main():
    """Main entry point"""
    print("=== Real-time Security Monitor ===")

    # Create and start monitor
    monitor = RealTimeMonitor()

    # Setup signal handlers
    def signal_handler(signum, frame):
        print("\nReceived signal, shutting down...")
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start monitoring
    monitor.start()

if __name__ == "__main__":
    main()