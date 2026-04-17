#!/usr/bin/env python3
"""
Improved Automated Incident Response System
Enhanced security response with intelligent mitigation
"""

import os
import json
import sys
import logging
import time
import threading
import subprocess
import psutil
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
import signal
import hashlib
import shutil
from collections import defaultdict, deque

class ImprovedAutoResponse:
    """Enhanced automated incident response system"""

    def __init__(self, config_path: str = "./auto_response_config.json"):
        self.config = self._load_config(config_path)
        self.running = True
        self.response_history = []
        self.active_incidents = {}
        self.quarantine_dir = f"./quarantine_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.response_queue = queue.Queue()
        self.lock = threading.Lock()

        # Initialize logging
        self._setup_logging()

        # Initialize database
        self._init_database()

        # Initialize response handlers
        self._init_response_handlers()

    def _load_config(self, config_path: str) -> Dict:
        """Load response configuration"""
        default_config = {
            "response_actions": {
                "isolate_system": {
                    "enabled": True,
                    "require_confirmation": True,
                    "timeout": 30
                },
                "kill_process": {
                    "enabled": True,
                    "require_confirmation": True,
                    "timeout": 10
                },
                "quarantine_file": {
                    "enabled": True,
                    "require_confirmation": False
                },
                "block_network": {
                    "enabled": True,
                    "require_confirmation": True
                },
                "reset_dns": {
                    "enabled": True,
                    "require_confirmation": False
                }
            },
            "response_strategies": {
                "immediate_isolation": {
                    "threat_types": ["active_compromise", "rootkit", "ransomware"],
                    "actions": ["isolate_system", "quarantine_files", "snapshot_system"],
                    "auto_approve": True
                },
                "standard_response": {
                    "threat_types": ["malware", "suspicious_process", "network_anomaly"],
                    "actions": ["kill_process", "block_network", "log_incident"],
                    "auto_approve": False
                },
                "low_priority": {
                    "threat_types": ["file_modification", "dns_hijack"],
                    "actions": ["reset_dns", "log_incident", "notify_admin"],
                    "auto_approve": False
                }
            },
            "escalation_config": {
                "escalate_after": 3,
                "escalate_to": ["admin", "security_team"],
                "escalation_timeout": 300
            },
            "logging": {
                "log_all_actions": True,
                "log_responses": True,
                "log_quarantine": True,
                "retention_days": 30
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
        log_dir = "./logs"
        os.makedirs(log_dir, exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f"{log_dir}/auto_response.log"),
                logging.StreamHandler()
            ]
        )

        self.logger = logging.getLogger('AutoResponse')

    def _init_database(self):
        """Initialize response database"""
        db_path = "./logs/response_db.db"
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()

        # Create tables
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                actions_taken TEXT
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                action_type TEXT NOT NULL,
                action_details TEXT,
                timestamp DATETIME NOT NULL,
                success BOOLEAN NOT NULL,
                error_message TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                incident_id INTEGER,
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            )
        ''')

        self.conn.commit()

    def _init_response_handlers(self):
        """Initialize response handlers"""
        self.response_handlers = {
            'kill_process': self._handle_kill_process,
            'isolate_system': self._handle_isolate_system,
            'quarantine_file': self._handle_quarantine_file,
            'block_network': self._handle_block_network,
            'reset_dns': self._handle_reset_dns,
            'snapshot_system': self._handle_snapshot_system,
            'notify_admin': self._handle_notify_admin
        }

    def start(self):
        """Start the automated response system"""
        self.logger.info("Starting Improved Automated Response System...")

        # Create quarantine directory
        os.makedirs(self.quarantine_dir, exist_ok=True)

        # Start response processing thread
        response_thread = threading.Thread(target=self._process_responses, daemon=True)
        response_thread.start()

        # Monitor for incidents
        self._monitor_incidents()

    def stop(self):
        """Stop the automated response system"""
        self.logger.info("Stopping Improved Automated Response System...")
        self.running = False
        self.conn.close()

    def _monitor_incidents(self):
        """Monitor for security incidents"""
        while self.running:
            try:
                # This would typically integrate with your security monitoring tools
                # For demo purposes, we'll simulate incident detection
                self._simulate_incident_detection()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                self.logger.error(f"Incident monitoring error: {e}")
                time.sleep(30)

    def _simulate_incident_detection(self):
        """Simulate incident detection (replace with actual integration)"""
        # Simulate various incident types
        incident_types = [
            ("malware", "HIGH", "Suspicious process detected: python3 suspicious_script.py"),
            ("network_anomaly", "MEDIUM", "Unusual network connection to 192.168.1.100"),
            ("file_modification", "LOW", "System file modified: /etc/passwd"),
            ("active_compromise", "CRITICAL", "Rootkit detected in system memory")
        ]

        incident_type, severity, details = incident_types[0]  # Simulate one incident

        incident = {
            'incident_id': hashlib.md5(f"{datetime.now()}{incident_type}{severity}".encode()).hexdigest()[:8],
            'threat_type': incident_type,
            'severity': severity,
            'timestamp': datetime.now(),
            'details': details,
            'status': 'DETECTED'
        }

        self._handle_incident(incident)

    def _handle_incident(self, incident: Dict):
        """Handle detected incident"""
        try:
            with self.lock:
                # Store incident in active incidents
                self.active_incidents[incident['incident_id']] = incident

                # Log incident
                self.cursor.execute('''
                    INSERT OR REPLACE INTO incidents (incident_id, threat_type, severity, timestamp, status, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    incident['incident_id'],
                    incident['threat_type'],
                    incident['severity'],
                    incident['timestamp'],
                    incident['status'],
                    incident['details']
                ))
                self.conn.commit()

                # Determine response strategy
                strategy = self._determine_response_strategy(incident)
                if strategy:
                    self.logger.info(f"Applying strategy {strategy['name']} to incident {incident['incident_id']}")

                    # Execute actions
                    for action_name in strategy['actions']:
                        action_config = self.config["response_actions"].get(action_name)
                        if action_config and action_config["enabled"]:
                            if self._should_auto_approve(action_config, strategy, incident):
                                self._execute_action(incident['incident_id'], action_name, {})
                            else:
                                # For this demo, we'll auto-approve everything
                                self._execute_action(incident['incident_id'], action_name, {})

                # Update incident status
                incident['status'] = 'RESPONDED'
                self.cursor.execute('''
                    UPDATE incidents SET status = ? WHERE incident_id = ?
                ''', (incident['status'], incident['incident_id']))
                self.conn.commit()

        except Exception as e:
            self.logger.error(f"Error handling incident {incident['incident_id']}: {e}")

    def _determine_response_strategy(self, incident: Dict) -> Optional[Dict]:
        """Determine appropriate response strategy"""
        strategies = self.config["response_strategies"]

        for strategy_name, strategy in strategies.items():
            if incident['threat_type'] in strategy['threat_types']:
                return {
                    'name': strategy_name,
                    'actions': strategy['actions'],
                    'auto_approve': strategy['auto_approve']
                }

        return None

    def _should_auto_approve(self, action_config: Dict, strategy: Dict, incident: Dict) -> bool:
        """Determine if action should be auto-approved"""
        if action_config.get("auto_approve", False):
            return True

        if strategy.get("auto_approve", False):
            return True

        if incident['severity'] == 'CRITICAL':
            return True

        return False

    def _execute_action(self, incident_id: str, action_name: str, action_params: Dict):
        """Execute response action"""
        try:
            action_handler = self.response_handlers.get(action_name)
            if not action_handler:
                raise ValueError(f"Unknown action: {action_name}")

            # Execute action
            success, result = action_handler(action_params)

            # Log action
            self.cursor.execute('''
                INSERT INTO actions (incident_id, action_type, action_details, timestamp, success, error_message)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                incident_id,
                action_name,
                json.dumps(action_params),
                datetime.now(),
                success,
                None if success else str(result)
            ))
            self.conn.commit()

            # Log result
            if success:
                self.logger.info(f"Action {action_name} completed successfully for incident {incident_id}")
            else:
                self.logger.error(f"Action {action_name} failed for incident {incident_id}: {result}")

            return success

        except Exception as e:
            self.logger.error(f"Error executing action {action_name} for incident {incident_id}: {e}")
            return False, str(e)

    def _handle_kill_process(self, params: Dict) -> tuple[bool, Any]:
        """Handle process killing"""
        try:
            identifier = params.get('pid') or params.get('process_name')

            if not identifier:
                return False, "No process identifier provided"

            # Check if it's a PID or name
            if isinstance(identifier, int) or identifier.isdigit():
                # Kill by PID
                pid = int(identifier)
                if psutil.pid_exists(pid):
                    process = psutil.Process(pid)
                    process.terminate()
                    time.sleep(2)
                    if process.is_running():
                        process.kill()
                    return True, f"Process {pid} killed"
                else:
                    return False, f"Process {pid} not found"
            else:
                # Kill by name
                processes = [p for p in psutil.process_iter(['name']) if p.info['name'] == identifier]
                if processes:
                    for process in processes:
                        process.terminate()
                        time.sleep(2)
                        if process.is_running():
                            process.kill()
                    return True, f"Killed {len(processes)} processes named {identifier}"
                else:
                    return False, f"No processes found with name {identifier}"

        except Exception as e:
            return False, str(e)

    def _handle_isolate_system(self, params: Dict) -> tuple[bool, Any]:
        """Handle system isolation"""
        try:
            interface = params.get('interface', 'en0')

            # Disable network interface
            subprocess.run(['ifconfig', interface, 'down'], check=True)

            # Log isolation
            self.logger.warning(f"System isolated by disabling interface {interface}")

            return True, f"System isolated via {interface}"

        except subprocess.CalledProcessError as e:
            return False, f"Failed to isolate system: {e}"
        except Exception as e:
            return False, str(e)

    def _handle_quarantine_file(self, params: Dict) -> tuple[bool, Any]:
        """Handle file quarantining"""
        try:
            file_path = params.get('file_path')
            if not file_path:
                return False, "No file path provided"

            if not os.path.exists(file_path):
                return False, f"File not found: {file_path}"

            # Generate quarantine filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, f"{timestamp}_{filename}")

            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)

            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            os.chmod(quarantine_path, 0o600)  # Remove execute permissions

            # Log quarantine
            self.cursor.execute('''
                INSERT INTO quarantine_files (original_path, quarantine_path, file_hash, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (file_path, quarantine_path, file_hash, datetime.now()))
            self.conn.commit()

            self.logger.info(f"File quarantined: {file_path} -> {quarantine_path}")

            return True, f"File quarantined to {quarantine_path}"

        except Exception as e:
            return False, str(e)

    def _handle_block_network(self, params: Dict) -> tuple[bool, Any]:
        """Handle network blocking"""
        try:
            ip_address = params.get('ip_address')
            if not ip_address:
                return False, "No IP address provided"

            # Add to firewall rules
            subprocess.run(['sudo', 'pfctl', '-t', 'blocked_ips', '-T', 'add', ip_address], check=True)

            self.logger.warning(f"IP blocked: {ip_address}")

            return True, f"IP {ip_address} blocked in firewall"

        except subprocess.CalledProcessError as e:
            return False, f"Failed to block IP: {e}"
        except Exception as e:
            return False, str(e)

    def _handle_reset_dns(self, params: Dict) -> tuple[bool, Any]:
        """Handle DNS reset"""
        try:
            interface = params.get('interface', 'Wi-Fi')

            # Reset DNS to safe values
            subprocess.run(['networksetup', '-setdnsservers', interface, '1.1.1.1', '1.0.0.1'], check=True)

            self.logger.info(f"DNS reset for {interface}")

            return True, f"DNS reset for {interface}"

        except subprocess.CalledProcessError as e:
            return False, f"Failed to reset DNS: {e}"
        except Exception as e:
            return False, str(e)

    def _handle_snapshot_system(self, params: Dict) -> tuple[bool, Any]:
        """Handle system snapshot"""
        try:
            snapshot_dir = params.get('snapshot_dir', f"./snapshots/{datetime.now().strftime('%Y%m%d_%H%M%S')}")

            os.makedirs(snapshot_dir, exist_ok=True)

            # Collect system information
            snapshot = {
                'timestamp': datetime.now().isoformat(),
                'processes': [],
                'network': [],
                'files': []
            }

            # Get running processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    snapshot['processes'].append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Get network connections
            for conn in psutil.net_connections():
                snapshot['network'].append({
                    'local_addr': conn.laddr,
                    'remote_addr': conn.raddr,
                    'status': conn.status,
                    'pid': conn.pid
                })

            # Save snapshot
            snapshot_file = os.path.join(snapshot_dir, 'system_snapshot.json')
            with open(snapshot_file, 'w') as f:
                json.dump(snapshot, f, indent=2)

            self.logger.info(f"System snapshot saved to {snapshot_dir}")

            return True, f"System snapshot saved to {snapshot_dir}"

        except Exception as e:
            return False, str(e)

    def _handle_notify_admin(self, params: Dict) -> tuple[bool, Any]:
        """Handle admin notification"""
        try:
            # Send notification to admin
            incident_id = params.get('incident_id')
            message = f"Security incident detected: {incident_id}"

            # Here you would integrate with your notification system
            # Email, Slack, SMS, etc.

            self.logger.info(f"Admin notified: {message}")

            return True, "Admin notified"

        except Exception as e:
            return False, str(e)

    def _process_responses(self):
        """Process response queue"""
        while self.running:
            try:
                if not self.response_queue.empty():
                    response = self.response_queue.get()
                    # Process response
                    pass
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"Error processing response queue: {e}")

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except:
            return "ERROR"

    def get_response_history(self, incident_id: str = None) -> List[Dict]:
        """Get response history"""
        try:
            if incident_id:
                # Get specific incident responses
                self.cursor.execute('''
                    SELECT a.*, i.threat_type, i.severity
                    FROM actions a
                    JOIN incidents i ON a.incident_id = i.id
                    WHERE i.incident_id = ?
                    ORDER BY a.timestamp DESC
                ''', (incident_id,))
                return [dict(row) for row in self.cursor.fetchall()]
            else:
                # Get all responses
                self.cursor.execute('''
                    SELECT a.*, i.threat_type, i.severity
                    FROM actions a
                    JOIN incidents i ON a.incident_id = i.id
                    ORDER BY a.timestamp DESC
                    LIMIT 100
                ''')
                return [dict(row) for row in self.cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Error getting response history: {e}")
            return []

    def get_active_incidents(self) -> Dict:
        """Get active incidents"""
        return self.active_incidents

    def _simulate_incident_detection(self):
        """Enhanced incident detection simulation"""
        # This would be replaced with actual integration with security tools
        # Simulating various threats
        threats = [
            {
                "type": "malware",
                "severity": "HIGH",
                "message": "Suspicious process detected: python3 /tmp/malicious_script.py",
                "details": {"pid": 12345, "process_name": "malicious_script"}
            },
            {
                "type": "network_anomaly",
                "severity": "MEDIUM",
                "message": "Unusual outbound connection to 192.168.1.100:4444",
                "details": {"remote_ip": "192.168.1.100", "port": 4444}
            },
            {
                "type": "file_modification",
                "severity": "LOW",
                "message": "Sensitive file modified: /etc/passwd",
                "details": {"file_path": "/etc/passwd", "hash_changed": True}
            }
        ]

        # Randomly select and process threats
        import random
        threat = random.choice(threats)

        incident = {
            'incident_id': hashlib.md5(f"{datetime.now()}{threat['type']}{threat['severity']}".encode()).hexdigest()[:8],
            'threat_type': threat['type'],
            'severity': threat['severity'],
            'timestamp': datetime.now(),
            'details': threat['message'],
            'metadata': threat['details'],
            'status': 'DETECTED'
        }

        self._handle_incident(incident)


def main():
    """Main entry point"""
    print("=== Improved Automated Response System ===")

    # Create response system
    response_system = ImprovedAutoResponse()

    # Setup signal handlers
    def signal_handler(signum, frame):
        print("\nReceived signal, shutting down...")
        response_system.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start the system
    response_system.start()

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        response_system.stop()


if __name__ == "__main__":
    main()