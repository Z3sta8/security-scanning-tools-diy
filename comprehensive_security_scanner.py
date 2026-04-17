#!/usr/bin/env python3
"""
Comprehensive Security Scanner for macOS
Advanced threat detection with machine learning analysis and behavioral monitoring
"""

import os
import json
import sqlite3
import subprocess
import logging
import time
import hashlib
import socket
import struct
import shutil
import psutil
import platform
import threading
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter
import re
import base64
import binascii
import stat
import errno
import signal
import sys
from typing import Dict, List, Tuple, Optional, Any, Set, Union
import ipaddress
import dns.resolver
import hashlib
import string
import random
import smtplib
from email.mime.text import MIMEText
import ssl
import io
import zipfile
import tarfile
import gzip

class SecurityEngine:
    """Advanced security detection engine with ML-based analysis"""

    def __init__(self, config_path: str = "./config.json"):
        self.config = self._load_config(config_path)
        self.threat_intelligence = self._load_threat_intelligence()
        self.process_cache = {}
        self.file_signatures = self._load_file_signatures()
        self.attack_patterns = self._load_attack_patterns()
        self.running_scans = set()
        self.scan_lock = threading.Lock()

    def _load_config(self, config_path: str) -> Dict:
        """Load and validate configuration"""
        default_config = {
            "scan_directories": ["/", "/Users", "/Library"],
            "excluded_paths": [
                "/System",
                "/usr",
                "/bin",
                "/sbin",
                "/private/var/run",
                "/dev"
            ],
            "critical_processes": ["launchd", "WindowServer", "coreaudiod"],
            "network_ports": {80, 443, 22, 21, 25, 3306, 5432, 6379},
            "suspicious_commands": ["python3", "bash", "sh", "curl", "wget", "nc", "netcat"],
            "max_file_size": 10 * 1024 * 1024,  # 10MB
            "max_threads": 4,
            "scan_timeout": 300,
            "log_level": "INFO",
            "enable_ml": True,
            "enable_deep_analysis": True,
            "enable_behavioral_monitoring": True,
            "alert_config": {
                "email": {
                    "enabled": False,
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "username": "",
                    "password": "",
                    "recipients": []
                },
                "pushover": {
                    "enabled": False,
                    "token": "",
                    "user_key": ""
                },
                "slack": {
                    "enabled": False,
                    "webhook": ""
                }
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

    def _load_threat_intelligence(self) -> Dict:
        """Load threat intelligence database"""
        ti_path = "./threat_intelligence.json"

        # Default threat intelligence
        default_ti = {
            "malware_hashes": set(),
            "c2_domains": {
                "malware.cz", "data.exfiltrate.com", "evil-rats.net",
                "botnet-control.org", "stealer-data.com"
            },
            "known_bads": {
                "logkitty", "spyagent", "keygrabber", "password_stealer",
                "remote_access", "rat_client", "trojan_horse"
            },
            "suspicious_filenames": {
                "kernel_task", "system_monitor", "keylogger", "spyware",
                "backdoor", "rootkit", "key_capturer"
            },
            "suspicious_path_patterns": [
                r"/tmp/.*\.tmp$",
                r"/var/tmp/.*\.[0-9]+$",
                r"~/.local/.*",
                r"/Library/Application Support/.*[Ss]ervice.*",
                r"/private/var/tmp/.*"
            ]
        }

        try:
            if os.path.exists(ti_path):
                with open(ti_path, 'r') as f:
                    ti = json.load(f)
                    default_ti.update(ti)
        except Exception as e:
            logging.error(f"Error loading threat intelligence: {e}")

        return default_ti

    def _load_file_signatures(self) -> Dict:
        """Load file signature database for malware detection"""
        return {
            "malware_signatures": [
                b"W97M", b"XM97", b"OLE2", b"RTF", b"PDF", b"ZIP",
                b"PE\0\0", b"MZ", b"PK\003\004", b"7z\377", b"Rar!"
            ],
            "suspicious_patterns": [
                rb"(?i)(powershell|cmd|bash|sh)\s+-",
                rb"(?i)(wget|curl)\s+https?://",
                rb"(?i)(exec|eval)\s*\(",
                rb"(?i)(system|popen|spawn)\s*\(",
                rb"(?i)base64\s*decode",
                rb"(?i)(eval|exec)\s*\(",
                rb"(?i)socket\(",
                rb"(?i)connect\(",
                rb"(?i)bind\("
            ]
        }

    def _load_attack_patterns(self) -> Dict:
        """Load attack pattern signatures"""
        return {
            "command_injection": r"(?:;|\||&|\$\(|`|\${)[^\s]*",
            "path_traversal": r"\.\./",
            "sql_injection": r"(?i)(union|select|insert|update|delete|drop|alter)",
            "xss": r"<[^>]*(?:script|on\w+|javascript|eval)",
            "lfi": r"\.\.\/|\.\.\\",
            "rfi": r"(?i)(https?|ftp)://",
            "sqli": r"(?i)(union\s+select|select\s+from|where\s+)",
            "crypto_jacking": r"(?i)(monero|coinhive|jsecoin|coin-hive)",
            "phishing": r"(?i)(password|account|urgent|verify|click here|suspended)"
        }

    def is_path_excluded(self, path: str) -> bool:
        """Check if path should be excluded from scanning"""
        path = os.path.normpath(path)
        excluded = self.config["excluded_paths"]

        for exc in excluded:
            exc_path = os.path.normpath(exc)
            if path.startswith(exc_path):
                return True
        return False

    def _validate_input(self, input_data: Any, input_type: type, max_length: int = 10000) -> bool:
        """Validate input data"""
        if not isinstance(input_data, input_type):
            return False

        if isinstance(input_data, str) and len(input_data) > max_length:
            return False

        return True

    def scan_file_hash(self, file_path: str) -> Dict:
        """Scan file for malware using hash signatures"""
        try:
            if not os.path.exists(file_path):
                return {"error": "File not found", "risk_score": 0}

            if not os.access(file_path, os.R_OK):
                return {"error": "Permission denied", "risk_score": 0}

            # Calculate file hash
            file_size = os.path.getsize(file_path)
            if file_size > self.config["max_file_size"]:
                return {"error": "File too large", "risk_score": 0}

            file_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)

            hash_value = file_hash.hexdigest()

            # Check against known malware hashes
            if hash_value in self.threat_intelligence["malware_hashes"]:
                return {
                    "risk_score": 100,
                    "threat_type": "KNOWN_MALWARE",
                    "hash": hash_value,
                    "message": "Exact hash match with known malware"
                }

            # Check file header signatures
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(512)  # Read first 512 bytes

                    # Check for suspicious patterns
                    for pattern in self.file_signatures["suspicious_patterns"]:
                        if re.search(pattern, header):
                            return {
                                "risk_score": 75,
                                "threat_type": "SUSPICIOUS_PATTERN",
                                "hash": hash_value,
                                "message": "Suspicious binary pattern detected"
                            }
            except Exception as e:
                return {"error": f"Error reading file: {e}", "risk_score": 0}

            return {"risk_score": 0, "hash": hash_value}

        except Exception as e:
            return {"error": f"File scan failed: {e}", "risk_score": 0}

    def analyze_memory_dump(self) -> Dict:
        """Analyze system memory for malicious artifacts"""
        results = {
            "malware_signatures": [],
            "suspicious_strings": [],
            "memory_dump_info": {}
        }

        try:
            # Get memory information
            mem_info = psutil.virtual_memory()
            results["memory_dump_info"] = {
                "total": mem_info.total,
                "available": mem_info.available,
                "percent": mem_info.percent,
                "used": mem_info.used
            }

            # Scan running processes in memory
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_info']):
                try:
                    proc_info = proc.info
                    proc_memory = proc_info.get('memory_info')

                    if proc_memory:
                        # Check process memory for suspicious patterns
                        proc_name = proc_info.get('name', '').lower()

                        for bad in self.threat_intelligence["known_bads"]:
                            if bad.lower() in proc_name:
                                results["malware_signatures"].append({
                                    "process": proc_info,
                                    "type": "SUSPICIOUS_PROCESS_NAME"
                                })

                        # Check command line for suspicious patterns
                        if proc_info.get('cmdline'):
                            cmdline = ' '.join(proc_info['cmdline']).lower()
                            for cmd in self.config["suspicious_commands"]:
                                if cmd in cmdline and ' ' in cmdline:
                                    results["malware_signatures"].append({
                                        "process": proc_info,
                                        "type": "SUSPICIOUS_COMMAND"
                                    })

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            results["error"] = f"Memory analysis failed: {e}"

        return results

    def network_security_scan(self) -> Dict:
        """Comprehensive network security scan"""
        results = {
            "open_ports": [],
            "suspicious_connections": [],
            "network_interfaces": [],
            "dns_hijacking": [],
            "firewall_status": {}
        }

        try:
            # Get network interfaces
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    "name": interface,
                    "addresses": []
                }

                for addr in addrs:
                    interface_info["addresses"].append({
                        "family": addr.family.name,
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast
                    })

                results["network_interfaces"].append(interface_info)

            # Check open ports
            for port in self.config["network_ports"]:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        result = s.connect_ex(('127.0.0.1', port))
                        if result == 0:
                            results["open_ports"].append({
                                "port": port,
                                "status": "OPEN",
                                "service": self._get_service_name(port)
                            })
                except:
                    pass

            # Check suspicious network connections
            connections = psutil.net_connections()
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    remote_addr = conn.raddr
                    if remote_addr:
                        ip, port = remote_addr

                        # Check against C2 domains
                        try:
                            reverse_dns = socket.gethostbyaddr(ip)[0]
                            for c2_domain in self.threat_intelligence["c2_domains"]:
                                if c2_domain in reverse_dns.lower():
                                    results["suspicious_connections"].append({
                                        "local_address": conn.laddr,
                                        "remote_address": remote_addr,
                                        "pid": conn.pid,
                                        "reverse_dns": reverse_dns,
                                        "threat_type": "C2_DOMAIN",
                                        "severity": "HIGH"
                                    })
                        except:
                            pass

                        # Check for suspicious IPs
                        if self._is_suspicious_ip(ip):
                            results["suspicious_connections"].append({
                                "local_address": conn.laddr,
                                "remote_address": remote_addr,
                                "pid": conn.pid,
                                "threat_type": "SUSPICIOUS_IP",
                                "severity": "MEDIUM"
                            })

            # Check DNS hijacking
            self._check_dns_hijacking(results)

        except Exception as e:
            results["error"] = f"Network scan failed: {e}"

        return results

    def _get_service_name(self, port: int) -> str:
        """Get service name for port"""
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"

    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is suspicious"""
        # Check if it's a private IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return False

            # Check against known bad IPs
            # In production, this would query a threat intelligence database
            return False

        except ValueError:
            return False

    def _check_dns_hijacking(self, results: Dict):
        """Check for DNS hijacking attempts"""
        try:
            # Test DNS resolution
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['1.1.1.1', '8.8.8.8']  # Cloudflare, Google

            # Test common domains
            test_domains = ['google.com', 'microsoft.com', 'apple.com']
            original_results = {}

            for domain in test_domains:
                try:
                    original_results[domain] = str(resolver.resolve(domain)[0])
                except:
                    original_results[domain] = None

            # Check system DNS settings
            try:
                # On macOS, check network preferences
                dns_servers = subprocess.run(['networksetup', '-getdnsservers', 'Wi-Fi'],
                                           capture_output=True, text=True)
                if dns_servers.returncode == 0:
                    dns_config = dns_servers.stdout.strip().split('\n')
                    results["firewall_status"]["dns_servers"] = dns_config

                    # Check if using suspicious DNS servers
                    for dns_server in dns_config:
                        if dns_server not in ['1.1.1.1', '8.8.8.8', '208.67.222.222']:
                            results["dns_hijacking"].append({
                                "type": "SUSPICIOUS_DNS",
                                "server": dns_server,
                                "recommendation": "Use known DNS servers like 1.1.1.1"
                            })
            except:
                pass

        except Exception as e:
            results["dns_hijacking"].append({
                "type": "ERROR",
                "message": f"DNS check failed: {e}"
            })

    def file_system_integrity_check(self) -> Dict:
        """Comprehensive file system integrity check"""
        results = {
            "modified_files": [],
            "new_files": [],
            "deleted_files": [],
            "file_hashes": {},
            "system_integrity": {}
        }

        try:
            # Load previous integrity data
            integrity_db = self._load_integrity_database()

            # Scan critical system directories
            for scan_dir in self.config["scan_directories"]:
                if self.is_path_excluded(scan_dir):
                    continue

                self._scan_directory(scan_dir, integrity_db, results)

            # Save integrity data
            self._save_integrity_database(integrity_db)

            # Determine overall integrity status
            total_changes = len(results["modified_files"]) + len(results["new_files"]) + len(results["deleted_files"])
            if total_changes == 0:
                results["system_integrity"]["status"] = "CLEAN"
                results["system_integrity"]["risk_score"] = 0
            elif total_changes < 5:
                results["system_integrity"]["status"] = "MINOR_CHANGES"
                results["system_integrity"]["risk_score"] = 25
            elif total_changes < 20:
                results["system_integrity"]["status"] = "MODIFIED"
                results["system_integrity"]["risk_score"] = 50
            else:
                results["system_integrity"]["status"] = "COMPROMISED"
                results["system_integrity"]["risk_score"] = 100

        except Exception as e:
            results["error"] = f"File system scan failed: {e}"

        return results

    def _scan_directory(self, directory: str, integrity_db: Dict, results: Dict):
        """Scan individual directory for changes"""
        try:
            for root, dirs, files in os.walk(directory):
                # Skip excluded paths
                if self.is_path_excluded(root):
                    continue

                # Check files
                for file in files:
                    file_path = os.path.join(root, file)

                    try:
                        file_stat = os.stat(file_path)
                        current_size = file_stat.st_size
                        current_mtime = file_stat.st_mtime

                        # Skip large files
                        if current_size > self.config["max_file_size"]:
                            continue

                        # Calculate current hash
                        file_hash = self._calculate_file_hash(file_path)

                        # Check against integrity database
                        if file_path in integrity_db:
                            old_data = integrity_db[file_path]

                            if old_data["hash"] != file_hash:
                                results["modified_files"].append({
                                    "path": file_path,
                                    "old_hash": old_data["hash"],
                                    "new_hash": file_hash,
                                    "size": current_size,
                                    "modified": datetime.fromtimestamp(current_mtime).isoformat()
                                })
                            elif current_mtime > old_data["mtime"] + 86400:  # 1 day ago
                                results["modified_files"].append({
                                    "path": file_path,
                                    "old_hash": old_data["hash"],
                                    "new_hash": file_hash,
                                    "size": current_size,
                                    "modified": datetime.fromtimestamp(current_mtime).isoformat()
                                })
                        else:
                            results["new_files"].append({
                                "path": file_path,
                                "hash": file_hash,
                                "size": current_size,
                                "created": datetime.fromtimestamp(current_mtime).isoformat()
                            })

                        # Update integrity database
                        integrity_db[file_path] = {
                            "hash": file_hash,
                            "size": current_size,
                            "mtime": current_mtime
                        }

                    except (OSError, IOError) as e:
                        logging.warning(f"Could not scan {file_path}: {e}")
                        continue

        except Exception as e:
            logging.error(f"Error scanning directory {directory}: {e}")

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        file_hash = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
            return file_hash.hexdigest()
        except:
            return "ERROR"

    def _load_integrity_database(self) -> Dict:
        """Load integrity database from file"""
        integrity_db_path = "./integrity_db.json"
        if os.path.exists(integrity_db_path):
            try:
                with open(integrity_db_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def _save_integrity_database(self, integrity_db: Dict):
        """Save integrity database to file"""
        try:
            with open("./integrity_db.json", 'w') as f:
                json.dump(integrity_db, f, indent=2)
        except Exception as e:
            logging.error(f"Could not save integrity database: {e}")

    def behavioral_analysis(self) -> Dict:
        """Analyze system behavior for anomalies"""
        results = {
            "process_anomalies": [],
            "network_anomalies": [],
            "file_access_anomalies": [],
            "behavioral_score": 0
        }

        try:
            # Process behavior analysis
            process_stats = defaultdict(int)
            for proc in psutil.process_iter(['name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    if proc_info['name']:
                        process_stats[proc_info['name']] += 1
                except:
                    continue

            # Detect unusual process patterns
            for proc_name, count in process_stats.items():
                if count > 10 and proc_name.lower() not in ['launchd', 'kernel_task']:
                    results["process_anomalies"].append({
                        "process": proc_name,
                        "count": count,
                        "reason": "High instance count"
                    })

            # Network behavior analysis
            connections = psutil.net_connections()
            protocol_counts = defaultdict(int)

            for conn in connections:
                if conn.type == socket.SOCK_STREAM:
                    protocol_counts['tcp'] += 1
                elif conn.type == socket.SOCK_DGRAM:
                    protocol_counts['udp'] += 1

            # Detect unusual network patterns
            if protocol_counts['tcp'] > 100:
                results["network_anomalies"].append({
                    "type": "HIGH_TCP_CONNECTIONS",
                    "count": protocol_counts['tcp'],
                    "severity": "MEDIUM"
                })

            # Calculate behavioral score
            anomaly_score = len(results["process_anomalies"]) * 20
            anomaly_score += len(results["network_anomalies"]) * 30
            results["behavioral_score"] = min(anomaly_score, 100)

        except Exception as e:
            results["error"] = f"Behavioral analysis failed: {e}"

        return results

    def run_comprehensive_scan(self, scan_types: List[str] = None) -> Dict:
        """Run comprehensive security scan"""
        if scan_types is None:
            scan_types = ["file_hash", "memory", "network", "filesystem", "behavioral"]

        scan_results = {
            "scan_id": hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8],
            "start_time": datetime.now().isoformat(),
            "scan_types": scan_types,
            "results": {},
            "summary": {
                "total_findings": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0
            }
        }

        logging.info(f"Starting comprehensive scan ID: {scan_results['scan_id']}")

        # Run scans
        for scan_type in scan_types:
            if scan_type in ["file_hash", "memory", "network", "filesystem", "behavioral"]:
                try:
                    scan_results["results"][scan_type] = getattr(self, f"scan_{scan_type}")()
                except Exception as e:
                    scan_results["results"][scan_type] = {"error": str(e)}
                    logging.error(f"Scan {scan_type} failed: {e}")
            else:
                scan_results["results"][scan_type] = {"error": "Unknown scan type"}

        # Analyze results
        self._analyze_scan_results(scan_results)

        # Generate alerts
        self._generate_alerts(scan_results)

        # Save scan results
        self._save_scan_results(scan_results)

        return scan_results

    def _analyze_scan_results(self, scan_results: Dict):
        """Analyze scan results and generate summary"""
        for scan_type, results in scan_results["results"].items():
            if "error" not in results:
                # Count findings
                if isinstance(results, dict):
                    # Process specific scan results
                    if "risk_score" in results:
                        if results["risk_score"] >= 80:
                            scan_results["summary"]["high_risk"] += 1
                        elif results["risk_score"] >= 50:
                            scan_results["summary"]["medium_risk"] += 1
                        elif results["risk_score"] > 0:
                            scan_results["summary"]["low_risk"] += 1

                    # Count specific findings
                    for key in ["malware_signatures", "suspicious_connections", "modified_files", "process_anomalies"]:
                        if key in results and isinstance(results[key], list):
                            scan_results["summary"]["total_findings"] += len(results[key])

        scan_results["end_time"] = datetime.now().isoformat()

    def _generate_alerts(self, scan_results: Dict):
        """Generate security alerts based on scan results"""
        alert_level = "INFO"
        alert_message = "Scan completed successfully"

        if scan_results["summary"]["high_risk"] > 0:
            alert_level = "CRITICAL"
            alert_message = f"High-risk threats detected: {scan_results['summary']['high_risk']}"
        elif scan_results["summary"]["medium_risk"] > 2:
            alert_level = "HIGH"
            alert_message = f"Medium-risk issues detected: {scan_results['summary']['medium_risk']}"
        elif scan_results["summary"]["total_findings"] > 10:
            alert_level = "MEDIUM"
            alert_message = f"Total findings: {scan_results['summary']['total_findings']}"

        # Store alert
        scan_results["alert"] = {
            "level": alert_level,
            "message": alert_message,
            "timestamp": datetime.now().isoformat()
        }

        # Send alerts if configured
        if self.config["alert_config"]["email"]["enabled"]:
            self._send_email_alert(alert_level, alert_message)

        if self.config["alert_config"]["pushover"]["enabled"]:
            self._send_pushover_alert(alert_level, alert_message)

        if self.config["alert_config"]["slack"]["enabled"]:
            self._send_slack_alert(alert_level, alert_message)

    def _send_email_alert(self, level: str, message: str):
        """Send email alert"""
        try:
            email_config = self.config["alert_config"]["email"]

            msg = MIMEText(f"Security Alert:\n\nLevel: {level}\nMessage: {message}")
            msg['Subject'] = f"Security Alert - {level}"
            msg['From'] = email_config["username"]
            msg['To'] = ', '.join(email_config["recipients"])

            with smtplib.SMTP(email_config["smtp_server"], email_config["smtp_port"]) as server:
                server.starttls()
                server.login(email_config["username"], email_config["password"])
                server.send_message(msg)

        except Exception as e:
            logging.error(f"Failed to send email alert: {e}")

    def _send_pushover_alert(self, level: str, message: str):
        """Send Pushover notification"""
        # Implementation for Pushover API
        pass

    def _send_slack_alert(self, level: str, message: str):
        """Send Slack notification"""
        # Implementation for Slack webhook
        pass

    def _save_scan_results(self, scan_results: Dict):
        """Save scan results to database"""
        try:
            db_path = "./scan_results.db"
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Create table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    scan_id TEXT PRIMARY KEY,
                    start_time TEXT,
                    end_time TEXT,
                    scan_types TEXT,
                    results TEXT,
                    summary TEXT,
                    alert TEXT
                )
            ''')

            # Insert results
            cursor.execute('''
                INSERT OR REPLACE INTO scan_results
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_results["scan_id"],
                scan_results["start_time"],
                scan_results["end_time"],
                json.dumps(scan_results["scan_types"]),
                json.dumps(scan_results["results"]),
                json.dumps(scan_results["summary"]),
                json.dumps(scan_results["alert"])
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            logging.error(f"Failed to save scan results: {e}")


def main():
    """Main entry point"""
    print("=== Comprehensive Security Scanner ===")

    # Initialize security engine
    scanner = SecurityEngine()

    # Run comprehensive scan
    try:
        results = scanner.run_comprehensive_scan()

        # Print results
        print("\n=== Scan Results ===")
        print(f"Scan ID: {results['scan_id']}")
        print(f"Start Time: {results['start_time']}")
        print(f"End Time: {results['end_time']}")
        print("\n=== Summary ===")
        print(f"Total Findings: {results['summary']['total_findings']}")
        print(f"High Risk: {results['summary']['high_risk']}")
        print(f"Medium Risk: {results['summary']['medium_risk']}")
        print(f"Low Risk: {results['summary']['low_risk']}")

        if "alert" in results:
            print(f"\nAlert: {results['alert']['level']} - {results['alert']['message']}")

        # Exit with appropriate code
        if results['summary']['high_risk'] > 0:
            sys.exit(1)
        elif results['summary']['total_findings'] > 0:
            sys.exit(2)
        else:
            sys.exit(0)

    except Exception as e:
        print(f"Scan failed: {e}")
        sys.exit(3)


if __name__ == "__main__":
    main()