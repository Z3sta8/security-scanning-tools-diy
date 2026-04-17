#!/bin/bash
# Local testing script (without Docker)

set -e

echo "================================"
echo "Security Monitor - Local Test"
echo "================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "[1/5] Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "[2/5] Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "[3/5] Installing dependencies..."
pip install -q -r requirements.txt

# Create directories
echo "[4/5] Creating directories..."
mkdir -p logs data

# Update config for local paths
cat > config_local.json <<'EOF'
{
  "scan_interval": 60,
  "log_dir": "./logs",
  "db_path": "./data/scans.db",
  "scans": {
    "integrity_check": {
      "script": "./integrity_monitor.sh",
      "enabled": false,
      "interval": 300,
      "timeout": 300
    },
    "log_analysis": {
      "script": "./log_analyzer.sh",
      "enabled": true,
      "interval": 120,
      "timeout": 120
    },
    "memory_analysis": {
      "script": "./memory_analysis.sh",
      "enabled": false,
      "interval": 300,
      "timeout": 300
    }
  }
}
EOF

# Update security_monitor.py to use local config
sed -i.bak 's|"log_dir": "/var/log/security_monitor"|"log_dir": "./logs"|g' security_monitor.py
sed -i.bak 's|"db_path": "/var/lib/security_monitor/scans.db"|"db_path": "./data/scans.db"|g' security_monitor.py

# Also update web_dashboard.py
sed -i.bak 's|DB_PATH = "/var/lib/security_monitor/scans.db"|DB_PATH = "./data/scans.db"|g' web_dashboard.py

echo "[5/5] Starting services..."
echo ""
echo "Starting web dashboard on http://localhost:8080..."
python3 web_dashboard.py &
WEB_PID=$!

sleep 2

echo "Starting security monitor..."
echo ""
python3 security_monitor.py &
MONITOR_PID=$!

echo ""
echo "================================"
echo "Security Monitor is running!"
echo "================================"
echo ""
echo "Web Dashboard: http://localhost:8080"
echo ""
echo "Press Ctrl+C to stop..."
echo ""

# Wait for user interrupt
trap "echo ''; echo 'Stopping...'; kill $WEB_PID $MONITOR_PID 2>/dev/null; exit 0" INT TERM

wait
