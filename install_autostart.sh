#!/bin/bash
# Install/Uninstall Security Monitor and Dashboard LaunchAgents
# Run this script to enable/disable auto-startup at login

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
MONITOR_PLIST="com.security.monitor.plist"
DASHBOARD_PLIST="com.security.dashboard.plist"
MONITOR_LABEL="com.security.monitor"
DASHBOARD_LABEL="com.security.dashboard"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Function to check if python3 exists
check_python() {
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed or not in PATH"
        print_info "Install Python 3 using: brew install python3"
        exit 1
    fi
    print_success "Python 3 found: $(python3 --version)"

    # Get the actual python3 path
    PYTHON_PATH=$(which python3)
    print_info "Python path: $PYTHON_PATH"

    # Update plist files with correct Python path
    if [ -f "$SCRIPT_DIR/$MONITOR_PLIST" ]; then
        /usr/libexec/PlistBuddy -c "Set :ProgramArguments:0 $PYTHON_PATH" "$SCRIPT_DIR/$MONITOR_PLIST" 2>/dev/null
        sed -i '' "s|<string>/usr/bin/python3</string>|<string>$PYTHON_PATH</string>|g" "$SCRIPT_DIR/$MONITOR_PLIST"
        sed -i '' "s|<string>/Library/Frameworks/Python.framework/Versions/3.13/bin/python3</string>|<string>$PYTHON_PATH</string>|g" "$SCRIPT_DIR/$MONITOR_PLIST"
    fi

    if [ -f "$SCRIPT_DIR/$DASHBOARD_PLIST" ]; then
        sed -i '' "s|<string>/usr/bin/python3</string>|<string>$PYTHON_PATH</string>|g" "$SCRIPT_DIR/$DASHBOARD_PLIST"
        sed -i '' "s|<string>/Library/Frameworks/Python.framework/Versions/3.13/bin/python3</string>|<string>$PYTHON_PATH</string>|g" "$SCRIPT_DIR/$DASHBOARD_PLIST"
    fi
}

# Function to check if Flask is installed
check_flask() {
    if ! python3 -c "import flask" 2>/dev/null; then
        print_warning "Flask not installed. Installing now..."
        pip3 install flask
        if [ $? -eq 0 ]; then
            print_success "Flask installed successfully"
        else
            print_error "Failed to install Flask"
            exit 1
        fi
    else
        print_success "Flask is installed"
    fi
}

# Function to stop existing services
stop_services() {
    echo ""
    print_info "Stopping any running services..."

    # Stop monitor if running
    if launchctl list | grep -q "$MONITOR_LABEL"; then
        launchctl stop "$MONITOR_LABEL" 2>/dev/null
        print_success "Stopped security monitor"
    fi

    # Stop dashboard if running
    if launchctl list | grep -q "$DASHBOARD_LABEL"; then
        launchctl stop "$DASHBOARD_LABEL" 2>/dev/null
        print_success "Stopped web dashboard"
    fi
}

# Function to install LaunchAgents
install_autostart() {
    echo ""
    echo "=================================="
    echo "Installing Auto-Startup Services"
    echo "=================================="
    echo ""

    # Check prerequisites
    check_python
    check_flask

    # Create logs directory
    mkdir -p "$SCRIPT_DIR/logs"
    print_success "Created logs directory"

    # Create data directory
    mkdir -p "$SCRIPT_DIR/data"
    print_success "Created data directory"

    # Ensure LaunchAgents directory exists
    mkdir -p "$LAUNCH_AGENTS_DIR"
    print_success "LaunchAgents directory ready"

    # Stop any existing services
    stop_services

    # Copy plist files
    echo ""
    print_info "Installing LaunchAgent plists..."

    cp "$SCRIPT_DIR/$MONITOR_PLIST" "$LAUNCH_AGENTS_DIR/"
    print_success "Installed $MONITOR_PLIST"

    cp "$SCRIPT_DIR/$DASHBOARD_PLIST" "$LAUNCH_AGENTS_DIR/"
    print_success "Installed $DASHBOARD_PLIST"

    # Load the agents
    echo ""
    print_info "Loading LaunchAgents..."

    launchctl load "$LAUNCH_AGENTS_DIR/$MONITOR_PLIST"
    if [ $? -eq 0 ]; then
        print_success "Loaded security monitor LaunchAgent"
    else
        print_error "Failed to load security monitor LaunchAgent"
        print_info "Check logs at: $SCRIPT_DIR/logs/monitor.stderr.log"
    fi

    launchctl load "$LAUNCH_AGENTS_DIR/$DASHBOARD_PLIST"
    if [ $? -eq 0 ]; then
        print_success "Loaded web dashboard LaunchAgent"
    else
        print_error "Failed to load web dashboard LaunchAgent"
        print_info "Check logs at: $SCRIPT_DIR/logs/dashboard.stderr.log"
    fi

    echo ""
    echo "=================================="
    print_success "Installation Complete!"
    echo "=================================="
    echo ""
    print_info "Services are now running and will start automatically at login."
    echo ""
    echo "Security Monitor Dashboard:"
    echo "  → URL: http://localhost:8080"
    echo "  → Logs: $SCRIPT_DIR/logs/"
    echo ""
    print_info "To view the dashboard now, open:"
    echo "  http://localhost:8080"
    echo ""

    # Wait a moment for services to start
    sleep 3

    # Check if services are running
    echo "Checking service status..."
    if launchctl list | grep -q "$MONITOR_LABEL"; then
        print_success "Security Monitor is running"
    else
        print_warning "Security Monitor may not be running (check logs)"
    fi

    if launchctl list | grep -q "$DASHBOARD_LABEL"; then
        print_success "Web Dashboard is running"
    else
        print_warning "Web Dashboard may not be running (check logs)"
    fi

    echo ""
    print_info "To manage services manually:"
    echo "  Start:  launchctl start $MONITOR_LABEL"
    echo "          launchctl start $DASHBOARD_LABEL"
    echo "  Stop:   launchctl stop $MONITOR_LABEL"
    echo "          launchctl stop $DASHBOARD_LABEL"
    echo "  Status: launchctl list | grep security"
    echo ""
}

# Function to uninstall LaunchAgents
uninstall_autostart() {
    echo ""
    echo "=================================="
    echo "Uninstalling Auto-Startup Services"
    echo "=================================="
    echo ""

    # Stop services
    stop_services

    # Unload the agents
    echo ""
    print_info "Unloading LaunchAgents..."

    if [ -f "$LAUNCH_AGENTS_DIR/$MONITOR_PLIST" ]; then
        launchctl unload "$LAUNCH_AGENTS_DIR/$MONITOR_PLIST" 2>/dev/null
        rm "$LAUNCH_AGENTS_DIR/$MONITOR_PLIST"
        print_success "Uninstalled $MONITOR_PLIST"
    else
        print_info "$MONITOR_PLIST not installed"
    fi

    if [ -f "$LAUNCH_AGENTS_DIR/$DASHBOARD_PLIST" ]; then
        launchctl unload "$LAUNCH_AGENTS_DIR/$DASHBOARD_PLIST" 2>/dev/null
        rm "$LAUNCH_AGENTS_DIR/$DASHBOARD_PLIST"
        print_success "Uninstalled $DASHBOARD_PLIST"
    else
        print_info "$DASHBOARD_PLIST not installed"
    fi

    echo ""
    echo "=================================="
    print_success "Uninstallation Complete!"
    echo "=================================="
    echo ""
    print_info "Services will NOT start automatically at login."
    echo "You can still run them manually:"
    echo "  cd $SCRIPT_DIR"
    echo "  python3 security_monitor.py"
    echo "  python3 web_dashboard.py"
    echo ""
}

# Function to show status
show_status() {
    echo ""
    echo "=================================="
    echo "Service Status"
    echo "=================================="
    echo ""

    # Check monitor
    if launchctl list | grep -q "$MONITOR_LABEL"; then
        print_success "Security Monitor: INSTALLED"
        pid=$(launchctl list | grep "$MONITOR_LABEL" | awk '{print $1}')
        if [ "$pid" != "-" ]; then
            echo "  PID: $pid"
        fi
    else
        print_info "Security Monitor: NOT INSTALLED"
    fi

    echo ""

    # Check dashboard
    if launchctl list | grep -q "$DASHBOARD_LABEL"; then
        print_success "Web Dashboard: INSTALLED"
        pid=$(launchctl list | grep "$DASHBOARD_LABEL" | awk '{print $1}')
        if [ "$pid" != "-" ]; then
            echo "  PID: $pid"
        fi
    else
        print_info "Web Dashboard: NOT INSTALLED"
    fi

    echo ""

    # Check if dashboard is accessible
    if command -v curl > /dev/null 2>&1; then
        if curl -s http://localhost:8080 > /dev/null 2>&1; then
            print_success "Dashboard is accessible at http://localhost:8080"
        else
            print_warning "Dashboard may not be responding"
        fi
    fi

    echo ""
}

# Function to restart services
restart_services() {
    echo ""
    echo "Restarting services..."
    stop_services
    sleep 2
    start_services
}

# Function to start services only
start_services() {
    echo ""
    print_info "Starting services..."

    if [ -f "$LAUNCH_AGENTS_DIR/$MONITOR_PLIST" ]; then
        launchctl start "$MONITOR_LABEL" 2>/dev/null
        print_success "Started security monitor"
    else
        print_warning "Security Monitor not installed (run install first)"
    fi

    if [ -f "$LAUNCH_AGENTS_DIR/$DASHBOARD_PLIST" ]; then
        launchctl start "$DASHBOARD_LABEL" 2>/dev/null
        print_success "Started web dashboard"
    else
        print_warning "Web Dashboard not installed (run install first)"
    fi

    echo ""
    sleep 2
    show_status
}

# Main menu
show_menu() {
    echo ""
    echo "=================================="
    echo "Security Monitor Auto-Startup Manager"
    echo "=================================="
    echo ""
    echo "1) Install auto-startup (recommended)"
    echo "2) Uninstall auto-startup"
    echo "3) Show status"
    echo "4) Restart services"
    echo "5) Start services"
    echo "6) Stop services"
    echo "7) View logs"
    echo "8) Quit"
    echo ""
    read -p "Choose an option [1-8]: " choice

    case $choice in
        1) install_autostart ;;
        2) uninstall_autostart ;;
        3) show_status ;;
        4) restart_services ;;
        5) start_services ;;
        6) stop_services; show_status ;;
        7)
            echo ""
            print_info "Opening logs directory..."
            open "$SCRIPT_DIR/logs"
            ;;
        8) echo "Goodbye!"; exit 0 ;;
        *) print_error "Invalid option"; sleep 1; show_menu ;;
    esac
}

# Command line mode
if [ "$1" = "install" ]; then
    install_autostart
elif [ "$1" = "uninstall" ]; then
    uninstall_autostart
elif [ "$1" = "status" ]; then
    show_status
elif [ "$1" = "start" ]; then
    start_services
elif [ "$1" = "stop" ]; then
    stop_services
elif [ "$1" = "restart" ]; then
    restart_services
else
    # Interactive mode
    show_menu
fi
