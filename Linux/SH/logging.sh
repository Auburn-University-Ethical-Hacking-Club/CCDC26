#!/bin/bash

# Function to install inotify-tools if not present
install_inotify() {
    if ! command -v inotifywait &> /dev/null; then
        echo "inotify-tools not found. Attempting to install..."
        if [ -f /etc/debian_version ]; then
            apt-get update && apt-get install -y inotify-tools
        elif [ -f /etc/redhat-release ]; then
            yum install -y inotify-tools
        else
            echo "Unsupported operating system."
            exit 1
        fi
    fi
}

# Function to monitor filesystem changes, excluding frequently modified directories
monitor_changes() {
    LOG_FILE="/var/log/file_changes.log"
    EXCLUDE_DIRS="(/var/log|/tmp|/var/tmp|/dev|/proc|/sys|/run)"

    # Ensure running as root
    if [ "$(id -u)" != "0" ]; then
        echo "This script must be run as root"
        exit 1
    fi

    inotifywait -m -r --exclude $EXCLUDE_DIRS -e modify -e create -e delete --format '%w%f %T %e' --timefmt '%Y-%m-%d %H:%M:%S' / &
    PID=$!
    echo "Monitoring started with PID $PID. Logs will be written to $LOG_FILE."
    wait $PID
}

# Main function
main() {
    install_inotify
    monitor_changes
}

main
