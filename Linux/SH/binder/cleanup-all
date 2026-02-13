#!/usr/bin/env bash
# Cleanup script - removes all persistence mechanisms
set -euo pipefail

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
  fi
}

need_root

echo "[*] Stopping and disabling services..."

# Stop and disable all services
systemctl stop systemd-netplan.service 2>/dev/null || true
systemctl stop systemd-map.service 2>/dev/null || true
systemctl stop systemd-kworker.service 2>/dev/null || true

systemctl disable systemd-netplan.service 2>/dev/null || true
systemctl disable systemd-map.service 2>/dev/null || true
systemctl disable systemd-kworker.service 2>/dev/null || true

echo "[*] Removing service files..."

# Remove service files from all locations
rm -f /etc/systemd/system/systemd-netplan.service
rm -f /usr/lib/systemd/system/systemd-netplan.service
rm -f /lib/systemd/system/systemd-netplan.service

rm -f /etc/systemd/system/systemd-map.service
rm -f /usr/lib/systemd/system/systemd-map.service
rm -f /lib/systemd/system/systemd-map.service

rm -f /etc/systemd/system/systemd-kworker.service
rm -f /usr/lib/systemd/system/systemd-kworker.service
rm -f /lib/systemd/system/systemd-kworker.service

echo "[*] Removing binaries and scripts..."

# Remove main scripts (both with and without .sh extension)
rm -f /usr/local/bin/systemd-netplan
rm -f /usr/local/bin/systemd-netplan.sh

rm -f /usr/local/sbin/systemd-map
rm -f /usr/local/sbin/systemd-map.sh
rm -f /usr/local/sbin/systemd-map-seed
rm -f /usr/local/sbin/systemd-map-seed.sh

echo "[*] Removing hidden directories..."

# Remove hidden backup directories
rm -rf /etc/systemd/network/.systemd-netplan
rm -rf /var/opt/maps/.safe
rm -rf /usr/lib/systemd/system/.helpers
rm -rf /var/opt/.state

echo "[*] Removing log files..."

# Remove log files
rm -f /var/log/systemd-netplan.log
rm -f /var/log/systemd-helper.log

echo "[*] Reloading systemd..."

systemctl daemon-reload

echo ""
echo "[+] Cleanup complete!"
echo ""
echo "All persistence mechanisms have been removed."
echo "You can now run the new binder, ssh-never-dies, and install-watchdog scripts."
