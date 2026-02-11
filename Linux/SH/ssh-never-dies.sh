#!/usr/bin/env bash
# axon
set -euo pipefail

# One-file installer
# - systemd-map.sh
# - systemd-map-seed.sh
# - commands.txt

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
  fi
}

need_root

install -d /usr/local/sbin
install -d /etc/systemd/system
install -d /var/opt/maps/.safe

cat > /usr/local/sbin/systemd-map.sh <<'EOF'
#!/bin/sh
set -eu

SAFE_ROOT="/var/opt/maps/.safe"
INTERVAL="15"
TAG="systemd-map"
VERIFY_DELAY="1"
VERIFY_TRIES="5"

have() { command -v "$1" >/dev/null 2>&1; }

log() {
    if have logger; then
        logger -t "$TAG" -- "$*"
    else
        printf '%s\n' "$*" >&2
    fi
}

is_sshd_running() {
    if have pgrep; then
        pgrep -x sshd >/dev/null 2>&1 && return 0
    fi
    if have pidof; then
        pidof sshd >/dev/null 2>&1 && return 0
    fi
    ps ax 2>/dev/null | grep -q '[s]shd'
}

start_sshd() {
    if have systemctl; then
        systemctl start sshd >/dev/null 2>&1 && return 0
        systemctl start ssh  >/dev/null 2>&1 && return 0
        return 1
    fi

    if have service; then
        service sshd start >/dev/null 2>&1 && return 0
        service ssh  start >/dev/null 2>&1 && return 0
        return 1
    fi

    if [ "$(uname -s 2>/dev/null || true)" = "FreeBSD" ]; then
        service sshd onestart >/dev/null 2>&1 && return 0
        service sshd start     >/dev/null 2>&1 && return 0
        return 1
    fi

    [ -x /etc/init.d/sshd ] && /etc/init.d/sshd start >/dev/null 2>&1 && return 0
    [ -x /etc/init.d/ssh  ] && /etc/init.d/ssh  start >/dev/null 2>&1 && return 0
    return 1
}

restore_file() {
    rel="$1"
    src="${SAFE_ROOT}/${rel}"
    dst="/${rel}"

    if [ ! -e "$src" ]; then
        log "RESTORE: missing ${src} (skip)"
        return 0
    fi

    mkdir -p "$(dirname "$dst")"
    cp -p "$src" "$dst"

    case "$dst" in
        */sshd) chmod 0755 "$dst" ;;
        *)      chmod 0644 "$dst" ;;
    esac

    log "RESTORE: ${src} -> ${dst}"
}

restore_dir() {
    rel="$1"
    src="${SAFE_ROOT}/${rel}"
    dst="/${rel}"

    if [ ! -d "$src" ]; then
        log "RESTORE: missing dir ${src} (skip)"
        return 0
    fi

    mkdir -p "$dst"
    if have rsync; then
        rsync -a --delete "$src"/ "$dst"/ >/dev/null 2>&1
        log "RESTORE: dir ${src}/ -> ${dst}/ (rsync)"
    else
        (cd "$src" && find . -depth -print) | (cd "$dst" && cpio -pdm 2>/dev/null)
        log "RESTORE: dir ${src}/ -> ${dst}/ (cpio)"
    fi
}

restore_safe() {
    log "RESTORE: begin (SAFE_ROOT=${SAFE_ROOT})"

    # sshd config + config.d
    restore_file "etc/ssh/sshd_config"
    restore_dir  "etc/ssh/sshd_config.d"

    # sshd binary
    if [ -e "${SAFE_ROOT}/usr/sbin/sshd" ]; then
        mkdir -p /usr/sbin
        cp -p "${SAFE_ROOT}/usr/sbin/sshd" /usr/sbin/sshd
        chmod 0755 /usr/sbin/sshd
        log "RESTORE: ${SAFE_ROOT}/usr/sbin/sshd -> /usr/sbin/sshd"
    else
        log "RESTORE: missing ${SAFE_ROOT}/usr/sbin/sshd (skip)"
    fi

    # systemd unit restore (both common paths + names)
    restore_file "usr/lib/systemd/system/ssh.service"
    restore_file "usr/lib/systemd/system/sshd.service"
    restore_file "lib/systemd/system/ssh.service"
    restore_file "lib/systemd/system/sshd.service"

    # reload systemd units if we restored any (best-effort)
    if have systemctl; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        log "RESTORE: systemctl daemon-reload (best-effort)"
    fi

    if have restorecon; then
        restorecon -RF /etc/ssh /usr/sbin/sshd /usr/lib/systemd/system /lib/systemd/system >/dev/null 2>&1 || true
        log "RESTORE: restorecon applied (best-effort)"
    fi

    log "RESTORE: end"
}

verify_sshd_up() {
    i=0
    log "VERIFY: begin (tries=${VERIFY_TRIES}, delay=${VERIFY_DELAY}s)"
    while [ "$i" -lt "$VERIFY_TRIES" ]; do
        if is_sshd_running; then
            log "VERIFY: sshd is running"
            return 0
        fi
        i=$((i + 1))
        sleep "$VERIFY_DELAY"
    done
    log "VERIFY: sshd is NOT running"
    return 1
}

log "START: watchdog online (INTERVAL=${INTERVAL}s, SAFE_ROOT=${SAFE_ROOT})"

while :; do
    if is_sshd_running; then
        log "CHECK: sshd running"
        sleep "$INTERVAL"
        continue
    fi

    log "CHECK: sshd NOT running (detected)"
    restore_safe

    log "ACTION: attempting to start sshd"
    if start_sshd; then
        log "ACTION: start command succeeded"
    else
        log "ACTION: start command FAILED"
    fi

    if verify_sshd_up; then
        log "RESULT: sshd running after remediation"
    else
        log "RESULT: sshd STILL down after remediation"
    fi

    sleep "$INTERVAL"
done
EOF

cat > /usr/local/sbin/systemd-map-seed.sh <<'EOF'
#!/bin/sh
set -eu

SAFE_ROOT="/var/opt/maps/.safe"
TAG="systemd-map-seed"

have() { command -v "$1" >/dev/null 2>&1; }

log() {
    if have logger; then
        logger -t "$TAG" -- "$*"
    else
        printf '%s\n' "$*" >&2
    fi
}

copy_dir() {
    src="$1"
    dst="$2"

    mkdir -p "$dst"
    if have rsync; then
        rsync -a --delete "$src"/ "$dst"/ >/dev/null 2>&1
    else
        (cd "$src" && find . -depth -print) | (cd "$dst" && cpio -pdm 2>/dev/null)
    fi
}

seed_file() {
    src="$1"
    rel="$2"
    dst="${SAFE_ROOT}/${rel}"

    if [ ! -e "$src" ]; then
        log "SEED: missing ${src} (skip)"
        return 0
    fi

    mkdir -p "$(dirname "$dst")"
    cp -p "$src" "$dst"

    case "$rel" in
        */sshd) chmod 0755 "$dst" ;;
        *)      chmod 0644 "$dst" ;;
    esac

    log "SEED: ${src} -> ${dst}"
}

seed_dir() {
    src="$1"
    rel="$2"
    dst="${SAFE_ROOT}/${rel}"

    if [ ! -d "$src" ]; then
        log "SEED: missing dir ${src} (skip)"
        return 0
    fi

    copy_dir "$src" "$dst"
    log "SEED: dir ${src}/ -> ${dst}/"
}

mkdir -p "$SAFE_ROOT"
log "SEED: begin (SAFE_ROOT=${SAFE_ROOT})"

# SSH configs + binary
seed_file "/etc/ssh/sshd_config"   "etc/ssh/sshd_config"
seed_dir  "/etc/ssh/sshd_config.d" "etc/ssh/sshd_config.d"
seed_file "/usr/sbin/sshd"         "usr/sbin/sshd"

# systemd unit files (cross-distro safe)
seed_file "/usr/lib/systemd/system/ssh.service"  "usr/lib/systemd/system/ssh.service"
seed_file "/usr/lib/systemd/system/sshd.service" "usr/lib/systemd/system/sshd.service"

# Also check common alternate path (Debian-based sometimes use /lib/systemd/)
seed_file "/lib/systemd/system/ssh.service"  "lib/systemd/system/ssh.service"
seed_file "/lib/systemd/system/sshd.service" "lib/systemd/system/sshd.service"

if have restorecon; then
    restorecon -RF "$SAFE_ROOT" >/dev/null 2>&1 || true
fi

chmod -R go-rwx "$SAFE_ROOT" 2>/dev/null || true

log "SEED: complete"
EOF

cat > /etc/systemd/system/systemd-map.service <<'EOF'
[Unit]
Description=SystemD Mapper
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/systemd-map.sh
Restart=always
RestartSec=5
User=root
Group=root
Environment=SAFE_ROOT=/var/opt/maps/.safe
Environment=INTERVAL=15

[Install]
WantedBy=multi-user.target
EOF

# Now run the exact command sequence you provided :contentReference[oaicite:3]{index=3}
chmod +x /usr/local/sbin/systemd-map.sh
chmod +x /usr/local/sbin/systemd-map-seed.sh

/usr/local/sbin/systemd-map-seed.sh

chown root:root /usr/local/sbin/systemd-map.sh
chown root:root /usr/local/sbin/systemd-map-seed.sh

systemctl daemon-reload
systemctl enable --now systemd-map.service

chown -R root:root /var/opt/maps/.safe
chmod -R go-rwx /var/opt/maps/.safe

journalctl -u systemd-map.service -f