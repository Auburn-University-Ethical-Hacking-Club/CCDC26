#!/bin/bash

#############################################
# CCDC Jumpbox Backup Script
# Purpose: Rsync important directories from remote systems
# Usage: ./jumpbox_backup.sh [target_host] [ssh_user]
#############################################

set -uo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BACKUP_BASE_DIR="${HOME}/ccdc_backups"
LOG_DIR="${BACKUP_BASE_DIR}/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Directories to backup (customize as needed)
BACKUP_DIRS=(
    "/etc"
    "/var/www"
    "/home"
    "/root"
    "/opt"
    "/usr/local/bin"
    "/var/log"
)

# Rsync options
RSYNC_OPTS=(
    "-azh"                     # archive, compress, human-readable
    "--partial"                # keep partial transfers
    "--delete"                 # delete files that don't exist on source
    "--backup"                 # backup files that would be deleted/overwritten
    "--backup-dir=../deleted_${TIMESTAMP}" # where to store deleted files
    "--exclude='*.tmp'"        # exclude temporary files
    "--exclude='*.cache'"      # exclude cache files
    "--exclude='lost+found'"   # exclude lost+found directories
)

# SSH options
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

#############################################
# Functions
#############################################

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)
            echo -e "${BLUE}[INFO]${NC} ${message}"
            ;;
        SUCCESS)
            echo -e "${GREEN}[SUCCESS]${NC} ${message}"
            ;;
        WARNING)
            echo -e "${YELLOW}[WARNING]${NC} ${message}"
            ;;
        ERROR)
            echo -e "${RED}[ERROR]${NC} ${message}"
            ;;
    esac
    
    # Also log to file if LOG_FILE is set
    if [ -n "${LOG_FILE:-}" ]; then
        echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"
    fi
}

banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║         CCDC Jumpbox Backup Script                      ║"
    echo "║         Rsync Remote System Directories                 ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    cat << EOF
Usage: $0 <target_host> [ssh_user]

Arguments:
    target_host     Hostname or IP address of the target system
    ssh_user        SSH username (default: current user)

Examples:
    $0 web-server.example.com
    $0 192.168.1.10 admin
    $0 db-server root

The script will backup the following directories:
EOF
    for dir in "${BACKUP_DIRS[@]}"; do
        echo "    - $dir"
    done
    echo ""
}

check_dependencies() {
    log INFO "Checking dependencies..."
    
    local deps=("rsync" "ssh")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log ERROR "Missing dependencies: ${missing[*]}"
        log ERROR "Install with: sudo apt-get install ${missing[*]}"
        exit 1
    fi
    
    log SUCCESS "All dependencies found"
}

test_connectivity() {
    local target=$1
    local user=$2
    
    log INFO "Testing SSH connectivity to ${user}@${target}..."
    
    if ssh ${SSH_OPTS} "${user}@${target}" "echo 'Connection successful'" &> /dev/null; then
        log SUCCESS "SSH connection successful"
        return 0
    else
        log ERROR "Cannot connect to ${user}@${target}"
        log ERROR "Please verify:"
        log ERROR "  - Host is reachable"
        log ERROR "  - SSH service is running"
        log ERROR "  - Credentials are correct"
        return 1
    fi
}

get_hostname() {
    local target=$1
    local user=$2
    
    log INFO "Getting remote hostname..." >&2
    
    local hostname=$(ssh ${SSH_OPTS} "${user}@${target}" "hostname" 2>/dev/null | tr -d '\r\n')
    
    if [ -z "$hostname" ]; then
        log WARNING "Could not get hostname, using target address" >&2
        hostname="${target//[^a-zA-Z0-9]/_}"
    fi
    
    echo "$hostname"
}

backup_directory() {
    local target=$1
    local user=$2
    local remote_dir=$3
    local local_base=$4
    
    log INFO "Backing up ${remote_dir} from ${target}..."
    
    # Create local directory structure matching remote path
    local local_dir="${local_base}${remote_dir}"
    mkdir -p "$local_dir"
    
    # Perform rsync - redirect output to log file
    rsync "${RSYNC_OPTS[@]}" \
        -e "ssh ${SSH_OPTS}" \
        "${user}@${target}:${remote_dir}/" \
        "${local_dir}/" >> "${LOG_FILE}" 2>&1
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        log SUCCESS "Successfully backed up ${remote_dir}"
        return 0
    elif [ $exit_code -eq 23 ]; then
        log WARNING "Partial transfer for ${remote_dir} (some files may not exist or were not readable)"
        return 0
    else
        log ERROR "Failed to backup ${remote_dir} (exit code: ${exit_code})"
        return 1
    fi
}

create_backup_info() {
    local backup_dir=$1
    local target=$2
    local user=$3
    
    local info_file="${backup_dir}/backup_info.txt"
    
    cat > "$info_file" << EOF
CCDC Backup Information
========================
Backup Date: $(date)
Target Host: ${target}
SSH User: ${user}
Backup Location: ${backup_dir}
Script Version: 1.0

Backed Up Directories:
EOF
    
    for dir in "${BACKUP_DIRS[@]}"; do
        echo "  - $dir" >> "$info_file"
    done
    
    log INFO "Created backup information file: ${info_file}"
}

create_restore_script() {
    local backup_dir=$1
    local target=$2
    local user=$3
    
    local restore_script="${backup_dir}/restore.sh"
    
    cat > "$restore_script" << 'RESTORE_EOF'
#!/bin/bash

# CCDC Restore Script
# WARNING: This will overwrite files on the target system!

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

BACKUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESTORE_EOF
    
    echo "TARGET_HOST=\"${target}\"" >> "$restore_script"
    echo "SSH_USER=\"${user}\"" >> "$restore_script"
    
    cat >> "$restore_script" << 'RESTORE_EOF'

echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║              WARNING: RESTORE OPERATION                  ║${NC}"
echo -e "${RED}║  This will overwrite files on the target system!        ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Target: ${SSH_USER}@${TARGET_HOST}"
echo "Backup: ${BACKUP_DIR}"
echo ""
read -p "Are you sure you want to proceed? (type 'yes' to continue): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Restore cancelled."
    exit 0
fi

echo -e "${YELLOW}Starting restore...${NC}"

# Find all backed up directories
for dir in $(find "${BACKUP_DIR}" -mindepth 1 -maxdepth 10 -type d | grep -v deleted_ | grep -v "^\." | sed "s|${BACKUP_DIR}||"); do
    if [ -n "$dir" ] && [ "$dir" != "/" ]; then
        echo -e "${GREEN}Restoring ${dir}...${NC}"
        rsync -avzh --progress \
            "${BACKUP_DIR}${dir}/" \
            "${SSH_USER}@${TARGET_HOST}:${dir}/"
    fi
done

echo -e "${GREEN}Restore complete!${NC}"
RESTORE_EOF
    
    chmod +x "$restore_script"
    log INFO "Created restore script: ${restore_script}"
}

#############################################
# Main Script
#############################################

main() {
    banner
    
    # Parse arguments
    if [ $# -lt 1 ]; then
        usage
        exit 1
    fi
    
    TARGET_HOST="$1"
    SSH_USER="${2:-${USER}}"
    
    # Setup directories
    mkdir -p "${BACKUP_BASE_DIR}"
    mkdir -p "${LOG_DIR}"
    
    # Get remote hostname for directory naming
    REMOTE_HOSTNAME=$(get_hostname "${TARGET_HOST}" "${SSH_USER}")
    BACKUP_DIR="${BACKUP_BASE_DIR}/${REMOTE_HOSTNAME}_${TIMESTAMP}"
    LOG_FILE="${LOG_DIR}/${REMOTE_HOSTNAME}_${TIMESTAMP}.log"
    
    log INFO "Starting backup process"
    log INFO "Target: ${SSH_USER}@${TARGET_HOST}"
    log INFO "Remote hostname: ${REMOTE_HOSTNAME}"
    log INFO "Backup directory: ${BACKUP_DIR}"
    log INFO "Log file: ${LOG_FILE}"
    
    # Pre-flight checks
    check_dependencies
    test_connectivity "${TARGET_HOST}" "${SSH_USER}" || exit 1
    
    # Create backup directory
    mkdir -p "${BACKUP_DIR}"
    
    # Backup each directory
    local success_count=0
    local fail_count=0
    
    for dir in "${BACKUP_DIRS[@]}"; do
        if backup_directory "${TARGET_HOST}" "${SSH_USER}" "$dir" "${BACKUP_DIR}"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
        echo ""
    done
    
    # Create metadata files
    create_backup_info "${BACKUP_DIR}" "${TARGET_HOST}" "${SSH_USER}"
    create_restore_script "${BACKUP_DIR}" "${TARGET_HOST}" "${SSH_USER}"
    
    # Summary
    echo ""
    log INFO "╔══════════════════════════════════════════════════════════╗"
    log INFO "║                  Backup Summary                          ║"
    log INFO "╚══════════════════════════════════════════════════════════╝"
    log SUCCESS "Successfully backed up: ${success_count} directories"
    if [ $fail_count -gt 0 ]; then
        log WARNING "Failed backups: ${fail_count} directories"
    fi
    log INFO "Backup location: ${BACKUP_DIR}"
    log INFO "Log file: ${LOG_FILE}"
    log INFO "To restore: ${BACKUP_DIR}/restore.sh"
    echo ""
    
    # Create symlink to latest backup
    ln -sfn "${BACKUP_DIR}" "${BACKUP_BASE_DIR}/${REMOTE_HOSTNAME}_latest"
    log INFO "Latest backup symlink: ${BACKUP_BASE_DIR}/${REMOTE_HOSTNAME}_latest"
}

# Run main function
main "$@"
