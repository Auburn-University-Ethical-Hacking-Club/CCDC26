#!/bin/bash

# Ensure we're running over SSH
if [[ -z "$SSH_CLIENT" ]]; then
    echo "Not running over SSH. Cannot detect local host."
    exit 1
fi

# Extract client IP from SSH connection
LOCAL_IP=$(echo $SSH_CLIENT | awk '{print $1}')

# Ask for local username
read -p "Enter your username on the local machine ($LOCAL_IP): " LOCAL_USER
if [[ -z "$LOCAL_USER" ]]; then
    echo "No username entered. Exiting."
    exit 1
fi

# Check arguments
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 /path/to/file_or_directory"
    exit 1
fi

SOURCE="$1"

# Check if the source exists
if [[ ! -e "$SOURCE" ]]; then
    echo "Source does not exist: $SOURCE"
    exit 1
fi

# Prepare timestamped destination path
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASENAME=$(basename "$SOURCE")
DEST="/home/$LOCAL_USER/backups/${BASENAME}_$TIMESTAMP"

echo
echo "Backing up $SOURCE to $LOCAL_USER@$LOCAL_IP:$DEST ..."
echo

# Create backup folder on local machine
ssh "$LOCAL_USER@$LOCAL_IP" "mkdir -p \"$DEST\"" || {
    echo "Failed to create destination folder on local machine. Check SSH connectivity."
    exit 1
}

# Determine rsync options
if [[ -d "$SOURCE" ]]; then
    # Source is a directory
    rsync -avz --progress "$SOURCE/" "$LOCAL_USER@$LOCAL_IP:$DEST/"
else
    # Source is a single file
    rsync -avz --progress "$SOURCE" "$LOCAL_USER@$LOCAL_IP:$DEST/"
fi

if [[ $? -eq 0 ]]; then
    echo
    echo "Backup complete: $DEST"
else
    echo
    echo "Backup failed."
    exit 1
fi
