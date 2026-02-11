#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Run as root."
    exit 1
fi
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color
echo "========== FULL LINUX USER SECURITY AUDIT =========="
echo

VALID_SHELLS=$(grep -v '^#' /etc/shells | grep -v '^$')
TODAY=$(date +%s)

# Detect sudo group
if getent group sudo > /dev/null; then
    SUDO_GROUP="sudo"
elif getent group wheel > /dev/null; then
    SUDO_GROUP="wheel"
else
    SUDO_GROUP=""
fi

echo "Detected sudo group: ${SUDO_GROUP:-None}"
echo

# Collect UIDs for duplicate detection
declare -A UID_MAP

# Buffer for 2-column layout
COL_WIDTH=85
LEFT_BUF=""
PENDING=false

print_row() {
    local left="$1"
    local right="$2"

    # Zip the two blocks side by side with a | separator
    paste <(echo "$left") <(echo "$right") | while IFS=$'\t' read -r l r; do
        printf "%-${COL_WIDTH}s| %s\n" "$l" "$r"
    done
}

flush_left() {
    # Print a pending left column with an empty right column
    if $PENDING; then
        echo "$LEFT_BUF"
        echo "--------------------------------------------------------"
        PENDING=false
        LEFT_BUF=""
    fi
}

print_divider() {
    printf '%0.s-' $(seq 1 $(( COL_WIDTH * 2 + 2 )))
    echo
}

print_divider

while IFS=: read -r username password uid gid gecos home shell; do
    FLAGS=""
    groups=$(id -nG "$username" 2>/dev/null)

    if ! getent group "$gid" > /dev/null; then
        FLAGS+="MissingPrimaryGroup;"
    fi

    # Track duplicate UIDs
    if [[ -n "${UID_MAP[$uid]}" ]]; then
        FLAGS+="DuplicateUID;"
    else
        UID_MAP[$uid]=$username
    fi

    # Shadow info
    shadow_entry=$(getent shadow "$username")
    shadow_pass=$(echo "$shadow_entry" | cut -d: -f2)
    last_change_days=$(echo "$shadow_entry" | cut -d: -f3)
    max_days=$(echo "$shadow_entry" | cut -d: -f5)

    # Password status
    if [[ "$shadow_pass" == "!"* || "$shadow_pass" == "*" ]]; then
        pass_status="LOCKED"
    elif [[ -z "$shadow_pass" ]]; then
        pass_status="NO_PASS"
        FLAGS+="NoPassword;"
    else
        pass_status="SET"
    fi

    # Password aging check
    if [[ "$last_change_days" =~ ^[0-9]+$ ]]; then
        last_change_sec=$(( last_change_days * 86400 ))
        last_change_epoch=$(( last_change_sec + 0 ))
        password_age_days=$(( (TODAY/86400) - last_change_days ))

        if [[ "$max_days" == "99999" ]]; then
            FLAGS+="NeverExpires;"
        fi

        if [[ "$password_age_days" -gt 365 ]]; then
            FLAGS+="OldPassword;"
        fi
    fi

    # Sudo group membership
    if [[ -n "$SUDO_GROUP" && "$groups" == *"$SUDO_GROUP"* ]]; then
        FLAGS+="SUDO_GROUP;"
    fi

    # Direct sudoers entries
    if grep -rqs "^$username " /etc/sudoers /etc/sudoers.d 2>/dev/null; then
        FLAGS+="SUDOERS_FILE;"
    fi

    # Passwordless sudo
    if grep -rqs "^$username .*NOPASSWD" /etc/sudoers /etc/sudoers.d 2>/dev/null; then
        FLAGS+="NOPASSWD;"
    fi

    # UID 0 check
    if [[ "$uid" -eq 0 && "$username" != "root" ]]; then
        FLAGS+="UID0;"
    fi

    # System account login shell
    if [[ "$uid" -lt 1000 && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
        FLAGS+="SystemLogin;"
    fi

    # Normal user disabled shell
    if [[ "$uid" -ge 1000 && ( "$shell" == "/usr/sbin/nologin" || "$shell" == "/bin/false" ) ]]; then
        FLAGS+="NoLoginShell;"
    fi

    # Invalid shell
    if ! echo "$VALID_SHELLS" | grep -qx "$shell"; then
        FLAGS+="InvalidShell;"
    fi

    # Home directory checks
    if [[ ! -d "$home" ]]; then
        FLAGS+="MissingHome;"
    else
        perms=$(stat -c "%a" "$home")
        if [[ "${perms: -1}" -ge 6 ]]; then
            FLAGS+="WorldWritableHome;"
        fi
    fi

    # SSH keys
    if [[ -f "$home/.ssh/authorized_keys" ]]; then
        FLAGS+="SSHKey;"
    fi

    # Build this user's block (no leading divider — divider is between pairs)
    BLOCK=$(printf "User:     \033[1;32m%-20s\033[0m  UID: %s\n" "$username" "$uid"
            printf "Shell:    %s\n" "$shell"
            printf "Groups:   %s\n" "$groups"
            printf "Password: %-10s\n" "$pass_status"
            printf "Flags:    %s\n" "${FLAGS:-OK}")

    if ! $PENDING; then
        LEFT_BUF="$BLOCK"
        PENDING=true
    else
        print_row "$LEFT_BUF" "$BLOCK"
        print_divider
        PENDING=false
        LEFT_BUF=""
    fi

done < /etc/passwd

# Flush any remaining single entry
if $PENDING; then
    echo "$LEFT_BUF"
    print_divider
fi

echo
echo "========== PASSWD / SHADOW INTEGRITY CHECK =========="

integrity_issue=false

while IFS=: read -r username _; do
    if ! getent shadow "$username" > /dev/null; then
        echo "User $username exists in passwd but NOT in shadow"
        integrity_issue=true
    fi
done < /etc/passwd

while IFS=: read -r username _; do
    if ! getent passwd "$username" > /dev/null; then
        echo "User $username exists in shadow but NOT in passwd"
        integrity_issue=true
    fi
done < /etc/shadow

if ! $integrity_issue; then
    echo "No inconsistencies detected between passwd and shadow."
fi


echo
echo "========== DUPLICATE UID SUMMARY =========="

duplicate_found=false

for uid in "${!UID_MAP[@]}"; do
    users=$(awk -F: -v id="$uid" '$3==id {print $1}' /etc/passwd | wc -l)
    if [[ "$users" -gt 1 ]]; then
        echo "UID $uid shared by:"
        awk -F: -v id="$uid" '$3==id {print "  - " $1}' /etc/passwd
        duplicate_found=true
    fi
done

if ! $duplicate_found; then
    echo "No duplicate UIDs detected."
fi


echo
echo "========== ORPHANED HOME DIRECTORIES =========="

orphan_found=false

for dir in /home/*; do
    [[ -d "$dir" ]] || continue
    user=$(basename "$dir")
    if ! getent passwd "$user" > /dev/null; then
        echo "Directory $dir has no matching user"
        orphan_found=true
    fi
done

if ! $orphan_found; then
    echo "No orphaned home directories detected."
fi


echo
echo "========== SUDOERS SUMMARY =========="
grep -rEv '^(#|$)' /etc/sudoers /etc/sudoers.d 2>/dev/null

echo
echo "========== USERS WITH SUDO PRIVILEGES =========="

# Collect sudoers entries
SUDO_ENTRIES=$(grep -h -rEv '^(#|$|Defaults|@includedir)' /etc/sudoers /etc/sudoers.d 2>/dev/null)

declare -A SUDO_USERS
declare -A SUDO_GROUPS
declare -A NOPASSWD_USERS

while read -r line; do
    entry=$(echo "$line" | awk '{print $1}')

    if [[ "$line" == *"NOPASSWD"* ]]; then
        if [[ "$entry" != %* ]]; then
            NOPASSWD_USERS["$entry"]=1
        fi
    fi

    if [[ "$entry" == %* ]]; then
        group="${entry#%}"
        SUDO_GROUPS["$group"]=1
    else
        SUDO_USERS["$entry"]=1
    fi

done <<< "$SUDO_ENTRIES"

# Expand group members
for group in "${!SUDO_GROUPS[@]}"; do
    members=$(getent group "$group" | cut -d: -f4)
    for user in ${members//,/ }; do
        SUDO_USERS["$user"]=1
    done
done

if [[ ${#SUDO_USERS[@]} -eq 0 ]]; then
    echo "No sudo users detected."
else
    for user in "${!SUDO_USERS[@]}"; do
        if [[ -n "${NOPASSWD_USERS[$user]}" ]]; then
            echo -e "${RED}${user} (NOPASSWD)${NC}"
        else
            echo -e "${RED}${user}${NC}"
        fi
    done
fi


echo
echo "========== AUDIT COMPLETE =========="
