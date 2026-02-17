#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

USER_UID=$1
LOCK_OR_DELETE=$2

if [ -z "$USER_UID" ] || ! [[ "$USER_UID" =~ ^[0-9]+$ ]]; then
    echo "Usage: $0 <UID> <lock password or delete [L/D]>" 
    exit 1
fi
USER_INFO=$(getent passwd "$USER_UID")

if [ -z "$USER_INFO" ]; then
    echo "Error: UID $USER_UID does not exist in /etc/passwd."
    exit 1
fi
USER_TO_BOOT=$(echo "$USER_INFO" | cut -d: -f1)
USER_HOME=$(echo "$USER_INFO" | cut -d: -f6)

echo "Targeting User: $USER_TO_BOOT (UID: $USER_UID)"

echo "Terminating all processes for UID $USER_UID..."
killall -u "$USER_TO_BOOT" -9 2>/dev/null

echo "Removing crontabs for $USER_TO_BOOT..."
crontab -r -u "$USER_TO_BOOT" 2>/dev/null

echo "Cleaning up systemd user units for $USER_TO_BOOT..."
if [ -d "$USER_HOME/.config/systemd/user" ]; then
    export XDG_RUNTIME_DIR="/run/user/$USER_UID"
    sudo -u "$USER_TO_BOOT" systemctl --user stop "*.timer" 2>/dev/null
    sudo -u "$USER_TO_BOOT" systemctl --user stop "*.service" 2>/dev/null
    rm -rf "$USER_HOME/.config/systemd/user/"
    echo "  -> User-level systemd units deleted."
fi

case "$LOCK_OR_DELETE" in
  [Ll]* )
    passwd -l "$USER_TO_BOOT"
    passwd -e "$USER_TO_BOOT"
    echo "Account $USER_TO_BOOT (UID $USER_UID) has been locked and kicked."
    ;;
  [Dd]* )
    deluser --remove-home "$USER_TO_BOOT"
    echo "User $USER_TO_BOOT (UID $USER_UID) and their files have been deleted."
    ;;
  * )
    echo "Invalid choice [L/D]. Skipping account modification."
    ;;
esac

echo "Operation for UID $USER_UID complete."