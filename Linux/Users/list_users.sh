#!/bin/bash

# Define Colors
RED='\e[1;31m'
GREEN='\e[1;32m'
WHITE='\e[0m' # Default/White
NC='\e[0m'    # Reset

echo "-------------------------------------------------------------"
echo "USER AUDIT ON $(hostname) - $(date)"
echo "-------------------------------------------------------------"
printf "%-20s %-8s %-15s %-35s\n" "USERNAME" "UID" "STATUS" "HOME DIRECTORY"
echo "-------------------------------------------------------------"

# Get a list of all active usernames
ACTIVE_USERS=$(loginctl list-users --no-legend | awk '{print $2}')

getent passwd | while IFS=: read -r user pass uid gid full home shell; do
    
    # Check if user is in the active list
    IS_ACTIVE=false
    if echo "$ACTIVE_USERS" | grep -qw "$user"; then
        IS_ACTIVE=true
    fi

    # Logic for Human/Admin Users (UID 0 and 1000+)
    if [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; then
        if [ "$IS_ACTIVE" = true ]; then
            COLOR=$GREEN
            STATUS="ACTIVE"
        else
            COLOR=$RED
            STATUS="INACTIVE"
        fi
    # Logic for System Users (Everyone else)
    else
        COLOR=$WHITE
        STATUS="System"
    fi

    # Print the formatted line
    printf "${COLOR}%-20s %-8s %-15s %-35s${NC}\n" "$user" "$uid" "$STATUS" "$home"

done

echo "-------------------------------------------------------------"
echo -e "Legend: ${GREEN}Active Human${NC} | ${RED}Inactive Human${NC} | White: System User"