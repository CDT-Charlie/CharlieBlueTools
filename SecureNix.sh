#!/usr/bin/env bash
# ==============================================================================
# SecureNix.sh - Linux Hardening Script
# Blue Team Hardening Script for CDT Competition - Team Charlie Spring 2026
# ==============================================================================
#
# SYNOPSIS:
#   Comprehensive hardening script for Blue vs Red team competitions.
#   Interactive user management, service-specific firewall port selection,
#   SSH hardening, PAM policy, backdoor detection, and full audit logging.
#
# BEFORE_RUNNING:
#   **REQUIRED CONFIGURATION - EDIT THESE VARIABLES:**
#
#   1. AUTHORIZED_ADMINS   - Add your blue team usernames (~line 170)
#   2. SET_ALL_USER_PASSWORDS - Change to YOUR secure password (~line 185)
#   3. SAFE_IP_ADDRESSES   - Scoring engine/jumpbox IPs (pre-filled from packet)
#
# CRITICAL_RULES (CDT Team Charlie Spring 2026):
#   Rule 5:  DO NOT modify any file with "greyteam" in its name
#   Rule 7:  DO NOT BLOCK subnets - but ALLOWING a subnet range is fine!
#   Rule 9:  DO NOT disable any valid user accounts listed in the packet
#   Rule 10: DO NOT disable SSH on Linux machines - only HARDEN it!
#   Rule 14: Password changes limited to 3 per host per comp session
#   Rule 15: Red Team tools only run if /greyteam_key exists - DO NOT DELETE IT
#   Rule 16: Blue Team may request up to 3 host reverts per competition day
#
# GREYTEAM NOTES (learned from competition feedback - Grey Team is real infra):
#   - "greyteam" user is NOT in the packet but IS a valid system user - never lock!
#   - SSH AllowUsers MUST include greyteam or Grey Team loses SSH access entirely
#   - TCP Wrappers + UFW MUST whitelist 172.20.0.0/24 - they jump from anywhere in mgmt range
#   - PAM common-auth/account/password MUST NOT be edited - previous edit broke ALL auth
#
# SCORED LINUX SERVICES:
#   ponyville       (10.0.10.3)  Debian 13    Apache2
#   seaddle         (10.0.10.4)  Debian 13    MariaDB
#   trotsylvania    (10.0.10.5)  Debian 13    CUPS
#   crystal-empire  (10.0.10.6)  Debian 13    vsftpd
#   everfree-forest (10.0.20.3)  Debian 13    IRC (ngircd/inspircd)
#   griffonstone    (10.0.20.4)  Debian 13    Nginx
#   cloudsdale      (10.0.30.4)  Ubuntu 24.04 Workstation
#   vanhoover       (10.0.30.5)  Ubuntu 24.04 Workstation
#   whinnyapolis    (10.0.30.6)  Ubuntu 24.04 Workstation
#
# NOTES:
#   Author:       Christian Tomassetti + Claude AI
#   Requires:     Bash 4+ and root (sudo) privileges
#   Compatible:   Debian 13 (Trixie), Ubuntu 24.04 LTS
#   Last Updated: 02/25/2026
#
# USAGE:
#   sudo ./SecureNix.sh [OPTIONS]
#
# OPTIONS:
#   --help           Display this help menu
#   --all            Run ALL phases (same as no args)
#   --phase1         User Account Management (interactive)
#   --phase2         Password Policy Hardening (PAM)
#   --phase3         Firewall Hardening - UFW (service selector)
#   --phase4         SSH Hardening (NEVER disable - Rule 10!)
#   --phase5         Network Security (sysctl, disable bad services)
#   --phase6         Backdoor Detection
#   --phase7         System Hardening (AppArmor, perms, mounts)
#   --phase8         Audit Logging (auditd)
#   --phases N,M,... Run selected phases (e.g., --phases 1,3,8)
#
# EXAMPLES:
#   sudo ./SecureNix.sh
#   sudo ./SecureNix.sh --all
#   sudo ./SecureNix.sh --phase1
#   sudo ./SecureNix.sh --phase1 --phase3
#   sudo ./SecureNix.sh --phases 1,3,8
#   sudo ./SecureNix.sh --help
# ==============================================================================

set -uo pipefail

# ==============================================================================
# ROOT CHECK
# ==============================================================================
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root."
    echo "Usage: sudo ./SecureNix.sh"
    exit 1
fi

# ==============================================================================
# ARGUMENT PARSING
# ==============================================================================
RUN_PHASE1=false; RUN_PHASE2=false; RUN_PHASE3=false; RUN_PHASE4=false
RUN_PHASE5=false; RUN_PHASE6=false; RUN_PHASE7=false; RUN_PHASE8=false
RUNNING_INDIVIDUAL_PHASE=false
SELECTED_PHASES=()

show_help() {
    echo ""
    echo "================================================================================"
    echo "                SecureNix.sh - Linux Hardening Script"
    echo "                Time to lock out Red... For good :)"
    echo "================================================================================"
    echo ""
    echo "USAGE:"
    echo "    sudo ./SecureNix.sh [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "    --help          Display this help menu"
    echo "    --all           Run ALL phases (same as no args)"
    echo "    --phase1        User Account Management    - Interactive lock/remove bad users!"
    echo "    --phase2        Password Policy (PAM)      - Enforce strong passwords!"
    echo "    --phase3        Firewall (UFW)             - Service selector, block bad traffic!"
    echo "    --phase4        SSH Hardening              - Harden SSH (DO NOT DISABLE - Rule 10)!"
    echo "    --phase5        Network Security           - Sysctl, disable bad services/pkgs!"
    echo "    --phase6        Backdoor Detection         - Scan for sneaky Red Team persistence!"
    echo "    --phase7        System Hardening           - AppArmor, permissions, mounts!"
    echo "    --phase8        Audit Logging (auditd)     - Full auditd rule set!"
    echo "    --phases N,...  Run selected phases        - e.g., --phases 1,3,8"
    echo ""
    echo "DEFAULT:"
    echo "    (no args)       Run ALL phases interactively"
    echo ""
    echo "EXAMPLES:"
    echo "    sudo ./SecureNix.sh"
    echo "    sudo ./SecureNix.sh --all"
    echo "    sudo ./SecureNix.sh --phase1"
    echo "    sudo ./SecureNix.sh --phase1 --phase3 --phase8"
    echo "    sudo ./SecureNix.sh --phases 1,3,8"
    echo ""
    echo "COMPETITION RULES SUMMARY:"
    echo "    Rule 5:  NEVER touch files with 'greyteam' in their name"
    echo "    Rule 7:  NEVER block entire subnets"
    echo "    Rule 9:  NEVER disable valid competition user accounts"
    echo "    Rule 10: NEVER disable SSH on Linux!"
    echo "    Rule 14: Max 3 password changes per host per session"
    echo "    Rule 15: NEVER delete /greyteam_key"
    echo "================================================================================"
    exit 0
}

if [[ $# -eq 0 ]]; then
    RUN_PHASE1=true; RUN_PHASE2=true; RUN_PHASE3=true; RUN_PHASE4=true
    RUN_PHASE5=true; RUN_PHASE6=true; RUN_PHASE7=true; RUN_PHASE8=true
    SELECTED_PHASES=(1 2 3 4 5 6 7 8)
else
    PARSED_PHASES=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)   show_help ;;
            --all)
                RUN_PHASE1=true; RUN_PHASE2=true; RUN_PHASE3=true; RUN_PHASE4=true
                RUN_PHASE5=true; RUN_PHASE6=true; RUN_PHASE7=true; RUN_PHASE8=true
                SELECTED_PHASES=(1 2 3 4 5 6 7 8)
                ;;
            --phase1)    PARSED_PHASES+=(1) ;;
            --phase2)    PARSED_PHASES+=(2) ;;
            --phase3)    PARSED_PHASES+=(3) ;;
            --phase4)    PARSED_PHASES+=(4) ;;
            --phase5)    PARSED_PHASES+=(5) ;;
            --phase6)    PARSED_PHASES+=(6) ;;
            --phase7)    PARSED_PHASES+=(7) ;;
            --phase8)    PARSED_PHASES+=(8) ;;
            --phases)
                shift
                IFS=',' read -ra nums <<< "$1"
                for n in "${nums[@]}"; do PARSED_PHASES+=("$n"); done
                ;;
            *)
                echo "ERROR: Unknown option: $1"
                echo "Run with --help for usage."
                exit 1
                ;;
        esac
        shift
    done

    if [[ ${#PARSED_PHASES[@]} -gt 0 ]]; then
        mapfile -t SELECTED_PHASES < <(printf '%s\n' "${PARSED_PHASES[@]}" | sort -un)
        RUNNING_INDIVIDUAL_PHASE=true
        for p in "${SELECTED_PHASES[@]}"; do
            if [[ $p -lt 1 || $p -gt 8 ]]; then
                echo "ERROR: Invalid phase number: $p. Valid phases are 1-8."
                exit 1
            fi
        done
        for p in "${SELECTED_PHASES[@]}"; do
            case "$p" in
                1) RUN_PHASE1=true ;; 2) RUN_PHASE2=true ;;
                3) RUN_PHASE3=true ;; 4) RUN_PHASE4=true ;;
                5) RUN_PHASE5=true ;; 6) RUN_PHASE6=true ;;
                7) RUN_PHASE7=true ;; 8) RUN_PHASE8=true ;;
            esac
        done
    fi
fi

# ==============================================================================
# CRITICAL COMPETITION VARIABLES - CDT TEAM Charlie SPRING 2026
# *** EDIT THE SECTIONS MARKED BELOW BEFORE RUNNING ***
# ==============================================================================

# ---------------------------------------------------------------------------
# SAFE USERS - Competition packet users (Rule 9: DO NOT disable these!)
# ---------------------------------------------------------------------------
SAFE_USERS=(
    # === GREY TEAM (infrastructure) - NOT in packet but MUST NEVER be touched ===
    # greyteam logs in via SSH to manage infrastructure. Any global change that
    # affects all users (AllowUsers, PAM, account locking) must preserve this account.
    "greyteam" "grayteam" "grey_team" "gray_team"

    # === SYSTEM / SERVICE ACCOUNTS (never touch these) ===
    "root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail"
    "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats"
    "nobody" "systemd-network" "systemd-resolve" "systemd-timesync"
    "messagebus" "avahi-autoipd" "sshd" "ntp" "ftp" "cups" "postfix"
    "mysql" "mariadb" "ftpuser" "vsftpd" "nginx" "apache2" "www"
    "_apt" "systemd-coredump" "landscape" "pollinate" "ubuntu" "lxd"
    "tcpdump" "usbmux" "rtkit" "pulse" "saned" "colord" "geoclue"
    "gdm" "lightdm" "sddm" "ircd" "ngircd" "inspircd" "debian"
    "systemd-oom" "tss" "uuidd" "dnsmasq" "speech-dispatcher"

    # === COMPETITION PACKET USERS (Rule 9 - DO NOT DISABLE!) ===
    # Local Users
    "twilight" "pinkiepie" "applejack" "rarity" "rainbowdash" "fluttershy"
    # Local Admins
    "bigmac" "mayormare" "shiningarmor" "cadance"
    # Domain Users (may also exist as local accounts)
    "spike" "starlight" "trixie" "derpy" "snips" "snails"
    # Domain Admins
    "celestia" "discord" "luna" "starswirl"

    # === BLUE TEAM ADMIN ACCOUNTS ===
    # *** ADD YOUR BLUE TEAM USERNAMES HERE ***
    "blueadmin"
)

# All competition-packet users (used for password changes)
COMP_USERS=(
    "twilight" "pinkiepie" "applejack" "rarity" "rainbowdash" "fluttershy"
    "bigmac" "mayormare" "shiningarmor" "cadance"
    "spike" "starlight" "trixie" "derpy" "snips" "snails"
    "celestia" "discord" "luna" "starswirl"
)

# Blue team members (accounts YOU control - keep their authorized_keys!)
# *** EDIT THIS LIST WITH YOUR ACTUAL BLUE TEAM USERNAMES ***
AUTHORIZED_ADMINS=(
    "blueadmin"
    "bigmac"
    "mayormare"
    "shiningarmor"
    "cadance"
    "celestia"
    "discord"
    "luna"
    "starswirl"
)

# ---------------------------------------------------------------------------
# PASSWORD CONFIGURATION
# *** CHANGE THIS TO YOUR SECURE PASSWORD BEFORE RUNNING! ***
# CRITICAL: Update on the SCORING PORTAL FIRST (Rule 14 - max 3 changes/host)
# Default from packet: Friendship0!
# ---------------------------------------------------------------------------
SET_ALL_USER_PASSWORDS="MyLittlePonySucks1!"   # <--- CHANGE ME

# ---------------------------------------------------------------------------
# SAFE IP ADDRESSES - Scoring engine, jumpboxes, competition infrastructure
# Rule 7: Do NOT block subnets. Whitelisting (ALLOWING) a range is fine.
#
# GREY TEAM ACCESS: Grey Team may jump from ANY IP in 172.20.0.0/24, not just
# the listed jumpboxes. MGMT_SUBNET below is whitelisted in UFW + TCP Wrappers
# so Grey Team infra access is never blocked regardless of which host they use.
# ---------------------------------------------------------------------------
SAFE_IP_ADDRESSES=(
    # Scoring engine (CRITICAL - never block this!)
    # Accessible via: https://scoring.mlp.local:443  |  nc scoring.mlp.local 444  |  172.20.0.100:444
    "172.20.0.100"

    # Blue Team jumpboxes (jumpblue1-10) - Ubuntu 24.04 Desktop, 172.20.32-127 mgmt subnet
    # Credentials for all jumpboxes: Friendship0!
    # Access: CyberRange Sshwifty (CLI) or CyberRange RustDesk Relay (GUI)
    "172.20.0.41"   # jumpblue1  | ExtIP: 100.65.6.247  | RustDesk: 507 549 506
    "172.20.0.42"   # jumpblue2  | ExtIP: 100.65.6.186  | RustDesk: 514 264 008
    "172.20.0.43"   # jumpblue3  | ExtIP: 100.65.7.94   | RustDesk: 515 186 532
    "172.20.0.44"   # jumpblue4  | ExtIP: 100.65.6.185  | RustDesk: 513 810 519
    "172.20.0.45"   # jumpblue5  | ExtIP: 100.65.7.201  | RustDesk: 503 969 997  [UPDATED - overrides packet]
    "172.20.0.46"   # jumpblue6  | ExtIP: 100.65.3.191  | RustDesk: 199 067 4293
    "172.20.0.47"   # jumpblue7  | ExtIP: 100.65.6.2    | RustDesk: 512 381 411
    "172.20.0.48"   # jumpblue8  | ExtIP: 100.65.3.215  | RustDesk: 506 287 610
    "172.20.0.49"   # jumpblue9  | ExtIP: 100.65.8.5    | RustDesk: 503 963 007
    "172.20.0.40"   # jumpblue10 | ExtIP: 100.65.2.107  | RustDesk: 519 436 120
    "100.65.6.247"  # jumpblue1  | ExtIP: 100.65.6.247  | RustDesk: 507 549 506
    "100.65.6.186"  # jumpblue2  | ExtIP: 100.65.6.186  | RustDesk: 514 264 008
    "100.65.7.94"   # jumpblue3  | ExtIP: 100.65.7.94   | RustDesk: 515 186 532
    "100.65.6.185"  # jumpblue4  | ExtIP: 100.65.6.185  | RustDesk: 513 810 519
    "100.65.7.201"  # jumpblue5  | ExtIP: 100.65.7.201  | RustDesk: 503 969 997  [UPDATED - overrides packet]
    "100.65.3.191"  # jumpblue6  | ExtIP: 100.65.3.191  | RustDesk: 199 067 4293
    "100.65.6.2"    # jumpblue7  | ExtIP: 100.65.6.2    | RustDesk: 512 381 411
    "100.65.3.215"  # jumpblue8  | ExtIP: 100.65.3.215  | RustDesk: 506 287 610
    "100.65.8.5"    # jumpblue9  | ExtIP: 100.65.8.5    | RustDesk: 503 963 007
    "100.65.2.107"  # jumpblue10 | ExtIP: 100.65.2.107  | RustDesk: 519 436 120

    # Core subnet scored hosts (10.0.10.0/24)
    "10.0.10.1"     # canterlot       - Windows Server 2022 - Active Directory
    "10.0.10.2"     # manehatten      - Windows Server 2022 - MSSQL
    "10.0.10.3"     # ponyville       - Debian 13           - Apache2
    "10.0.10.4"     # seaddle         - Debian 13           - MariaDB
    "10.0.10.5"     # trotsylvania    - Debian 13           - CUPS
    "10.0.10.6"     # crystal-empire  - Debian 13           - vsftpd

    # DMZ subnet scored hosts (10.0.20.0/24)
    "10.0.20.1"     # las-pegasus     - Windows Server 2022 - IIS
    "10.0.20.2"     # appleloosa      - Windows Server 2022 - SMB
    "10.0.20.3"     # everfree-forest - Debian 13           - IRC
    "10.0.20.4"     # griffonstone    - Debian 13           - Nginx

    # Internal subnet workstations (10.0.30.0/24)
    "10.0.30.1"     # baltamare       - Windows 10          - Workstation
    "10.0.30.2"     # neighara-falls  - Windows 10          - Workstation
    "10.0.30.3"     # fillydelphia    - Windows 10          - Workstation
    "10.0.30.4"     # cloudsdale      - Ubuntu 24.04        - Workstation
    "10.0.30.5"     # vanhoover       - Ubuntu 24.04        - Workstation
    "10.0.30.6"     # whinnyapolis    - Ubuntu 24.04        - Workstation

    # Loopback (always safe)
    "127.0.0.1" "::1"
)

# Full management subnet - whitelisted as an ALLOW range in UFW and TCP Wrappers.
# Grey Team uses 172.20.0.0/24 but their exact source IP is unpredictable.
# Rule 7 prohibits BLOCKING subnets - this is an ALLOW rule, which is fine.
MGMT_SUBNET="172.20.0.0/24"

# Known safe listening ports (used by backdoor detection scanner)
SAFE_PORTS=(
    22    # SSH  - Rule 10: NEVER disable SSH on Linux!
    80    # HTTP
    443   # HTTPS / Scoring portal
    444   # Scoring engine netcat port
    3306  # MariaDB / MySQL
    3307  # MariaDB alternate
    21    # FTP command (vsftpd)
    20    # FTP data (vsftpd)
    631   # CUPS printing
    6667  # IRC
    6697  # IRC over TLS
    139   # SMB/NetBIOS (needed for AD comms)
    445   # SMB
    389   # LDAP
    636   # LDAPS
    88    # Kerberos (AD interop)
    53    # DNS
    323   # Chrony NTP
    68    # DHCP client
)

# ==============================================================================
# LOGGING & STATE INFRASTRUCTURE
# ==============================================================================
LOG_DIR="/var/log/blueteam"
LOG_FILE="$LOG_DIR/SecureNix_$(date +%Y%m%d_%H%M%S).log"
STATE_DIR="/var/lib/blueteam"
STATE_FILE="$STATE_DIR/last-completion-state.json"
SCRIPT_START_TIME=$(date +%s)
HOSTNAME_VAL=$(hostname)
CHANGES=()
REMOVED_USERS=()
SECURITY_ISSUES=()
CHANGES_COUNT=0
PASSWORD_CHANGE_COUNT=0
MAX_PASSWORD_CHANGES=3

mkdir -p "$LOG_DIR" "$STATE_DIR"

# Script run counter
SCRIPT_RUN_COUNT=1
if [[ -f "$STATE_FILE" ]]; then
    prev=$(grep -o '"RunCount":[0-9]*' "$STATE_FILE" 2>/dev/null | grep -o '[0-9]*' || echo 0)
    SCRIPT_RUN_COUNT=$(( prev + 1 ))
fi

# Detect current operator (the user who invoked sudo)
CURRENT_OPERATOR="${SUDO_USER:-}"
if [[ -z "$CURRENT_OPERATOR" ]]; then
    CURRENT_OPERATOR="${USER:-root}"
fi

# Color codes
C_RESET='\033[0m';   C_RED='\033[0;31m';     C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'; C_CYAN='\033[0;36m';  C_MAGENTA='\033[0;35m'
C_WHITE='\033[1;37m';  C_BOLD='\033[1m';     C_BLUE='\033[0;34m'

# Log function - writes to file (no color) and console (with color)
log() {
    local msg="$1"
    local level="${2:-INFO}"
    local timestamp; timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local line="[$timestamp] [$level] $msg"
    echo "$line" >> "$LOG_FILE"
    case "$level" in
        SUCCESS)  echo -e "${C_GREEN}${line}${C_RESET}" ;;
        WARNING)  echo -e "${C_YELLOW}${line}${C_RESET}" ;;
        ERROR)    echo -e "${C_RED}${line}${C_RESET}" ;;
        CRITICAL) echo -e "${C_MAGENTA}${C_BOLD}${line}${C_RESET}" ;;
        REMOVED)  echo -e "${C_CYAN}${line}${C_RESET}" ;;
        SKIPPED)  echo -e "${C_BLUE}${line}${C_RESET}" ;;
        *)        echo -e "${C_WHITE}${line}${C_RESET}" ;;
    esac
}

add_change() {
    CHANGES+=("[${1}] ${2} - ${3}${4:+ | $4}")
    (( CHANGES_COUNT++ )) || true
}

add_security_issue() {
    SECURITY_ISSUES+=("$1")
    log "SECURITY ISSUE: $1" "CRITICAL"
}

is_safe_user() {
    local user="$1"
    for su in "${SAFE_USERS[@]}"; do [[ "$su" == "$user" ]] && return 0; done
    return 1
}

is_admin_user() {
    local user="$1"
    for au in "${AUTHORIZED_ADMINS[@]}"; do [[ "$au" == "$user" ]] && return 0; done
    return 1
}

# ==============================================================================
# BANNER
# ==============================================================================
echo ""
echo -e "${C_CYAN}================================================================================${C_RESET}"
echo -e "${C_GREEN}           SecureNix.sh - Linux Hardening Script${C_RESET}"
echo -e "${C_GREEN}           Time to lock out Red... For good :)${C_RESET}"
echo -e "${C_CYAN}================================================================================${C_RESET}"
echo -e "${C_YELLOW}  Host:        $HOSTNAME_VAL${C_RESET}"
echo -e "${C_YELLOW}  Operator:    $CURRENT_OPERATOR${C_RESET}"
echo -e "${C_YELLOW}  Script Run:  #$SCRIPT_RUN_COUNT${C_RESET}"
echo -e "${C_YELLOW}  Log File:    $LOG_FILE${C_RESET}"
echo -e "${C_YELLOW}  Phases:      $(IFS=', '; echo "${SELECTED_PHASES[*]}")${C_RESET}"
echo -e "${C_CYAN}================================================================================${C_RESET}"
echo ""
log "SecureNix.sh started - Run #$SCRIPT_RUN_COUNT | Host: $HOSTNAME_VAL | Operator: $CURRENT_OPERATOR" "INFO"
log "Executing phase(s): $(IFS=', '; echo "${SELECTED_PHASES[*]}")" "INFO"

# ==============================================================================
# GREYTEAM_KEY CHECK (Rule 15 - NEVER delete this file!)
# ==============================================================================
log "Checking for /greyteam_key (Rule 15)..." "INFO"
if [[ -f "/greyteam_key" ]]; then
    log "NOTICE: /greyteam_key EXISTS on this host." "WARNING"
    log "  Rule 15: Red Team tools may run on this host." "WARNING"
    log "  Rule  5: DO NOT modify or delete /greyteam_key!" "WARNING"
    add_security_issue "NOTICE: /greyteam_key present - Red Team tools authorized on this host"
else
    log "/greyteam_key NOT found - Red Team tools should not be running here." "INFO"
fi
echo ""

# ==============================================================================
# PHASE 1 - USER ACCOUNT MANAGEMENT (INTERACTIVE)
# ==============================================================================
if $RUN_PHASE1; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 1: USER ACCOUNT MANAGEMENT" "CRITICAL"
log "============================================================" "INFO"
log "Rule 9:  DO NOT disable valid competition users!" "WARNING"
log "Rule 14: Password changes limited to 3 per host per session!" "WARNING"

# --- 1a: Identify current operator account and protect it -------------------
log "Detected operator account: '$CURRENT_OPERATOR' - this account is PROTECTED." "INFO"
if ! is_safe_user "$CURRENT_OPERATOR"; then
    log "Adding operator '$CURRENT_OPERATOR' to protected list for this session." "WARNING"
    SAFE_USERS+=("$CURRENT_OPERATOR")
fi

# --- 1a.5: Ensure Blue Team admin accounts exist ----------------------------
log "Ensuring Blue Team admin accounts exist..." "INFO"

for admin in "${AUTHORIZED_ADMINS[@]}"; do
    if id "$admin" &>/dev/null; then
        log "Blue Team admin '$admin' already exists." "INFO"
    else
        log "Creating Blue Team admin account: $admin" "WARNING"

        # Create user with home directory and bash shell
        useradd -m -s /bin/bash "$admin" 2>/dev/null && \
            log "  User created: $admin" "SUCCESS" || \
            log "  Failed to create user: $admin" "ERROR"

        # Add to sudo group (Debian/Ubuntu)
        usermod -aG sudo "$admin" 2>/dev/null && \
            log "  Added $admin to sudo group." "SUCCESS" || \
            log "  Failed to add $admin to sudo group." "WARNING"

        # Set initial password (if configured)
        if [[ -n "$SET_ALL_USER_PASSWORDS" ]]; then
            echo "$admin:$SET_ALL_USER_PASSWORDS" | chpasswd 2>/dev/null && \
                log "  Password set for $admin." "SUCCESS" || \
                log "  Failed to set password for $admin." "WARNING"
        fi

        add_change "Users" "Created Blue Team admin account" "SUCCESS" "$admin"
    fi
done

# --- 1b: Scan for unauthorized users ----------------------------------------
log "Scanning all user accounts for unauthorized entries..." "INFO"
SUSPICIOUS_USERS=()
while IFS=: read -r username _ uid _ _ home shell; do
    [[ $uid -lt 1000 || $uid -eq 65534 ]] && continue
    [[ "$shell" == "/usr/sbin/nologin" || "$shell" == "/bin/false" ]] && continue
    if ! is_safe_user "$username"; then
        SUSPICIOUS_USERS+=("$username|$uid|$home|$shell")
        log "SUSPICIOUS USER FOUND: $username (UID=$uid, shell=$shell, home=$home)" "CRITICAL"
        add_security_issue "Suspicious user account: $username (UID=$uid)"
    fi
done < /etc/passwd

# --- 1c: Interactive user removal selector -----------------------------------
# Step 1.5 - Like SecureWin's interactive selector
if [[ ${#SUSPICIOUS_USERS[@]} -eq 0 ]]; then
    log "No unauthorized users found." "SUCCESS"
else
    echo ""
    echo -e "${C_MAGENTA}${C_BOLD}========================================${C_RESET}"
    echo -e "${C_MAGENTA}${C_BOLD}  UNAUTHORIZED USERS FOUND - REVIEW NOW${C_RESET}"
    echo -e "${C_MAGENTA}${C_BOLD}========================================${C_RESET}"
    echo ""
    echo -e "${C_YELLOW}The following suspicious user accounts were detected:${C_RESET}"
    echo ""

    declare -A USER_SELECTIONS
    local_idx=1
    for entry in "${SUSPICIOUS_USERS[@]}"; do
        IFS='|' read -r uname uuid uhome ushell <<< "$entry"
        echo -e "  ${C_CYAN}[$local_idx]${C_RESET} ${C_WHITE}$uname${C_RESET}  (UID=$uuid | shell=$ushell | home=$uhome)"
        USER_SELECTIONS[$local_idx]="$uname"
        (( local_idx++ ))
    done

    echo ""
    echo -e "${C_GREEN}${C_BOLD}DEFAULT: ALL suspicious users will be locked.${C_RESET}"
    echo -e "${C_CYAN}OPTIONS (to opt out of locking specific users):${C_RESET}"
    echo -e "  ${C_WHITE}Enter${C_RESET}   - Lock ALL (default, just press Enter)"
    echo -e "  ${C_WHITE}none${C_RESET}    - Skip user locking entirely (not recommended)"
    echo -e "  ${C_WHITE}1,2,3${C_RESET}   - SKIP locking these specific users by number"
    echo -e "  ${C_WHITE}1-3${C_RESET}     - SKIP locking a range of users"
    echo ""
    echo -e "${C_RED}NOTE: Operator account '${CURRENT_OPERATOR}' is ALWAYS protected.${C_RESET}"
    echo ""

    read -rp "$(echo -e "${C_CYAN}Enter numbers to SKIP (or press Enter to lock ALL): ${C_RESET}")" user_sel
    user_sel="${user_sel,,}"  # lowercase

    # Build skip list first, then lock everyone not in it
    SKIP_INDICES=()
    if [[ "$user_sel" == "none" ]]; then
        log "User locking SKIPPED by operator." "SKIPPED"
        # Mark all as skip by putting all indices in SKIP_INDICES
        for i in "${!USER_SELECTIONS[@]}"; do SKIP_INDICES+=("$i"); done
    elif [[ -z "$user_sel" ]]; then
        : # Empty = lock all, skip nobody
    else
        # Parse comma-separated and ranges into skip list
        IFS=',' read -ra parts <<< "$user_sel"
        for part in "${parts[@]}"; do
            part="${part// /}"
            if [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                for (( r=${BASH_REMATCH[1]}; r<=${BASH_REMATCH[2]}; r++ )); do
                    SKIP_INDICES+=("$r")
                done
            elif [[ "$part" =~ ^[0-9]+$ ]]; then
                SKIP_INDICES+=("$part")
            fi
        done
    fi

    # Build final lock list: all users NOT in SKIP_INDICES
    USERS_TO_LOCK=()
    for i in "${!USER_SELECTIONS[@]}"; do
        skip=false
        for si in "${SKIP_INDICES[@]}"; do [[ "$i" == "$si" ]] && skip=true && break; done
        if ! $skip; then
            USERS_TO_LOCK+=("${USER_SELECTIONS[$i]}")
        else
            log "SKIPPED locking (operator opt-out): ${USER_SELECTIONS[$i]}" "SKIPPED"
        fi
    done

    # Perform locking on selected users
    for uname in "${USERS_TO_LOCK[@]}"; do
        # Final safety check - never lock the operator
        if [[ "$uname" == "$CURRENT_OPERATOR" ]]; then
            log "SKIPPED: '$uname' is the current operator - refusing to lock." "WARNING"
            continue
        fi

        log "Locking unauthorized user: $uname" "REMOVED"

        # Lock the account password
        usermod -L "$uname" 2>/dev/null && \
            log "  Account locked (password): $uname" "SUCCESS" || \
            log "  Could not lock password for: $uname" "ERROR"

        # Set shell to nologin
        usermod -s /usr/sbin/nologin "$uname" 2>/dev/null && \
            log "  Shell set to nologin: $uname" "SUCCESS" || \
            log "  Could not change shell for: $uname" "WARNING"

        # Expire account immediately
        usermod -e 1 "$uname" 2>/dev/null || true

        # Kill any live sessions
        pkill -u "$uname" 2>/dev/null && \
            log "  Killed active sessions for: $uname" "SUCCESS" || true

        # Clear their SSH keys
        UHOME=$(getent passwd "$uname" | cut -d: -f6)
        if [[ -f "$UHOME/.ssh/authorized_keys" ]]; then
            cp "$UHOME/.ssh/authorized_keys" "$UHOME/.ssh/authorized_keys.bak.$(date +%s)" 2>/dev/null || true
            > "$UHOME/.ssh/authorized_keys"
            log "  Cleared SSH authorized_keys for: $uname" "SUCCESS"
        fi

        REMOVED_USERS+=("$uname (locked)")
        add_change "Users" "Lock unauthorized account" "SUCCESS" "$uname"
    done
fi
unset USER_SELECTIONS

# --- 1d: Check for UID=0 accounts other than root ---------------------------
log "Checking for non-root UID=0 accounts..." "INFO"
while IFS=: read -r username _ uid _; do
    if [[ $uid -eq 0 && "$username" != "root" ]]; then
        add_security_issue "Non-root UID=0 account: $username - INVESTIGATE IMMEDIATELY"
        log "CRITICAL: Non-root UID=0: $username" "CRITICAL"
    fi
done < /etc/passwd

# --- 1e: Audit and REMEDIATE sudo privileges ---------------------------------
log "Auditing and remediating sudo configuration..." "INFO"
SUDOERS_ISSUES_FOUND=0

# Helper: remove or comment out a NOPASSWD line from a sudoers file
# Uses 'visudo -c' to validate before applying, then writes via temp file
remediate_sudoers_nopasswd() {
    local filepath="$1"
    local bad_line="$2"
    local bak="${filepath}.bak.$(date +%s)"

    cp "$filepath" "$bak" 2>/dev/null && \
        log "  Backed up: $filepath -> $bak" "INFO" || \
        { log "  Could not back up $filepath - SKIPPING remediation for safety" "ERROR"; return 1; }

    # Strategy: comment out lines containing NOPASSWD
    # Use a temp file + visudo -c to validate before overwriting
    local tmpfile; tmpfile=$(mktemp)
    # Escape special chars in bad_line for sed
    local escaped_line; escaped_line=$(printf '%s\n' "$bad_line" | sed 's/[[\.*^$()+?{|]/\\&/g')
    sed "s|^${escaped_line}$|# SecureNix-REMOVED: &|" "$filepath" > "$tmpfile" 2>/dev/null

    # Validate with visudo before applying
    if visudo -c -f "$tmpfile" &>/dev/null; then
        cp "$tmpfile" "$filepath"
        log "  REMEDIATED: Commented out NOPASSWD line in $filepath" "SUCCESS"
        log "  Removed line: $bad_line" "SUCCESS"
        add_change "Sudoers" "Remove NOPASSWD entry" "SUCCESS" "$filepath"
        (( SUDOERS_ISSUES_FOUND++ )) || true
        rm -f "$tmpfile"
        return 0
    else
        # visudo -c failed - the file change broke something, restore backup
        cp "$bak" "$filepath" 2>/dev/null || true
        log "  visudo validation failed on modified $filepath - backup restored, manual review needed!" "ERROR"
        add_security_issue "Could not auto-remediate NOPASSWD in $filepath - MANUAL ACTION REQUIRED: $bad_line"
        rm -f "$tmpfile"
        return 1
    fi
}

# Scan /etc/sudoers
if [[ -f /etc/sudoers ]]; then
    log "Scanning /etc/sudoers for NOPASSWD entries..." "INFO"
    while IFS= read -r line; do
        [[ "$line" =~ ^# || "$line" =~ ^#.*REMOVED || -z "$line" ]] && continue
        if echo "$line" | grep -qE 'NOPASSWD'; then
            log "NOPASSWD FOUND in /etc/sudoers: $line" "CRITICAL"
            add_security_issue "NOPASSWD sudo in /etc/sudoers: $line"
            log "  Attempting auto-remediation..." "WARNING"
            remediate_sudoers_nopasswd "/etc/sudoers" "$line"
        fi
    done < /etc/sudoers
fi

# Scan /etc/sudoers.d/*
if [[ -d /etc/sudoers.d ]]; then
    log "Scanning /etc/sudoers.d/ for NOPASSWD entries..." "INFO"
    for sf in /etc/sudoers.d/*; do
        [[ -f "$sf" ]] || continue
        [[ "$sf" == *greyteam* ]] && {
            log "  SKIPPING (Rule 5 - greyteam file): $sf" "SKIPPED"
            continue
        }
        while IFS= read -r line; do
            [[ "$line" =~ ^# || "$line" =~ ^#.*REMOVED || -z "$line" ]] && continue
            if echo "$line" | grep -qE 'NOPASSWD'; then
                log "NOPASSWD FOUND in $sf: $line" "CRITICAL"
                add_security_issue "NOPASSWD sudo in $sf: $line"
                log "  Attempting auto-remediation..." "WARNING"
                remediate_sudoers_nopasswd "$sf" "$line"
            fi
        done < "$sf"
    done
fi

# Also check for wildcard ALL=(ALL) entries that give full root without NOPASSWD
# These are suspicious but may be intentional - flag only
if [[ -f /etc/sudoers ]]; then
    while IFS= read -r line; do
        [[ "$line" =~ ^# || -z "$line" ]] && continue
        # Non-competition users with ALL privileges
        if echo "$line" | grep -qE 'ALL=\(ALL\).*ALL|ALL=\(ALL:ALL\).*ALL'; then
            username_part=$(echo "$line" | awk '{print $1}')
            # Check if it's a non-packet user (excluding % groups like %sudo which are OK)
            if [[ ! "$username_part" =~ ^% ]]; then
                if ! is_safe_user "$username_part" 2>/dev/null; then
                    log "SUSPICIOUS: Non-packet user with full sudo in /etc/sudoers: $line" "CRITICAL"
                    add_security_issue "Suspicious full sudo for non-packet user: $line"
                fi
            fi
        fi
    done < /etc/sudoers
fi

if [[ $SUDOERS_ISSUES_FOUND -eq 0 ]]; then
    log "Sudo configuration looks clean - no NOPASSWD entries found." "SUCCESS"
else
    log "$SUDOERS_ISSUES_FOUND NOPASSWD sudo issue(s) remediated." "SUCCESS"
fi

# --- 1f: Audit SSH authorized_keys for ALL users ----------------------------
log "Auditing SSH authorized_keys files..." "INFO"
for homedir in /home/*/; do
    [[ -d "$homedir" ]] || continue
    auth_keys="$homedir/.ssh/authorized_keys"
    username=$(basename "$homedir")
    if [[ -f "$auth_keys" ]]; then
        # grep -c counts lines in the file itself; strip any whitespace to get a clean integer
        key_count=$(grep -c '' "$auth_keys" 2>/dev/null | tr -d '[:space:]' || echo 0)
        key_count=$(( key_count + 0 ))   # force integer
        # Count only non-comment, non-blank lines for the actual key count
        real_keys=$(grep -Evc '^\s*#|^\s*$' "$auth_keys" 2>/dev/null | tr -d '[:space:]' || echo 0)
        real_keys=$(( real_keys + 0 ))
        # Protect authorized admin accounts AND the current operator - keep their keys
        if is_admin_user "$username" || [[ "$username" == "$CURRENT_OPERATOR" ]]; then
            log "Kept authorized_keys for admin/operator: $username ($real_keys key(s))" "INFO"
        else
            cp "$auth_keys" "${auth_keys}.bak.$(date +%s)" 2>/dev/null || true
            > "$auth_keys"
            log "Cleared authorized_keys for: $username ($real_keys key(s) removed)" "REMOVED"
            add_change "SSH" "Clear authorized_keys" "SUCCESS" "$username"
            if [[ $real_keys -gt 0 ]]; then
                add_security_issue "Cleared $real_keys SSH key(s) from non-admin user: $username"
            fi
        fi
    fi
done
# Root authorized_keys - always flag and clear
if [[ -f /root/.ssh/authorized_keys ]]; then
    real_keys=$(grep -Evc '^\s*#|^\s*$' /root/.ssh/authorized_keys 2>/dev/null | tr -d '[:space:]' || echo 0)
    real_keys=$(( real_keys + 0 ))
    if [[ $real_keys -gt 0 ]]; then
        cp /root/.ssh/authorized_keys "/root/.ssh/authorized_keys.bak.$(date +%s)" 2>/dev/null || true
        > /root/.ssh/authorized_keys
        add_security_issue "CLEARED $real_keys SSH key(s) from ROOT authorized_keys!"
        log "CRITICAL: Cleared $real_keys key(s) from root authorized_keys!" "CRITICAL"
        add_change "SSH" "Clear ROOT authorized_keys" "SUCCESS" "$real_keys key(s) removed"
    else
        log "root authorized_keys is empty - OK." "INFO"
    fi
fi

# --- 1g: SecureWin-parity password selector (Step 1.5) ----------------------
log "" "INFO"
log "Step 1.5: Selective password reset (max $MAX_PASSWORD_CHANGES users per host per session)..." "CRITICAL"
log "A menu will be displayed. Select up to $MAX_PASSWORD_CHANGES users to reset to the team password." "INFO"
log "CRITICAL: Update passwords on the SCORING PORTAL FIRST: https://scoring.mlp.local:443" "WARNING"

# Dedicated password change log (separate file like SecureWin)
PW_CHANGE_LOG="$LOG_DIR/3-user-password-changes-$(date +%Y-%m-%d-%H%M%S).log"
pw_log() {
    local msg="$1"
    local timestamp; timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $msg" >> "$PW_CHANGE_LOG"
    log "  [PW-LOG] $msg" "INFO"
}
pw_log "Host: $HOSTNAME_VAL"
pw_log "Operator: $CURRENT_OPERATOR"
pw_log "Purpose: Track up to $MAX_PASSWORD_CHANGES password changes per host per competition day"
pw_log "Rule 14: MAX $MAX_PASSWORD_CHANGES CHANGES ENFORCED"
log "Password change log: $PW_CHANGE_LOG" "INFO"

# Handle placeholder password - prompt interactively
if [[ "$SET_ALL_USER_PASSWORDS" == "<CHANGE-THIS-BEFORE-RUNNING>" ]]; then
    echo ""
    echo -e "${C_RED}${C_BOLD}WARNING: SET_ALL_USER_PASSWORDS is still the default placeholder!${C_RESET}"
    echo -e "${C_YELLOW}Enter the new password to set for selected users (input hidden):${C_RESET}"
    read -rs -p "$(echo -e "${C_CYAN}New password: ${C_RESET}")" input_password; echo ""
    read -rs -p "$(echo -e "${C_CYAN}Confirm:      ${C_RESET}")" input_password2; echo ""
    if [[ -z "$input_password" ]]; then
        log "Empty password entered - password changes will be skipped." "ERROR"
        pw_log "SKIPPED: Empty password entered by operator."
    elif [[ "$input_password" != "$input_password2" ]]; then
        log "Passwords did not match - password changes will be skipped." "ERROR"
        pw_log "SKIPPED: Passwords did not match."
        input_password=""
    else
        SET_ALL_USER_PASSWORDS="$input_password"
        log "Password accepted from interactive input." "INFO"
        pw_log "Password accepted from interactive input (not logged for security)."
    fi
fi

if [[ "$SET_ALL_USER_PASSWORDS" == "<CHANGE-THIS-BEFORE-RUNNING>" || -z "$SET_ALL_USER_PASSWORDS" ]]; then
    log "Step 1.5 skipped - no valid password configured." "SKIPPED"
    pw_log "Step 1.5 skipped - no valid password."
else
    # -----------------------------------------------------------------------
    # Build user table - ALL users on the system (not just comp users)
    # Show username, UID, groups they belong to (like SecureWin shows groups)
    # -----------------------------------------------------------------------
    echo ""
    echo -e "${C_CYAN}========================================${C_RESET}"
    echo -e "${C_YELLOW}  USER LIST - SELECT UP TO $MAX_PASSWORD_CHANGES FOR PASSWORD RESET${C_RESET}"
    echo -e "${C_CYAN}========================================${C_RESET}"
    echo ""

    # Collect all users with UID >= 1000 (real human accounts) + root
    declare -a PW_MENU_USERS
    declare -a PW_MENU_UIDS
    declare -a PW_MENU_GROUPS
    declare -a PW_MENU_STATUS

    pw_idx=0
    # Always include root first
    PW_MENU_USERS[$pw_idx]="root"
    PW_MENU_UIDS[$pw_idx]="0"
    root_groups=$(groups root 2>/dev/null | sed 's/.*: //' || echo "root")
    PW_MENU_GROUPS[$pw_idx]="$root_groups"
    root_locked=$(passwd -S root 2>/dev/null | awk '{print $2}' || echo "?")
    PW_MENU_STATUS[$pw_idx]="$root_locked"
    (( pw_idx++ )) || true

    # All human accounts (UID >= 1000, exclude nobody at 65534)
    while IFS=: read -r uname _ uid _ _ _ _; do
        [[ $uid -lt 1000 || $uid -eq 65534 ]] && continue
        PW_MENU_USERS[$pw_idx]="$uname"
        PW_MENU_UIDS[$pw_idx]="$uid"
        ugroups=$(groups "$uname" 2>/dev/null | sed 's/.*: //' || echo "-")
        PW_MENU_GROUPS[$pw_idx]="$ugroups"
        ulocked=$(passwd -S "$uname" 2>/dev/null | awk '{print $2}' || echo "?")
        PW_MENU_STATUS[$pw_idx]="$ulocked"
        (( pw_idx++ )) || true
    done < /etc/passwd

    TOTAL_PW_USERS=$pw_idx

    # Display the table - mirroring SecureWin's Format-Table layout
    printf "\n"
    printf "  ${C_CYAN}%-6s${C_RESET}  ${C_WHITE}%-18s${C_RESET}  %-6s  %-8s  %s\n" \
        "Index" "User" "UID" "Status" "Groups"
    printf "  %-6s  %-18s  %-6s  %-8s  %s\n" \
        "------" "------------------" "------" "--------" "--------------------------------------------"
    for (( i=0; i<TOTAL_PW_USERS; i++ )); do
        num=$(( i + 1 ))
        uname="${PW_MENU_USERS[$i]}"
        uid="${PW_MENU_UIDS[$i]}"
        status="${PW_MENU_STATUS[$i]}"
        grps="${PW_MENU_GROUPS[$i]}"

        # Color code: comp packet users in green, operator in cyan, others in white
        if is_safe_user "$uname" 2>/dev/null && [[ "$uname" != "root" ]]; then
            ucolor="$C_GREEN"
        elif [[ "$uname" == "$CURRENT_OPERATOR" ]]; then
            ucolor="$C_CYAN"
        else
            ucolor="$C_YELLOW"
        fi

        printf "  ${C_WHITE}[%-4s]${C_RESET}  ${ucolor}%-18s${C_RESET}  %-6s  %-8s  %s\n" \
            "$num" "$uname" "$uid" "$status" "$grps"
    done

    echo ""
    echo -e "  ${C_GREEN}Green${C_RESET}  = Competition packet user  |  ${C_CYAN}Cyan${C_RESET}  = Operator  |  ${C_YELLOW}Yellow${C_RESET} = Other"
    echo ""
    echo -e "${C_YELLOW}Selection format examples:${C_RESET}"
    echo -e "  ${C_WHITE}1,3,5${C_RESET}   (comma-separated)"
    echo -e "  ${C_WHITE}1 3 5${C_RESET}   (space-separated)"
    echo -e "  ${C_WHITE}q${C_RESET}       (skip all password changes)"
    echo ""
    echo -e "${C_RED}${C_BOLD}Rule 14: Maximum $MAX_PASSWORD_CHANGES selections allowed. Extra selections will be rejected.${C_RESET}"
    echo ""

    # Selection loop - mirrors SecureWin's while(true) validation loop
    SELECTED_PW_INDICES=()
    while true; do
        read -rp "$(echo -e "${C_CYAN}Enter up to $MAX_PASSWORD_CHANGES user numbers to reset (or press Enter/q to skip): ${C_RESET}")" raw_sel

        # Skip / quit
        if [[ -z "$raw_sel" || "${raw_sel,,}" =~ ^(q|quit|exit|skip)$ ]]; then
            log "No users selected for password reset (skipped by operator)." "WARNING"
            pw_log "No users selected (skipped)."
            break
        fi

        # Parse comma and/or space separated numbers
        IFS=', ' read -ra raw_parts <<< "$raw_sel"
        parsed_nums=()
        bad_input=false
        for part in "${raw_parts[@]}"; do
            [[ -z "$part" ]] && continue
            if ! [[ "$part" =~ ^[0-9]+$ ]]; then
                echo -e "${C_RED}Invalid input: '$part' is not a number. Try again.${C_RESET}"
                bad_input=true; break
            fi
            n=$(( part + 0 ))
            if [[ $n -lt 1 || $n -gt $TOTAL_PW_USERS ]]; then
                echo -e "${C_RED}Number $n is out of range (1-$TOTAL_PW_USERS). Try again.${C_RESET}"
                bad_input=true; break
            fi
            # Deduplicate
            already=false
            for existing in "${parsed_nums[@]}"; do [[ "$existing" == "$n" ]] && already=true && break; done
            $already || parsed_nums+=("$n")
        done
        $bad_input && continue

        if [[ ${#parsed_nums[@]} -gt $MAX_PASSWORD_CHANGES ]]; then
            echo -e "${C_RED}${C_BOLD}Rule 14 enforcement: You selected ${#parsed_nums[@]} users but maximum is $MAX_PASSWORD_CHANGES. Try again.${C_RESET}"
            continue
        fi

        SELECTED_PW_INDICES=("${parsed_nums[@]}")
        break
    done

    # Perform the password changes if selections were made
    if [[ ${#SELECTED_PW_INDICES[@]} -gt 0 ]]; then
        # Build the selected user list for display
        echo ""
        echo -e "${C_YELLOW}Selected users for password reset:${C_RESET}"
        SELECTED_PW_USERNAMES=()
        for idx in "${SELECTED_PW_INDICES[@]}"; do
            real_idx=$(( idx - 1 ))
            uname="${PW_MENU_USERS[$real_idx]}"
            SELECTED_PW_USERNAMES+=("$uname")
            echo -e "  ${C_WHITE}- $uname${C_RESET}"
        done
        echo ""

        # Confirmation prompt - mirrors SecureWin's Y/N confirm
        read -rp "$(echo -e "${C_CYAN}Proceed with resetting passwords for these users to the team password? (Y/N): ${C_RESET}")" pw_confirm
        if [[ "${pw_confirm^^}" != "Y" ]]; then
            log "Password reset cancelled by operator." "WARNING"
            pw_log "Cancelled. Intended: $(IFS=', '; echo "${SELECTED_PW_USERNAMES[*]}")"
        else
            pw_success=0
            pw_fail=0
            for uname in "${SELECTED_PW_USERNAMES[@]}"; do
                if ! id "$uname" &>/dev/null; then
                    log "Cannot reset password: user not found: $uname" "ERROR"
                    pw_log "FAILED: $uname (user not found)"
                    (( pw_fail++ )) || true
                    continue
                fi

                if echo "$uname:$SET_ALL_USER_PASSWORDS" | chpasswd 2>/dev/null; then
                    (( PASSWORD_CHANGE_COUNT++ )) || true
                    log "Password changed: $uname ($PASSWORD_CHANGE_COUNT/$MAX_PASSWORD_CHANGES used)" "SUCCESS"
                    pw_log "SUCCESS: $uname ($PASSWORD_CHANGE_COUNT/$MAX_PASSWORD_CHANGES)"
                    add_change "Users" "Password reset (selective)" "SUCCESS" \
                        "$uname ($PASSWORD_CHANGE_COUNT/$MAX_PASSWORD_CHANGES)"
                    (( pw_success++ )) || true
                else
                    log "Failed to set password for: $uname" "ERROR"
                    pw_log "FAILED: $uname (chpasswd error)"
                    (( pw_fail++ )) || true
                fi
            done

            log "Step 1.5 complete: $pw_success successful, $pw_fail failed." "INFO"
            pw_log "Summary: $pw_success successful, $pw_fail failed."
            pw_log "Completed. Full log: $PW_CHANGE_LOG"

            echo ""
            echo -e "${C_CYAN}Password change log written to:${C_RESET}"
            echo -e "  ${C_CYAN}$PW_CHANGE_LOG${C_RESET}"
            echo ""
        fi
    fi

    unset PW_MENU_USERS PW_MENU_UIDS PW_MENU_GROUPS PW_MENU_STATUS
fi

log "Phase 1 complete." "SUCCESS"
fi  # end Phase 1

# ==============================================================================
# PHASE 2 - PASSWORD POLICY HARDENING
# ==============================================================================
if $RUN_PHASE2; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 2: PASSWORD POLICY HARDENING" "CRITICAL"
log "============================================================" "INFO"
log "SAFE APPROACH: Only touching pwquality.conf and login.defs." "WARNING"
log "PAM common-auth/account/password intentionally NOT modified (broke all auth in testing)." "WARNING"

# Install PAM password quality library
if command -v apt-get &>/dev/null; then
    log "Ensuring libpam-pwquality is installed..." "INFO"
    DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-pwquality 2>/dev/null | \
        grep -E "install|upgraded" | while IFS= read -r l; do log "$l" "INFO"; done || true
fi

# --- 2a: /etc/login.defs (safe - shadow-utils config, not a PAM stack file) --
log "Hardening /etc/login.defs..." "INFO"
LOGIN_DEFS="/etc/login.defs"
cp "$LOGIN_DEFS" "${LOGIN_DEFS}.bak.$(date +%s)" 2>/dev/null || true

set_login_def() {
    local key="$1" val="$2"
    if grep -qE "^${key}[[:space:]]" "$LOGIN_DEFS" 2>/dev/null; then
        sed -i "s|^${key}[[:space:]].*|${key}\t${val}|" "$LOGIN_DEFS"
    else
        echo -e "${key}\t${val}" >> "$LOGIN_DEFS"
    fi
}
set_login_def "PASS_MAX_DAYS"  "90"
set_login_def "PASS_MIN_DAYS"  "1"
set_login_def "PASS_MIN_LEN"   "12"
set_login_def "PASS_WARN_AGE"  "7"
set_login_def "LOGIN_RETRIES"  "3"
set_login_def "LOGIN_TIMEOUT"  "60"
set_login_def "DEFAULT_HOME"   "yes"
set_login_def "UMASK"          "027"
add_change "PasswordPolicy" "login.defs hardened" "SUCCESS" "90d max, 12 char min"
log "login.defs updated." "SUCCESS"

# --- 2b: pwquality.conf (safe - standalone config, cannot break auth stack) --
# pam_pwquality.so reads this file independently. Misconfiguration here only
# affects password complexity enforcement - it cannot lock anyone out.
log "Configuring /etc/security/pwquality.conf..." "INFO"
PWQUAL="/etc/security/pwquality.conf"
if [[ -f "$PWQUAL" ]]; then
    cp "$PWQUAL" "${PWQUAL}.bak.$(date +%s)" 2>/dev/null || true
    cat > "$PWQUAL" << 'PWEOF'
# SecureNix - CDT Team Charlie - Hardened password quality
# Safe to edit: pam_pwquality reads this independently, cannot break auth
minlen = 12
minclass = 3
maxrepeat = 3
maxsequence = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
dictcheck = 1
usercheck = 1
enforcing = 1
PWEOF
    add_change "PasswordPolicy" "pwquality.conf hardened" "SUCCESS" "minlen=12 minclass=3"
    log "pwquality.conf hardened." "SUCCESS"
else
    log "pwquality.conf not found - libpam-pwquality may not be installed yet." "WARNING"
fi

# --- 2c: PAM files - INTENTIONALLY NOT MODIFIED -----------------------------
# /etc/pam.d/common-auth, common-account, and common-password are NOT touched.
# During testing, blind sed surgery on these files broke ALL authentication
# system-wide including greyteam, all packet users, and the operator account.
# The correct approach requires pam-auth-update(8) with a tested profile.
# pwquality.conf + login.defs provide sufficient hardening for competition.
log "PAM common-auth/account/password: intentionally NOT modified." "INFO"
log "  Reason: Previous edits broke system-wide auth for ALL users." "WARNING"
log "  Safe hardening in use: pwquality.conf + login.defs." "INFO"

# --- 2d: Password aging on competition accounts (safe - chage utility) -------
log "Applying password aging to existing competition users..." "INFO"
for cuser in "${COMP_USERS[@]}"; do
    if id "$cuser" &>/dev/null; then
        chage -M 90 -m 1 -W 7 "$cuser" 2>/dev/null && \
            log "  Password aging applied: $cuser (max 90d, warn 7d)" "SUCCESS" || \
            log "  Could not set aging for: $cuser" "WARNING"
    fi
done
add_change "PasswordPolicy" "chage aging on comp users" "SUCCESS" "90d max, 1d min, 7d warn"
log "Password aging applied." "SUCCESS"

log "Phase 2 complete." "SUCCESS"
fi  # end Phase 2

# ==============================================================================
# PHASE 3 - FIREWALL HARDENING (UFW) - SERVICE SELECTOR
# ==============================================================================
if $RUN_PHASE3; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 3: FIREWALL HARDENING (UFW) - SERVICE SELECTOR" "CRITICAL"
log "============================================================" "INFO"
log "Rule 7:  DO NOT block entire subnets!" "WARNING"
log "Rule 10: NEVER block SSH (port 22)!" "WARNING"

# Install UFW if missing
if ! command -v ufw &>/dev/null; then
    log "Installing UFW..." "INFO"
    DEBIAN_FRONTEND=noninteractive apt-get install -y ufw 2>/dev/null || true
fi

# Backup current iptables state
iptables-save  > "$LOG_DIR/iptables_backup_$(date +%s).rules"  2>/dev/null || true
ip6tables-save > "$LOG_DIR/ip6tables_backup_$(date +%s).rules" 2>/dev/null || true
log "iptables rules backed up to $LOG_DIR" "INFO"

# --- 3a: Interactive service port selector -----------------------------------
# Mirror SecureWin's service-specific port selection logic
# Each Linux host runs ONE scored service - only open those ports + SSH always
echo ""
echo -e "${C_CYAN}============================================================${C_RESET}"
echo -e "${C_CYAN}  PHASE 3 - STEP 3.1: SERVICE PORT SELECTOR${C_RESET}"
echo -e "${C_CYAN}============================================================${C_RESET}"
echo ""
echo -e "${C_YELLOW}Which service runs on THIS host? (SSH port 22 is ALWAYS opened)${C_RESET}"
echo ""
echo -e "  ${C_CYAN}[1]${C_RESET} ${C_WHITE}ponyville${C_RESET}       - Apache2/HTTP     (ports: 80, 443)"
echo -e "  ${C_CYAN}[2]${C_RESET} ${C_WHITE}seaddle${C_RESET}         - MariaDB          (ports: 3306)"
echo -e "  ${C_CYAN}[3]${C_RESET} ${C_WHITE}trotsylvania${C_RESET}    - CUPS Printing    (ports: 631 tcp+udp)"
echo -e "  ${C_CYAN}[4]${C_RESET} ${C_WHITE}crystal-empire${C_RESET}  - vsftpd/FTP       (ports: 20, 21)"
echo -e "  ${C_CYAN}[5]${C_RESET} ${C_WHITE}everfree-forest${C_RESET} - IRC              (ports: 6667, 6697)"
echo -e "  ${C_CYAN}[6]${C_RESET} ${C_WHITE}griffonstone${C_RESET}    - Nginx/HTTP       (ports: 80, 443)"
echo -e "  ${C_CYAN}[7]${C_RESET} ${C_WHITE}Ubuntu Workstation${C_RESET} - No service port  (SSH only)"
echo ""
echo -e "${C_YELLOW}Also always opened: 443 (scoring portal), 444 (scoring netcat)${C_RESET}"
echo ""

read -rp "$(echo -e "${C_CYAN}Enter the number for this host's service [1-7]: ${C_RESET}")" svc_choice

# Define service port arrays
declare -a SERVICE_PORTS
SERVICE_NAME=""

case "$svc_choice" in
    1)
        SERVICE_NAME="Apache2 (ponyville)"
        SERVICE_PORTS=(80 443)
        ;;
    2)
        SERVICE_NAME="MariaDB (seaddle)"
        SERVICE_PORTS=(3306)
        ;;
    3)
        SERVICE_NAME="CUPS (trotsylvania)"
        SERVICE_PORTS=(631)
        ;;
    4)
        SERVICE_NAME="vsftpd/FTP (crystal-empire)"
        SERVICE_PORTS=(20 21)
        ;;
    5)
        SERVICE_NAME="IRC (everfree-forest)"
        SERVICE_PORTS=(6667 6697)
        ;;
    6)
        SERVICE_NAME="Nginx (griffonstone)"
        SERVICE_PORTS=(80 443)
        ;;
    7)
        SERVICE_NAME="Ubuntu Workstation"
        SERVICE_PORTS=()
        ;;
    *)
        log "Invalid service selection '$svc_choice' - defaulting to Workstation (SSH only)." "WARNING"
        SERVICE_NAME="Unknown/Workstation (fallback)"
        SERVICE_PORTS=()
        ;;
esac

log "Service selected: $SERVICE_NAME" "INFO"
log "Service-specific ports to open: ${SERVICE_PORTS[*]:-none}" "INFO"
add_change "Firewall" "Service selected" "INFO" "$SERVICE_NAME"

# --- 3b: Configure UFW -------------------------------------------------------
log "Resetting UFW for clean configuration..." "INFO"
ufw --force reset 2>/dev/null || true

ufw default deny incoming
ufw default allow outgoing
ufw default deny forward
log "Default policies: deny incoming, allow outgoing, deny forward" "INFO"

# --- SSH FIRST (CRITICAL - Rule 10) -----------------------------------------
log "Opening SSH (port 22) - REQUIRED by Rule 10..." "INFO"
ufw allow 22/tcp comment 'SSH - Rule 10 required'
ufw limit ssh    # Rate limiting to slow brute force
add_change "Firewall" "SSH allowed + rate-limited (Rule 10)" "SUCCESS" "port 22/tcp"

# --- Always-open ports (scoring engine access) -------------------------------
log "Opening scoring portal ports (always required)..." "INFO"
ufw allow 443/tcp comment 'HTTPS - Scoring portal'
ufw allow 444/tcp comment 'Scoring engine netcat'
add_change "Firewall" "Scoring engine ports opened" "SUCCESS" "443, 444"

# --- Service-specific ports --------------------------------------------------
if [[ ${#SERVICE_PORTS[@]} -gt 0 ]]; then
    log "Opening service-specific ports for: $SERVICE_NAME" "INFO"
    for port in "${SERVICE_PORTS[@]}"; do
        ufw allow "${port}/tcp" comment "$SERVICE_NAME"
        # CUPS also needs UDP
        if [[ "$svc_choice" == "3" && "$port" == "631" ]]; then
            ufw allow "${port}/udp" comment "CUPS UDP"
        fi
        log "  Opened port $port/tcp for $SERVICE_NAME" "SUCCESS"
    done
    add_change "Firewall" "Service ports opened" "SUCCESS" "${SERVICE_PORTS[*]}"
else
    log "No service-specific ports to open for: $SERVICE_NAME" "INFO"
fi

# --- Whitelist individual competition infrastructure IPs --------------------
log "Whitelisting individual competition infrastructure IPs..." "INFO"
for ip in "${SAFE_IP_ADDRESSES[@]}"; do
    # Skip loopback (UFW handles that natively)
    [[ "$ip" == "127.0.0.1" || "$ip" == "::1" ]] && continue
    ufw allow from "$ip" to any comment "Competition infrastructure" 2>/dev/null || \
        log "  Could not add UFW rule for $ip" "WARNING"
done
add_change "Firewall" "Safe IPs whitelisted" "SUCCESS" "${#SAFE_IP_ADDRESSES[@]} IPs"

# --- Whitelist entire management subnet for Grey Team -----------------------
# Grey Team may access from ANY IP in 172.20.0.0/24, not just the listed jumpboxes.
# Rule 7 forbids BLOCKING subnets - whitelisting/ALLOWING a range is explicitly fine.
log "Whitelisting management subnet $MGMT_SUBNET for Grey Team access..." "INFO"
ufw allow from "$MGMT_SUBNET" to any comment "Grey Team mgmt subnet - ALLOW per Rule 7"
add_change "Firewall" "Grey Team mgmt subnet allowed" "SUCCESS" "$MGMT_SUBNET"
log "  Grey Team can access from any IP in $MGMT_SUBNET" "SUCCESS"

# --- Block high-risk attack ports -------------------------------------------
log "Blocking known attack/unnecessary ports..." "INFO"
ufw deny  23/tcp  comment 'Block Telnet'
ufw deny  512/tcp comment 'Block rexec'
ufw deny  513/tcp comment 'Block rlogin'
ufw deny  514/tcp comment 'Block rsh'
ufw deny  69/udp  comment 'Block TFTP'
ufw deny  111/tcp comment 'Block RPC portmapper'
ufw deny  111/udp comment 'Block RPC portmapper'
ufw deny  2049/tcp comment 'Block NFS'
ufw deny  2049/udp comment 'Block NFS'
add_change "Firewall" "Attack ports blocked" "SUCCESS" "Telnet,rsh,TFTP,RPC,NFS"

# --- Enable UFW -------------------------------------------------------------
log "Enabling UFW firewall..." "INFO"
ufw --force enable
add_change "Firewall" "UFW enabled" "SUCCESS" ""
log "UFW status:" "INFO"
ufw status verbose 2>/dev/null | while IFS= read -r line; do log "  $line" "INFO"; done

log "Phase 3 complete." "SUCCESS"
fi  # end Phase 3

# ==============================================================================
# PHASE 4 - SSH HARDENING (NEVER DISABLE - RULE 10!)
# ==============================================================================
if $RUN_PHASE4; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 4: SSH HARDENING" "CRITICAL"
log "============================================================" "INFO"
log "Rule 10: NEVER disable SSH on Linux - HARDEN IT ONLY!" "WARNING"

SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ ! -f "$SSHD_CONFIG" ]]; then
    log "sshd_config not found - is OpenSSH installed?" "ERROR"
else
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"
    log "sshd_config backed up." "INFO"

    # Helper: safely replace or append an SSH option
    set_ssh_opt() {
        local key="$1" val="$2"
        # Remove any existing lines (commented or uncommented)
        sed -i "/^#*[[:space:]]*${key}[[:space:]]/d" "$SSHD_CONFIG"
        echo "${key} ${val}" >> "$SSHD_CONFIG"
    }

    log "Applying SSH hardening settings..." "INFO"

    # Protocol and core settings
    set_ssh_opt "Protocol"                   "2"
    set_ssh_opt "PermitRootLogin"            "no"
    set_ssh_opt "PermitEmptyPasswords"       "no"
    set_ssh_opt "MaxAuthTries"               "3"
    set_ssh_opt "MaxSessions"                "4"
    set_ssh_opt "LoginGraceTime"             "30"
    set_ssh_opt "UsePAM"                     "yes"
    set_ssh_opt "PubkeyAuthentication"       "yes"

    # Disable dangerous / unneeded features
    set_ssh_opt "X11Forwarding"              "no"
    set_ssh_opt "AllowAgentForwarding"       "no"
    set_ssh_opt "AllowTcpForwarding"         "no"
    set_ssh_opt "PermitTunnel"               "no"
    set_ssh_opt "GatewayPorts"               "no"
    set_ssh_opt "HostbasedAuthentication"    "no"
    set_ssh_opt "IgnoreRhosts"               "yes"
    # RhostsRSAAuthentication intentionally omitted - deprecated in OpenSSH 7.4+,
    # removed in 8.x. Debian 13 ships OpenSSH 9.x and this option causes errors.

    # Timeout and keepalive (detect dead connections)
    set_ssh_opt "ClientAliveInterval"        "300"
    set_ssh_opt "ClientAliveCountMax"        "2"
    set_ssh_opt "TCPKeepAlive"               "no"

    # Logging
    set_ssh_opt "LogLevel"                   "VERBOSE"
    set_ssh_opt "SyslogFacility"             "AUTH"
    set_ssh_opt "PrintLastLog"               "yes"

    # Strict modes and fingerprinting
    set_ssh_opt "StrictModes"                "yes"
    set_ssh_opt "IgnoreUserKnownHosts"       "yes"

    # Warning banner
    set_ssh_opt "Banner"                     "/etc/ssh/banner"
    cat > /etc/ssh/banner << 'SSHDBAN'
*******************************************************************************
     AUTHORIZED USERS ONLY!!!
     All unauthorized access attempts are monitored and logged.
     Blue Team is watching you...
     
  ⠀⠀⠀⠀           ⠀⠀    ⠀ ⠀⢐⢠⣤⣄⡀⣧⣟⣿⣥⣼⣷⣾⣶⣶⣴⣶⣦⣬⣁⠀
 ⠀⠀⠀⠀    ⠀⠀⠀⠀ ⠀ ⠀   ⣤⣠⣅⣶⣾⣿⣷⣿⣿⣿⡿⡿⠿⡿⠿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣷⣾⣽⣲⡡⡀⠀
  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⡀⣀⣴⣾⣿⣿⣿⣿⣿⣿⣿⢿⠉⣡⣾⣶⣾⣿⣷⣿⣿⣮⣦⢫⡟⢿⣿⣿⣿⣿⣿⣿⣷⣧⣤⣦⢤⣀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⣠⣶⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠎⢰⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⡦⡷⣎⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣏⣷⡄⣀⠀⡄⠀⠀⠀⠀⠀⠀
     ⠀⣠⢦⢄⣤⣽⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠆⣼⣿⣼⣉⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣺⠾⣵⢦⣀⠀⠀
⢺⠽⡇⣾⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⢬⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢳⡿⣛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢟⣿⣿⣜⣆⠀
    ⠀ ⠉⠉⠉⠙⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣹⡆⠚⢿⣿⣿⣿⢿⣿⣿⠻⠀⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣹⣏⠟⠉⠉
  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠻⡿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣭⣢⡏⠀⠀⠈⢠⣛⣰⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⡺⠁⠀⠉⠀
  ⠀⠀⠀⠀   ⠀⠀⠀  ⠀⠀⠀⠀  ⠀⠙⠛⠿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⡟⠀⠙⠀
  ⠀⠀⠀⠀⠀      ⠀⠀⠀⠀   ⠀⠀⠀  ⠀⠈⠀⠃⢋⠛⠙⢿⠿⢻⡿⠿⡿⠿⠿⢿⣟⠋⠏⠀⠀⠉

*******************************************************************************
SSHDBAN
    chmod 644 /etc/ssh/banner 2>/dev/null || true

    # Build AllowUsers: packet users + blue team admins + greyteam (REQUIRED) + operator
    # CRITICAL: greyteam MUST be in AllowUsers - it's not in the packet but it IS a
    # real system user. AllowUsers is a strict whitelist: anyone not listed is locked
    # out of SSH entirely. The operator is also always included (self-lockout protection).
    ALL_SSH_USERS=$(printf '%s\n' \
        "${COMP_USERS[@]}" \
        "${AUTHORIZED_ADMINS[@]}" \
        "greyteam" \
        "grayteam" \
        "grey_team" \
        "gray_team" \
        "scoring" \
        "$CURRENT_OPERATOR" \
        | sort -u | tr '\n' ' ' | sed 's/ $//')
    set_ssh_opt "AllowUsers" "$ALL_SSH_USERS"
    log "AllowUsers set to: $ALL_SSH_USERS" "INFO"
    log "  NOTE: greyteam explicitly included (not in packet but required for infra access)." "INFO"
    log "  NOTE: $CURRENT_OPERATOR explicitly included (self-lockout protection)." "INFO"

    # Secure the sshd_config itself
    chmod 600 "$SSHD_CONFIG"

    # Validate and restart
    log "Validating SSH configuration with sshd -t..." "INFO"
    if sshd -t 2>&1 | tee -a "$LOG_FILE"; then
        systemctl restart sshd 2>/dev/null || \
        systemctl restart ssh  2>/dev/null || \
        service ssh restart    2>/dev/null || true
        add_change "SSH" "sshd hardened and restarted" "SUCCESS" \
            "PermitRootLogin=no X11=no AgentFwd=no TcpFwd=no AllowUsers set"
        log "SSH hardened and service restarted successfully." "SUCCESS"
    else
        log "SSH config validation FAILED - restoring backup!" "ERROR"
        LATEST_BAK=$(ls -t "${SSHD_CONFIG}.bak."* 2>/dev/null | head -1)
        [[ -n "$LATEST_BAK" ]] && cp "$LATEST_BAK" "$SSHD_CONFIG"
        systemctl restart sshd 2>/dev/null || \
        systemctl restart ssh  2>/dev/null || true
        add_security_issue "SSH config validation failed - backup restored!"
    fi
fi

log "Phase 4 complete." "SUCCESS"
fi  # end Phase 4

# ==============================================================================
# PHASE 5 - NETWORK SECURITY
# ==============================================================================
if $RUN_PHASE5; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 5: NETWORK SECURITY" "CRITICAL"
log "============================================================" "INFO"

# --- 5a: Kernel hardening via sysctl -----------------------------------------
log "Applying kernel network hardening (sysctl)..." "INFO"
SYSCTL_FILE="/etc/sysctl.d/99-blueteam-hardening.conf"
cat > "$SYSCTL_FILE" << 'SYSCTL'
# =============================================================================
# SecureNix - CDT Team Charlie - Kernel Hardening
# =============================================================================

# --- Reverse path filtering (anti-spoofing) ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- Disable IP source routing ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# --- Disable ICMP redirect acceptance (prevents MITM) ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- SYN flood protection ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# --- Disable IP forwarding (not a router) ---
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# --- Log martian packets (suspicious source IPs) ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- Smurf attack protection ---
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Disable TCP timestamps (info leakage) ---
net.ipv4.tcp_timestamps = 0

# --- TCP RFC 1337 fix ---
net.ipv4.tcp_rfc1337 = 1

# --- ASLR (Address Space Layout Randomization) ---
kernel.randomize_va_space = 2

# --- Kernel pointer restriction ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1

# --- Disable core dumps ---
fs.suid_dumpable = 0
kernel.core_pattern = /dev/null

# --- Performance events paranoia ---
kernel.perf_event_paranoid = 3

# --- Hardlink/symlink protection ---
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
SYSCTL

sysctl -p "$SYSCTL_FILE" 2>&1 | while IFS= read -r l; do log "  sysctl: $l" "INFO"; done || true
add_change "Network" "Kernel sysctl hardening applied" "SUCCESS" \
    "ASLR,SYN-cookies,RP-filter,ICMP-hardening,anti-spoof"
log "sysctl hardening applied." "SUCCESS"

# --- 5b: Disable vulnerable/unnecessary services -----------------------------
log "Disabling unnecessary/vulnerable services..." "INFO"
DISABLE_SERVICES=(
    "telnet" "rsh" "rlogin" "rexec" "tftp" "xinetd"
    "finger" "talk" "ntalk" "avahi-daemon" "rpcbind"
)
for svc in "${DISABLE_SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc" 2>/dev/null && \
        systemctl disable "$svc" 2>/dev/null && \
            log "Stopped and disabled: $svc" "SUCCESS" || \
            log "Could not stop: $svc" "WARNING"
        add_change "Network" "Disable service" "SUCCESS" "$svc"
    elif systemctl list-unit-files --quiet "${svc}.service" 2>/dev/null | grep -q "$svc"; then
        systemctl disable "$svc" 2>/dev/null || true
        log "Disabled (was inactive): $svc" "INFO"
    fi
done

# --- 5c: Remove insecure packages --------------------------------------------
log "Removing insecure network packages..." "INFO"
REMOVE_PKGS=(
    "telnet" "telnetd" "rsh-client" "rsh-server"
    "rlogin" "tftp" "tftpd" "nis" "talk" "talkd"
    "finger" "xinetd" "rpcbind"
)
for pkg in "${REMOVE_PKGS[@]}"; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        DEBIAN_FRONTEND=noninteractive apt-get remove -y "$pkg" 2>/dev/null && \
            log "Removed package: $pkg" "SUCCESS" || \
            log "Could not remove: $pkg" "WARNING"
        add_change "Network" "Remove insecure package" "SUCCESS" "$pkg"
    fi
done

# --- 5d: TCP Wrappers (hosts.deny / hosts.allow) -----------------------------
log "Configuring TCP Wrappers..." "INFO"
log "  Grey Team mgmt subnet $MGMT_SUBNET will be whitelisted in addition to individual IPs." "INFO"
cp /etc/hosts.deny  "/etc/hosts.deny.bak.$(date +%s)"   2>/dev/null || true
cp /etc/hosts.allow "/etc/hosts.allow.bak.$(date +%s)"  2>/dev/null || true

cat > /etc/hosts.deny << 'DENY'
# SecureNix CDT Team Charlie - Deny all by default
# Rule 7: This denies unknown hosts. ALLOWing ranges in hosts.allow is not a subnet block.
ALL: ALL
DENY

{
    echo "# SecureNix CDT Team Charlie - Whitelist: mgmt subnet + individual competition IPs"
    echo ""
    echo "# Loopback"
    echo "ALL: 127.0.0.1"
    echo "ALL: ::1"
    echo ""
    echo "# Full management subnet (172.20.0.0/24) - Grey Team may jump from any IP here."
    echo "# Rule 7 forbids BLOCKING subnets - this ALLOW rule is explicitly permitted."
    echo "ALL: 172.20.0.0/255.255.255.0"
    echo ""
    echo "# Individual competition infrastructure IPs"
    for ip in "${SAFE_IP_ADDRESSES[@]}"; do
        [[ "$ip" == "127.0.0.1" || "$ip" == "::1" ]] && continue
        echo "ALL: $ip"
    done
} > /etc/hosts.allow

add_change "Network" "TCP Wrappers configured" "SUCCESS" "deny all; allow $MGMT_SUBNET + individual IPs"
log "TCP Wrappers configured. Management subnet $MGMT_SUBNET whitelisted for Grey Team." "SUCCESS"

# --- 5e: Disable USB mass storage --------------------------------------------
log "Blacklisting USB mass storage..." "INFO"
echo "install usb-storage /bin/true" >  /etc/modprobe.d/blueteam-disable-usb.conf
echo "blacklist usb-storage"         >> /etc/modprobe.d/blueteam-disable-usb.conf
add_change "Network" "USB mass storage blacklisted" "SUCCESS" ""
log "USB storage blacklisted." "INFO"

log "Phase 5 complete." "SUCCESS"
fi  # end Phase 5

# ==============================================================================
# PHASE 6 - BACKDOOR DETECTION
# ==============================================================================
if $RUN_PHASE6; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 6: BACKDOOR DETECTION" "CRITICAL"
log "============================================================" "INFO"

BD_REPORT="$LOG_DIR/backdoor_report_$(date +%Y%m%d_%H%M%S).txt"
log "Writing backdoor report to: $BD_REPORT" "INFO"

{
echo "======================================================================"
echo "  SecureNix - Backdoor Detection Report"
echo "  Host: $HOSTNAME_VAL  |  Date: $(date)"
echo "======================================================================"
} > "$BD_REPORT"

# --- 6a: Listening ports (unexpected = potential backdoor) ------------------
log "Scanning for unexpected listening ports..." "INFO"
{
echo ""
echo "=== LISTENING PORTS ==="
ss -tlnup 2>/dev/null || netstat -tlnup 2>/dev/null || echo "ss/netstat unavailable"
echo ""
} >> "$BD_REPORT"

if command -v ss &>/dev/null; then
    ss -tlnup 2>/dev/null | awk 'NR>1 {print $5}' | grep -oP ':\K[0-9]+' | sort -un | \
    while read -r port; do
        is_safe_port=false
        for sp in "${SAFE_PORTS[@]}"; do [[ "$port" == "$sp" ]] && is_safe_port=true && break; done
        if ! $is_safe_port; then
            log "SUSPICIOUS LISTENING PORT: $port" "CRITICAL"
            add_security_issue "Unexpected listening port: $port"
        fi
    done
fi

# --- 6b: SUID/SGID binaries --------------------------------------------------
log "Scanning for SUID/SGID binaries..." "INFO"
{
echo "=== SUID BINARIES ==="
find / -xdev -perm -4000 -type f 2>/dev/null | sort
echo ""
echo "=== SGID BINARIES ==="
find / -xdev -perm -2000 -type f 2>/dev/null | sort
echo ""
} >> "$BD_REPORT"

KNOWN_SUID=(
    "/bin/su" "/usr/bin/su" "/bin/sudo" "/usr/bin/sudo"
    "/bin/passwd" "/usr/bin/passwd" "/bin/mount" "/usr/bin/mount"
    "/bin/umount" "/usr/bin/umount" "/usr/bin/newgrp" "/usr/bin/chfn"
    "/usr/bin/chsh" "/usr/bin/gpasswd" "/usr/bin/pkexec"
    "/usr/lib/openssh/ssh-keysign" "/bin/ping" "/usr/bin/ping"
    "/usr/bin/at" "/usr/sbin/pppd"
)
find / -xdev -perm -4000 -type f 2>/dev/null | while read -r sf; do
    [[ "$sf" == *greyteam* ]] && continue  # Rule 5
    is_known=false
    for ks in "${KNOWN_SUID[@]}"; do [[ "$sf" == "$ks" ]] && is_known=true && break; done
    if ! $is_known; then
        log "UNUSUAL SUID FILE: $sf" "CRITICAL"
        add_security_issue "Unusual SUID file: $sf"
    fi
done

# --- 6c: Scheduled tasks (cron + systemd timers) ----------------------------
log "Auditing scheduled tasks..." "INFO"
{
echo "=== CRONTAB (/etc/crontab) ==="
cat /etc/crontab 2>/dev/null || echo "(not found)"
echo ""
echo "=== /etc/cron.d/ ==="
for cf in /etc/cron.d/*; do
    [[ -f "$cf" ]] || continue
    [[ "$cf" == *greyteam* ]] && continue  # Rule 5
    echo "--- $cf ---" && cat "$cf"
done
echo ""
echo "=== USER CRONTABS ==="
ls /var/spool/cron/crontabs/ 2>/dev/null || echo "(empty)"
for uc in /var/spool/cron/crontabs/*; do
    [[ -f "$uc" ]] && echo "--- $(basename "$uc") ---" && cat "$uc"
done
echo ""
echo "=== SYSTEMD TIMERS ==="
systemctl list-timers --all 2>/dev/null | head -30
echo ""
} >> "$BD_REPORT"

for uc in /var/spool/cron/crontabs/*; do
    [[ -f "$uc" ]] || continue
    cron_user=$(basename "$uc")
    if ! is_safe_user "$cron_user"; then
        log "SUSPICIOUS CRONTAB for unauthorized user: $cron_user" "CRITICAL"
        add_security_issue "Crontab for unauthorized user: $cron_user"
    else
        log "Crontab found for: $cron_user (packet user - review contents)" "WARNING"
    fi
done

# --- 6d: Running services and startup scripts --------------------------------
log "Checking running services and startup scripts..." "INFO"
{
echo "=== /etc/rc.local ==="
cat /etc/rc.local 2>/dev/null || echo "(not found)"
echo ""
echo "=== RUNNING SERVICES ==="
systemctl list-units --type=service --state=running 2>/dev/null | head -50
echo ""
} >> "$BD_REPORT"

# --- 6e: World-writable files in sensitive paths -----------------------------
log "Scanning for world-writable files in sensitive paths..." "INFO"
{
echo "=== WORLD-WRITABLE FILES (sensitive dirs) ==="
find /etc /usr/bin /usr/sbin /bin /sbin -xdev -perm -002 -type f 2>/dev/null | sort
echo ""
} >> "$BD_REPORT"

find /etc /usr/bin /usr/sbin /bin /sbin -xdev -perm -002 -type f 2>/dev/null | while read -r wwf; do
    [[ "$wwf" == *greyteam* ]] && continue  # Rule 5
    log "WORLD-WRITABLE IN SENSITIVE PATH: $wwf" "CRITICAL"
    add_security_issue "World-writable sensitive file: $wwf"
    chmod o-w "$wwf" 2>/dev/null && log "  Fixed permissions: $wwf" "SUCCESS" || true
done

# --- 6f: /etc/passwd and /etc/shadow anomalies ------------------------------
log "Auditing /etc/passwd and /etc/shadow..." "INFO"
{
echo "=== ACCOUNTS WITH VALID SHELLS ==="
grep -v '/nologin\|/false' /etc/passwd 2>/dev/null
echo ""
echo "=== ACCOUNTS WITH EMPTY/LOCKED PASSWORDS ==="
awk -F: '($2 == "" || $2 == "!!")' /etc/shadow 2>/dev/null || echo "(could not read shadow)"
echo ""
} >> "$BD_REPORT"

# Lock any empty-password accounts
awk -F: '($2 == "")' /etc/shadow 2>/dev/null | cut -d: -f1 | while read -r emp_user; do
    log "EMPTY PASSWORD - locking: $emp_user" "CRITICAL"
    add_security_issue "Empty password for user: $emp_user"
    passwd -l "$emp_user" 2>/dev/null || true
done

# --- 6g: Process and network snapshot ----------------------------------------
log "Capturing process and network snapshot..." "INFO"
{
echo "=== RUNNING PROCESSES ==="
ps auxf 2>/dev/null || ps aux 2>/dev/null
echo ""
echo "=== ALL NETWORK CONNECTIONS ==="
ss -anp 2>/dev/null || netstat -anp 2>/dev/null || echo "(unavailable)"
echo ""
} >> "$BD_REPORT"

# --- 6h: Executables in /tmp and /dev/shm -----------------------------------
log "Scanning /tmp and /dev/shm for executables..." "INFO"
{
echo "=== EXECUTABLES IN /tmp ==="
find /tmp -type f -perm /111 2>/dev/null | sort
echo ""
echo "=== HIDDEN FILES IN /tmp ==="
find /tmp -name ".*" -type f 2>/dev/null | sort
echo ""
echo "=== EXECUTABLES IN /dev/shm ==="
find /dev/shm -type f -perm /111 2>/dev/null | sort
echo ""
} >> "$BD_REPORT"

find /tmp /dev/shm -type f -perm /111 2>/dev/null | while read -r tmpexec; do
    log "EXECUTABLE IN TEMP DIR: $tmpexec" "CRITICAL"
    add_security_issue "Executable in temp dir: $tmpexec"
done

# --- 6i: /etc/hosts DNS poisoning check -------------------------------------
log "Checking /etc/hosts for DNS poisoning..." "INFO"
{
echo "=== /etc/hosts ==="
cat /etc/hosts 2>/dev/null
echo ""
} >> "$BD_REPORT"

while IFS= read -r hosts_line; do
    [[ "$hosts_line" =~ ^# || -z "$hosts_line" ]] && continue
    if echo "$hosts_line" | grep -qiE 'scoring|mlp\.local'; then
        if ! echo "$hosts_line" | grep -q "172.20.0.100"; then
            log "POSSIBLE /etc/hosts POISONING: $hosts_line" "CRITICAL"
            add_security_issue "/etc/hosts may be poisoning scoring domain: $hosts_line"
        fi
    fi
done < /etc/hosts 2>/dev/null || true

# --- 6j: Shell init file inspection -----------------------------------------
log "Auditing shell init files..." "INFO"
{
echo "=== /etc/profile ==="
cat /etc/profile 2>/dev/null
echo ""
echo "=== /etc/bash.bashrc ==="
cat /etc/bash.bashrc 2>/dev/null
echo ""
echo "=== USER .bashrc / .profile / .bash_logout ==="
for h in /home/*/; do
    for sf in .bashrc .bash_profile .profile .bash_logout; do
        [[ -f "$h$sf" ]] && echo "--- $h$sf ---" && cat "$h$sf"
    done
done
echo ""
} >> "$BD_REPORT"

# --- 6k: Loaded kernel modules -----------------------------------------------
log "Checking loaded kernel modules..." "INFO"
{
echo "=== LOADED KERNEL MODULES ==="
lsmod 2>/dev/null | head -60
echo ""
} >> "$BD_REPORT"

# --- 6l: Check for /greyteam_key status -------------------------------------
{
echo "=== GREYTEAM_KEY STATUS (Rule 15) ==="
if [[ -f "/greyteam_key" ]]; then
    echo "PRESENT - Red Team tools authorized on this host"
    ls -la /greyteam_key
else
    echo "NOT PRESENT - Red Team tools should not run here"
fi
echo ""
} >> "$BD_REPORT"

log "Backdoor scan complete. Report saved: $BD_REPORT" "SUCCESS"
log "Security issues found so far: ${#SECURITY_ISSUES[@]}" "WARNING"
add_change "Backdoor" "Detection scan complete" "SUCCESS" "Report: $BD_REPORT"

log "Phase 6 complete." "SUCCESS"
fi  # end Phase 6

# ==============================================================================
# PHASE 7 - SYSTEM HARDENING
# ==============================================================================
if $RUN_PHASE7; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 7: SYSTEM HARDENING" "CRITICAL"
log "============================================================" "INFO"

# --- 7a: Sensitive file permissions ------------------------------------------
log "Hardening sensitive file permissions..." "INFO"
declare -A FILE_PERMS=(
    ["/etc/passwd"]="644"         ["/etc/group"]="644"
    ["/etc/shadow"]="640"         ["/etc/gshadow"]="640"
    ["/etc/sudoers"]="440"        ["/etc/ssh/sshd_config"]="600"
    ["/etc/crontab"]="600"        ["/etc/hosts"]="644"
    ["/etc/hosts.deny"]="644"     ["/etc/hosts.allow"]="644"
    ["/boot/grub/grub.cfg"]="600"
)
for fpath in "${!FILE_PERMS[@]}"; do
    [[ -f "$fpath" ]] || continue
    chmod "${FILE_PERMS[$fpath]}" "$fpath" 2>/dev/null && \
        log "  Permissions set: $fpath -> ${FILE_PERMS[$fpath]}" "SUCCESS" || \
        log "  Could not chmod: $fpath" "WARNING"
done
chown root:shadow /etc/shadow  2>/dev/null || true
chown root:shadow /etc/gshadow 2>/dev/null || true
add_change "SystemHardening" "Sensitive file permissions hardened" "SUCCESS" \
    "shadow=640 sudoers=440 sshd_config=600"

# --- 7b: Harden /tmp (noexec) ------------------------------------------------
log "Hardening /tmp mount options..." "INFO"
if ! grep -qE 'tmpfs[[:space:]]*/tmp' /etc/fstab 2>/dev/null; then
    echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=512M 0 0" >> /etc/fstab
fi
mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null && \
    log "/tmp remounted: noexec,nosuid,nodev" "SUCCESS" || \
    log "/tmp remount failed (will apply after reboot)" "WARNING"
add_change "SystemHardening" "/tmp hardened" "SUCCESS" "noexec,nosuid,nodev"

# --- 7c: Secure /dev/shm -----------------------------------------------------
log "Hardening /dev/shm..." "INFO"
if ! grep -qE 'tmpfs[[:space:]]*/dev/shm' /etc/fstab 2>/dev/null; then
    echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
fi
mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null && \
    log "/dev/shm remounted: noexec,nosuid,nodev" "SUCCESS" || \
    log "/dev/shm remount failed (will apply after reboot)" "WARNING"
add_change "SystemHardening" "/dev/shm hardened" "SUCCESS" "noexec,nosuid,nodev"

# --- 7d: Disable core dumps --------------------------------------------------
log "Disabling core dumps..." "INFO"
{
echo "# SecureNix - Disable core dumps"
echo "* hard core 0"
echo "* soft core 0"
} >> /etc/security/limits.conf
cat > /etc/profile.d/blueteam-hardening.sh << 'PROF'
# SecureNix hardening - disable core dumps at shell level
ulimit -c 0
PROF
chmod 644 /etc/profile.d/blueteam-hardening.sh
add_change "SystemHardening" "Core dumps disabled" "SUCCESS" ""

# --- 7e: AppArmor enforcement ------------------------------------------------
log "Checking and enforcing AppArmor..." "INFO"
if command -v aa-status &>/dev/null; then
    if aa-status 2>/dev/null | grep -q "profiles are loaded"; then
        aa-enforce /etc/apparmor.d/* 2>/dev/null && \
            log "All AppArmor profiles set to enforce mode." "SUCCESS" || \
            log "Some AppArmor profiles could not be enforced." "WARNING"
        add_change "SystemHardening" "AppArmor enforced" "SUCCESS" ""
    else
        log "AppArmor not active - attempting install/start..." "WARNING"
        DEBIAN_FRONTEND=noninteractive apt-get install -y apparmor apparmor-utils 2>/dev/null && \
            systemctl enable apparmor && systemctl start apparmor && \
            log "AppArmor installed and started." "SUCCESS" || \
            log "AppArmor install failed - manual intervention needed." "ERROR"
    fi
else
    log "AppArmor utilities not available - skipping." "WARNING"
fi

# --- 7f: Restrict compiler access -------------------------------------------
log "Restricting compiler execute permissions for others..." "INFO"
for comp in /usr/bin/gcc /usr/bin/g++ /usr/bin/cc /usr/bin/make /usr/bin/python3; do
    [[ -f "$comp" ]] && chmod o-x "$comp" 2>/dev/null && \
        log "  Restricted execute for others: $comp" "INFO" || true
done
add_change "SystemHardening" "Compiler access restricted for others" "SUCCESS" ""

# --- 7g: Restrict cron/at access to root ------------------------------------
log "Restricting cron/at access to root only..." "INFO"
echo "root" > /etc/cron.allow   2>/dev/null || true
echo "root" > /etc/at.allow     2>/dev/null || true
> /etc/cron.deny               2>/dev/null || true
> /etc/at.deny                 2>/dev/null || true
chmod 600 /etc/cron.allow /etc/at.allow 2>/dev/null || true
add_change "SystemHardening" "Cron/at restricted to root" "SUCCESS" ""

# --- 7h: Disable Ctrl+Alt+Del reboot ----------------------------------------
log "Disabling Ctrl+Alt+Del reboot..." "INFO"
systemctl mask ctrl-alt-del.target 2>/dev/null && \
    log "Ctrl+Alt+Del reboot disabled." "SUCCESS" || true
add_change "SystemHardening" "Ctrl+Alt+Del disabled" "SUCCESS" ""

# --- 7i: Remove offensive security tools ------------------------------------
log "Removing offensive security tools if present..." "INFO"
REMOVE_DANGEROUS=(
    "nmap" "masscan" "hydra" "john" "hashcat"
    "aircrack-ng" "wireshark" "metasploit-framework"
    "netcat-traditional" "netcat-openbsd"
)
for pkg in "${REMOVE_DANGEROUS[@]}"; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        DEBIAN_FRONTEND=noninteractive apt-get remove -y "$pkg" 2>/dev/null && \
            log "  Removed offensive tool: $pkg" "SUCCESS" || \
            log "  Could not remove: $pkg" "WARNING"
        add_change "SystemHardening" "Remove offensive tool" "SUCCESS" "$pkg"
    fi
done

# --- 7j: MOTD ----------------------------------------------------------------
log "Setting competition MOTD..." "INFO"
cat > /etc/motd << 'MOTD'
*******************************************************************************
              CDT TEAM Charlie - Blue Team
*******************************************************************************
  Authorized users only. All activity is monitored and logged.
  Friendship is Magic, but security is BETTER.
  Legion of Doom: you will not pass!
*******************************************************************************
MOTD
add_change "SystemHardening" "MOTD configured" "SUCCESS" ""

# --- 7k: Enable automatic security updates -----------------------------------
log "Enabling unattended security updates..." "INFO"
if command -v apt-get &>/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades 2>/dev/null || true
    add_change "SystemHardening" "Unattended security upgrades enabled" "SUCCESS" ""
fi

log "Phase 7 complete." "SUCCESS"
fi  # end Phase 7

# ==============================================================================
# PHASE 8 - AUDIT LOGGING (auditd)
# ==============================================================================
if $RUN_PHASE8; then
log "" "INFO"
log "============================================================" "INFO"
log "PHASE 8: AUDIT LOGGING (auditd)" "CRITICAL"
log "============================================================" "INFO"

# Install auditd
if ! command -v auditctl &>/dev/null; then
    log "Installing auditd and audisp plugins..." "INFO"
    DEBIAN_FRONTEND=noninteractive apt-get install -y auditd audispd-plugins 2>/dev/null && \
        log "auditd installed." "SUCCESS" || \
        log "auditd install failed - logging may be incomplete." "ERROR"
fi

AUDITD_CONF="/etc/audit/auditd.conf"
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES="$AUDIT_RULES_DIR/99-blueteam.rules"
mkdir -p "$AUDIT_RULES_DIR"

# --- 8a: Configure auditd.conf -----------------------------------------------
if [[ -f "$AUDITD_CONF" ]]; then
    cp "$AUDITD_CONF" "${AUDITD_CONF}.bak.$(date +%s)" 2>/dev/null || true
    sed -i 's/^max_log_file_action.*/max_log_file_action = rotate/'        "$AUDITD_CONF" || true
    sed -i 's/^num_logs.*/num_logs = 10/'                                  "$AUDITD_CONF" || true
    sed -i 's/^max_log_file\s.*/max_log_file = 50/'                       "$AUDITD_CONF" || true
    sed -i 's/^space_left_action.*/space_left_action = syslog/'            "$AUDITD_CONF" || true
    sed -i 's/^admin_space_left_action.*/admin_space_left_action = syslog/' "$AUDITD_CONF" || true
    add_change "Auditing" "auditd.conf configured" "SUCCESS" "rotate 10 logs of 50MB"
    log "auditd.conf configured." "SUCCESS"
fi

# --- 8b: Write comprehensive audit rules -------------------------------------
log "Writing audit rules to $AUDIT_RULES..." "INFO"
cat > "$AUDIT_RULES" << 'AUDITRULES'
# ==============================================================================
# SecureNix - CDT Team Charlie - Comprehensive Audit Rules
# ==============================================================================

# Delete all existing rules and set buffer size
-D
-b 8192
-f 1

# ==============================================================================
# AUTHENTICATION & SESSION
# ==============================================================================
-w /var/log/faillog  -p wa -k logins
-w /var/log/lastlog  -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /etc/pam.d/        -p wa -k pam_config

# ==============================================================================
# SUDO & PRIVILEGE ESCALATION
# ==============================================================================
-w /etc/sudoers   -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /bin/su        -p x  -k priv_escalation
-w /usr/bin/su    -p x  -k priv_escalation
-w /bin/sudo      -p x  -k priv_escalation
-w /usr/bin/sudo  -p x  -k priv_escalation
-w /usr/bin/newgrp -p x -k priv_escalation
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k setuid_setgid
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k setuid_setgid

# ==============================================================================
# USER & GROUP MANAGEMENT
# ==============================================================================
-w /etc/passwd   -p wa -k user_accounts
-w /etc/group    -p wa -k user_accounts
-w /etc/shadow   -p wa -k user_accounts
-w /etc/gshadow  -p wa -k user_accounts
-w /etc/security/opasswd -p wa -k user_accounts
-w /usr/sbin/useradd -p x -k user_mgmt
-w /usr/sbin/usermod -p x -k user_mgmt
-w /usr/sbin/userdel -p x -k user_mgmt
-w /usr/sbin/groupadd -p x -k user_mgmt
-w /usr/sbin/groupmod -p x -k user_mgmt
-w /usr/sbin/groupdel -p x -k user_mgmt
-w /usr/sbin/adduser  -p x -k user_mgmt
-w /usr/sbin/deluser  -p x -k user_mgmt
-w /usr/bin/passwd    -p x -k passwd_changes
-w /usr/bin/chage     -p x -k passwd_changes

# ==============================================================================
# SSH CONFIGURATION & KEYS
# ==============================================================================
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/          -p wa -k root_ssh
-w /home/               -p wa -k home_dirs

# ==============================================================================
# GREYTEAM KEY (Rule 15 - any access to this file is critical intel)
# ==============================================================================
-w /greyteam_key -p rwa -k greyteam_key

# ==============================================================================
# NETWORK CONFIGURATION
# ==============================================================================
-w /etc/hosts         -p wa -k hosts_file
-w /etc/resolv.conf   -p wa -k dns_config
-w /etc/network/      -p wa -k network_config
-w /etc/NetworkManager/ -p wa -k network_config
-w /etc/hosts.allow   -p wa -k tcp_wrappers
-w /etc/hosts.deny    -p wa -k tcp_wrappers

# ==============================================================================
# FIREWALL CHANGES
# ==============================================================================
-w /etc/ufw/        -p wa -k firewall
-w /etc/iptables/   -p wa -k firewall
-w /usr/sbin/ufw    -p x  -k firewall_cmd
-w /sbin/iptables   -p x  -k firewall_cmd
-w /sbin/ip6tables  -p x  -k firewall_cmd
-w /sbin/nft        -p x  -k firewall_cmd

# ==============================================================================
# SCHEDULED TASKS
# ==============================================================================
-w /etc/crontab       -p wa -k cron
-w /etc/cron.d/       -p wa -k cron
-w /etc/cron.daily/   -p wa -k cron
-w /etc/cron.weekly/  -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/   -p wa -k cron
-w /usr/bin/crontab   -p x  -k cron_cmd

# ==============================================================================
# SYSTEMD
# ==============================================================================
-w /etc/systemd/     -p wa -k systemd
-w /lib/systemd/     -p wa -k systemd
-w /usr/lib/systemd/ -p wa -k systemd

# ==============================================================================
# SYSTEM CONFIGURATION
# ==============================================================================
-w /etc/fstab       -p wa -k fstab
-w /etc/rc.local    -p wa -k init_scripts
-w /etc/init.d/     -p wa -k init_scripts
-w /boot/grub/      -p wa -k bootloader
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/   -p wa -k sysctl
-w /sbin/sysctl     -p x  -k sysctl_cmd

# ==============================================================================
# FILE PERMISSION & OWNERSHIP CHANGES
# ==============================================================================
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat  -k file_perm_change
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat  -k file_perm_change
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat  -k file_owner_change
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat  -k file_owner_change

# ==============================================================================
# MOUNT / UNMOUNT
# ==============================================================================
-a always,exit -F arch=b64 -S mount -S umount2 -k mounts
-a always,exit -F arch=b32 -S mount -S umount  -k mounts

# ==============================================================================
# KERNEL MODULE LOADING (rootkit detection)
# ==============================================================================
-w /sbin/insmod  -p x -k module_load
-w /sbin/rmmod   -p x -k module_unload
-w /sbin/modprobe -p x -k module_load
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k kernel_modules

# ==============================================================================
# SUSPICIOUS EXECUTION LOCATIONS
# ==============================================================================
-a always,exit -F arch=b64 -S execve -F dir=/tmp     -k exec_in_tmp
-a always,exit -F arch=b32 -S execve -F dir=/tmp     -k exec_in_tmp
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k exec_in_shm
-a always,exit -F arch=b32 -S execve -F dir=/dev/shm -k exec_in_shm

# ==============================================================================
# MAKE RULES IMMUTABLE (requires reboot to change - comment out if testing)
# ==============================================================================
# -e 2
AUDITRULES

# Load the rules
if command -v augenrules &>/dev/null; then
    augenrules --load 2>/dev/null && \
        log "Audit rules loaded via augenrules." "SUCCESS" || \
        log "augenrules load failed - rules will apply after reboot." "WARNING"
elif command -v auditctl &>/dev/null; then
    auditctl -R "$AUDIT_RULES" 2>/dev/null && \
        log "Audit rules loaded via auditctl." "SUCCESS" || \
        log "auditctl load failed." "WARNING"
fi

# Enable and start auditd
systemctl enable auditd 2>/dev/null && systemctl restart auditd 2>/dev/null && \
    log "auditd enabled and restarted." "SUCCESS" || \
    log "Could not start auditd." "WARNING"
add_change "Auditing" "auditd configured and started" "SUCCESS" "99-blueteam.rules loaded"

# --- 8c: Log rotation for blueteam logs -------------------------------------
log "Configuring log rotation for /var/log/blueteam/..." "INFO"
cat > /etc/logrotate.d/blueteam << 'LOGROTATE'
/var/log/blueteam/*.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    create 640 root root
}
LOGROTATE
add_change "Auditing" "Log rotation configured for /var/log/blueteam/" "SUCCESS" ""
log "Log rotation configured." "SUCCESS"

log "Phase 8 complete." "SUCCESS"
fi  # end Phase 8

# ==============================================================================
# FINAL REPORT & SUMMARY
# ==============================================================================
if ! $RUNNING_INDIVIDUAL_PHASE; then

SCRIPT_END_TIME=$(date +%s)
DURATION=$(( SCRIPT_END_TIME - SCRIPT_START_TIME ))

log "" "INFO"
log "============================================================" "INFO"
log "GENERATING FINAL REPORT" "CRITICAL"
log "============================================================" "INFO"
log "  Host:               $HOSTNAME_VAL" "INFO"
log "  Operator:           $CURRENT_OPERATOR" "INFO"
log "  Start time:         $(date -d @"$SCRIPT_START_TIME" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'N/A')" "INFO"
log "  End time:           $(date '+%Y-%m-%d %H:%M:%S')" "INFO"
log "  Duration:           ${DURATION}s" "INFO"
log "  Script run #:       $SCRIPT_RUN_COUNT" "INFO"
log "  Total changes:      $CHANGES_COUNT" "INFO"
log "  Accounts locked:    ${#REMOVED_USERS[@]}" "INFO"
log "  Security issues:    ${#SECURITY_ISSUES[@]}" "INFO"
log "  Passwords changed:  $PASSWORD_CHANGE_COUNT / $MAX_PASSWORD_CHANGES (Rule 14)" "INFO"

log "" "INFO"
log "CHANGES APPLIED:" "INFO"
for chg in "${CHANGES[@]}"; do log "  + $chg" "INFO"; done

if [[ ${#REMOVED_USERS[@]} -gt 0 ]]; then
    log "" "INFO"
    log "LOCKED ACCOUNTS:" "REMOVED"
    for ru in "${REMOVED_USERS[@]}"; do log "  - $ru" "REMOVED"; done
fi

if [[ ${#SECURITY_ISSUES[@]} -gt 0 ]]; then
    log "" "INFO"
    log "SECURITY ISSUES DETECTED (${#SECURITY_ISSUES[@]} total):" "CRITICAL"
    for si in "${SECURITY_ISSUES[@]}"; do log "  ! $si" "CRITICAL"; done
fi

log "" "INFO"
log "SAFE IPs WHITELISTED (${#SAFE_IP_ADDRESSES[@]} total):" "INFO"
for ip in "${SAFE_IP_ADDRESSES[@]}"; do log "  - $ip" "INFO"; done

log "" "INFO"
log "============================================================" "INFO"
log "BLUE TEAM RECOMMENDATIONS - CDT COMPETITION:" "CRITICAL"
log "============================================================" "INFO"
log " 1. REBOOT to apply all kernel/mount/auditd changes" "WARNING"
log " 2. REVIEW log file for errors: $LOG_FILE" "WARNING"
log " 3. VERIFY scoring engine: curl -k https://scoring.mlp.local:443" "WARNING"
log " 4. NETCAT scoring: nc scoring.mlp.local 444" "WARNING"
log " 5. CHECK your scored service is still running!" "WARNING"
log "      Apache2:  systemctl status apache2" "WARNING"
log "      MariaDB:  systemctl status mariadb" "WARNING"
log "      CUPS:     systemctl status cups" "WARNING"
log "      vsftpd:   systemctl status vsftpd" "WARNING"
log "      IRC:      systemctl status ngircd || inspircd" "WARNING"
log "      Nginx:    systemctl status nginx" "WARNING"
log " 6. VERIFY competition users can SSH into the system" "WARNING"
log " 7. RULE 14: $PASSWORD_CHANGE_COUNT/$MAX_PASSWORD_CHANGES password changes used this session!" "CRITICAL"
log " 8. RULE 10: SSH is HARDENED but NEVER DISABLED on Linux!" "CRITICAL"
log " 9. RULE 9:  Competition user accounts are NEVER disabled!" "CRITICAL"
log "10. RULE 7:  No subnet blocking - individual IPs only!" "CRITICAL"
log "11. RULE 5:  DO NOT touch /greyteam_key or any greyteam file!" "CRITICAL"
log "12. RULE 15: /greyteam_key presence = Red Team tools authorized!" "CRITICAL"
log "13. WATCH /var/log/auth.log for Red Team SSH attempts" "WARNING"
log "14. MONITOR: ausearch -k priv_escalation | tail -50" "WARNING"
log "15. REVIEW backdoor report: $LOG_DIR/backdoor_report_*.txt" "WARNING"
log "16. WATCH for re-appearing cron jobs or new user accounts" "WARNING"
log "17. CHECK /etc/hosts wasn't tampered with (DNS poisoning)" "WARNING"
log "18. DOCUMENT all actions - needed for inject (friendship lesson) responses!" "WARNING"
log "19. RUN this script periodically to maintain security posture" "WARNING"
log "20. REVERT budget (Rule 16): Up to 3 hosts/day can be reverted" "WARNING"

log "" "INFO"
log "============================================================" "INFO"
log "HARDENING COMPLETE - SYSTEM READY FOR COMPETITION" "SUCCESS"
log "============================================================" "INFO"

# Save completion state
cat > "$STATE_FILE" << JSON
{
  "LastRunTime":        "$(date '+%Y-%m-%d %H:%M:%S')",
  "RunCount":           $SCRIPT_RUN_COUNT,
  "ChangesApplied":     $CHANGES_COUNT,
  "AccountsLocked":     ${#REMOVED_USERS[@]},
  "SecurityIssues":     ${#SECURITY_ISSUES[@]},
  "PasswordChanges":    $PASSWORD_CHANGE_COUNT,
  "MaxPasswordChanges": $MAX_PASSWORD_CHANGES,
  "Hostname":           "$HOSTNAME_VAL",
  "Operator":           "$CURRENT_OPERATOR",
  "ScriptVersion":      "2.0-CDT-Charlie",
  "LogFile":            "$LOG_FILE"
}
JSON

# Final status banner
echo ""
echo -e "${C_CYAN}================================================================================${C_RESET}"
echo -e "${C_GREEN}                    BLUE TEAM HARDENING COMPLETE${C_RESET}"
echo -e "${C_CYAN}================================================================================${C_RESET}"
echo ""
echo -e "${C_WHITE}Script Run #:      ${C_RESET}${C_GREEN}#$SCRIPT_RUN_COUNT${C_RESET}"
echo -e "${C_WHITE}Operator:          ${C_RESET}${C_YELLOW}$CURRENT_OPERATOR${C_RESET}"
echo -e "${C_WHITE}Log File:          ${C_RESET}${C_YELLOW}$LOG_FILE${C_RESET}"
echo -e "${C_WHITE}PW Change Log:     ${C_RESET}${C_YELLOW}${PW_CHANGE_LOG:-N/A}${C_RESET}"
echo -e "${C_WHITE}Backdoor Report:   ${C_RESET}${C_YELLOW}$(ls "$LOG_DIR"/backdoor_report_*.txt 2>/dev/null | tail -1 || echo 'N/A')${C_RESET}"
echo -e "${C_WHITE}Changes Applied:   ${C_RESET}${C_GREEN}$CHANGES_COUNT${C_RESET}"
echo -e "${C_WHITE}Accounts Locked:   ${C_RESET}${C_CYAN}${#REMOVED_USERS[@]}${C_RESET}"
echo -e "${C_WHITE}Passwords Changed: ${C_RESET}${C_YELLOW}$PASSWORD_CHANGE_COUNT / $MAX_PASSWORD_CHANGES (Rule 14)${C_RESET}"
if [[ ${#SECURITY_ISSUES[@]} -gt 0 ]]; then
    echo -e "${C_WHITE}Security Issues:   ${C_RESET}${C_RED}${#SECURITY_ISSUES[@]} - REVIEW IMMEDIATELY!${C_RESET}"
else
    echo -e "${C_WHITE}Security Issues:   ${C_RESET}${C_GREEN}0${C_RESET}"
fi
echo ""
echo -e "${C_CYAN}================================================================================${C_RESET}"
echo ""

# Smart reboot logic
SHOULD_REBOOT=false
REBOOT_REASON=""

if [[ $SCRIPT_RUN_COUNT -eq 1 ]]; then
    SHOULD_REBOOT=true
    REBOOT_REASON="First run - reboot required to apply all kernel/mount/auditd changes"
elif [[ $CHANGES_COUNT -ge 5 ]]; then
    SHOULD_REBOOT=true
    REBOOT_REASON="Significant changes applied ($CHANGES_COUNT total) - reboot recommended"
else
    echo -e "${C_YELLOW}This is run #$SCRIPT_RUN_COUNT with $CHANGES_COUNT change(s) applied.${C_RESET}"
    echo -e "${C_YELLOW}Most settings are already configured - a reboot may not be necessary.${C_RESET}"
    echo ""
    read -rp "$(echo -e "${C_CYAN}Do you want to reboot now? (y/N): ${C_RESET}")" reboot_choice
    if [[ "${reboot_choice,,}" == "y" ]]; then
        SHOULD_REBOOT=true
        REBOOT_REASON="Manual reboot requested by operator"
    else
        echo ""
        echo -e "${C_YELLOW}Reboot skipped. Reboot later with: sudo reboot${C_RESET}"
        echo ""
        exit 0
    fi
fi

if $SHOULD_REBOOT; then
    log "Initiating system reboot: $REBOOT_REASON" "CRITICAL"
    echo ""
    echo -e "${C_YELLOW}$REBOOT_REASON${C_RESET}"
    echo ""
    for i in $(seq 10 -1 1); do
        printf "\r${C_YELLOW}Rebooting in ${C_RED}%2d${C_YELLOW} seconds... (Ctrl+C to cancel)${C_RESET}" "$i"
        sleep 1
    done
    echo ""
    echo -e "${C_RED}REBOOTING NOW...${C_RESET}"
    log "Reboot initiated." "CRITICAL"
    sleep 1
    reboot
fi

else
    # Individual phase(s) banner
    echo ""
    echo -e "${C_GREEN}========================================${C_RESET}"
    echo -e "${C_GREEN}  Individual Phase(s) Complete${C_RESET}"
    echo -e "${C_GREEN}  Phase(s) $(IFS=', '; echo "${SELECTED_PHASES[*]}") executed successfully.${C_RESET}"
    echo -e "${C_YELLOW}  Log: $LOG_FILE${C_RESET}"
    echo -e "${C_GREEN}========================================${C_RESET}"
    echo ""
fi
