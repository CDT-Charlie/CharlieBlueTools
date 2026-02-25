#!/usr/bin/env bash
#
# SecureLinux.sh - Blue Team Linux Hardening Script for CDT Competition - Team Charlie Spring 2026
#
# Comprehensive hardening for Blue vs Red competitions. Hardens SSH, firewall, users,
# and scored services. Access to Linux infra is SSH-only - this script does NOT
# disable or break SSH.
#
# CRITICAL:
#   - PAM is NOT modified (common-auth, common-account, common-password). Changes there
#     have broken all authentication in the past. Password policy uses login.defs + chage only.
#   - All SSH/sshd_config changes are validated with 'sshd -t' before reload.
#   - greyteam and scoring users are always protected (even if not listed in packet).
#   - /greyteam_key is NEVER modified (Rule 5 / Rule 15).
#
# RULES COMPLIANCE:
#   5  Do not modify artifacts with "greyteam" in name; do not touch /greyteam_key.
#   6  Do not migrate scored services (script only configures firewall for existing service).
#   7  No subnet blocking: only ALLOW rules for specific IPs/ranges; no block rules on ranges.
#   9  Do not disable valid packet users; all packet admin users retain admin (we only add, never remove sudo).
#   10 Do not disable SSH on Linux (script only hardens sshd).
#   11 No irreversible changes (no disk wipe, no scored service uninstall; userdel without -r).
#   14 Password changes limited to 3 per host per comp session (operator responsibility; script logs reminder).
#
# Requires: root, bash, ufw (or iptables), openssh-server
# Usage: sudo ./SecureLinux.sh [--help] [--phase N] [--phases 1,2,3] [--dry-run]
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration - EDIT THESE
# ---------------------------------------------------------------------------
AUTHORIZED_ADMINS=(blueadmin)                    # Your blue team usernames (sudo)
SET_ALL_USER_PASSWORDS="<CHANGE-PASSWORD-HERE>"  # Team password (max 3 resets per host per day)
SAFE_IP_ADDRESSES=(
    172.20.0.100   # Scoring engine
    172.20.0.41    # jumpblue1
    172.20.0.42    # jumpblue2
    172.20.0.43    # jumpblue3
    172.20.0.44    # jumpblue4
    172.20.0.45    # jumpblue5
    172.20.0.46    # jumpblue6
    172.20.0.47    # jumpblue7
    172.20.0.48    # jumpblue8
    172.20.0.49    # jumpblue9
    172.20.0.40    # jumpblue10
)
SAFE_IP_RANGES=(
    "10.0.10.0/24"
    "10.0.20.0/24"
    "10.0.30.0/24"
)

# Competition users + greyteam/scoring (DO NOT REMOVE - Rule 9, Rule 5)
SAFE_USERS=(
    root
    twilight pinkiepie applejack rarity rainbowdash fluttershy
    bigmac mayormare shiningarmor cadance
    spike starlight trixie derpy snips snails
    celestia discord luna starswirl
    greyteam grayteam gray_team grey_team scoring
    daemon bin sys sync games man lp mail news uucp
    www-data backup list irc proxy gnats nobody
    systemd-network systemd-resolve messagebus syslog
    _apt ntp systemd-timesync
)

# Password policy (applied via login.defs and chage - NOT PAM)
PASS_MAX_DAYS=90
PASS_MIN_DAYS=1
PASS_MIN_LEN=16
PASS_WARN_AGE=14
FAIL_DELAY=4
UMASK=027

LOG_DIR="/var/log/BlueTeam"
RUN_COUNTER_FILE="/var/lib/BlueTeam/script-run-counter.txt"

# ---------------------------------------------------------------------------
# Phase selection and help
# ---------------------------------------------------------------------------
RUN_PHASE1=false RUN_PHASE2=false RUN_PHASE3=false RUN_PHASE4=false
RUN_PHASE5=false RUN_PHASE6=false RUN_PHASE7=false
DRY_RUN=false

show_help() {
    cat << 'HELP'
SecureLinux.sh - Linux Hardening (CDT Team Charlie - Spring 2026)

USAGE:
  sudo ./SecureLinux.sh [OPTIONS]

OPTIONS:
  --help       Show this help
  --all        Run all phases (default if no phase specified)
  --phase N    Run phase N only (1-7)
  --phases N,M Run phases N and M (e.g. --phases 1,3,5)
  --dry-run    Print actions without applying (where possible)

PHASES:
  1  User account management (remove unauthorized, protect safe users, sudo audit)
  2  Password policy (login.defs + chage only; PAM is NOT modified)
  3  Firewall (ufw: default deny, allow SSH + service ports + safe IPs)
  4  SSH hardening (sshd_config; syntax check before reload)
  5  Network/host hardening (sysctl, disable unnecessary services)
  6  Backdoor detection (cron, systemd, suspicious binaries; skip greyteam)
  7  Audit and logging (rsyslog, auth.log)

RULES (competition compliance):
  5  Do not modify greyteam-named artifacts or /greyteam_key.
  6  Do not migrate scored services.
  7  No subnet blocking (only allow rules).
  9  Do not disable valid packet users; admins keep admin.
  10 Do not disable SSH on Linux.
  14 Password changes: max 3 per host per comp session.
HELP
    exit 0
}

# Parse arguments
SELECTED_PHASES=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help)    show_help ;;
        --all)     SELECTED_PHASES=(1 2 3 4 5 6 7); shift ;;
        --phase)   SELECTED_PHASES+=("$2"); shift 2 ;;
        --phases)  IFS=',' read -ra P <<< "$2"; SELECTED_PHASES+=("${P[@]}"); shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        *)         echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Default: all phases
if [[ ${#SELECTED_PHASES[@]} -eq 0 ]]; then
    SELECTED_PHASES=(1 2 3 4 5 6 7)
fi

for p in "${SELECTED_PHASES[@]}"; do
    case "$p" in
        1) RUN_PHASE1=true ;;
        2) RUN_PHASE2=true ;;
        3) RUN_PHASE3=true ;;
        4) RUN_PHASE4=true ;;
        5) RUN_PHASE5=true ;;
        6) RUN_PHASE6=true ;;
        7) RUN_PHASE7=true ;;
        *) echo "Invalid phase: $p"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers: logging and idempotent counter
# ---------------------------------------------------------------------------
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/Hardening-$(date +%Y-%m-%d-%H%M%S).log"
CHANGES=()
REMOVED_USERS=()
SECURITY_ISSUES=()

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
log_info() { log_msg "[INFO] $*"; }
log_ok()   { log_msg "[OK]   $*"; }
log_warn() { log_msg "[WARN] $*"; SECURITY_ISSUES+=("$*"); }
log_err()  { log_msg "[ERR]  $*"; SECURITY_ISSUES+=("$*"); }
add_change() { CHANGES+=("$*"); }

[[ -f "$RUN_COUNTER_FILE" ]] && RUN_COUNT=$(($(cat "$RUN_COUNTER_FILE") + 1)) || RUN_COUNT=1
mkdir -p "$(dirname "$RUN_COUNTER_FILE")"
echo "$RUN_COUNT" > "$RUN_COUNTER_FILE"

HOSTNAME=$(hostname -s 2>/dev/null || echo "unknown")
log_info "=============================================="
log_info "SecureLinux - Blue Team Hardening"
log_info "Host: $HOSTNAME | Run #$RUN_COUNT | Log: $LOG_FILE"
log_info "=============================================="

# Ensure we're root
if [[ $(id -u) -ne 0 ]]; then
    log_err "Must run as root (e.g. sudo)"
    exit 1
fi

# Build full safe user list (safe + authorized admins + current user)
CURRENT_USER="${SUDO_USER:-${USER:-}}"
ALL_SAFE=("${SAFE_USERS[@]}" "${AUTHORIZED_ADMINS[@]}")
[[ -n "$CURRENT_USER" ]] && ALL_SAFE+=("$CURRENT_USER")

is_safe_user() {
    local u="$1"
    local s
    for s in "${ALL_SAFE[@]}"; do [[ "$s" == "$u" ]] && return 0; done
    [[ "$u" == "greyteam" ]] && return 0
    [[ "$u" == "grayteam" ]] && return 0
    [[ "$u" == "scoring" ]] && return 0
    return 1
}

# ---------------------------------------------------------------------------
# PHASE 1: User account management
# ---------------------------------------------------------------------------
phase1_users() {
    log_info "PHASE 1: User account management"
    # Get usernames: uid >= 1000 (human) or uid < 1000 that we explicitly protect
    local all_users=()
    while IFS= read -r line; do
        local name uid
        name=$(echo "$line" | awk -F: '{print $1}')
        uid=$(echo "$line" | awk -F: '{print $3}')
        [[ -z "$uid" || -z "$name" ]] && continue
        if (( uid >= 1000 )) || is_safe_user "$name"; then
            all_users+=("$name")
        fi
    done < /etc/passwd

    for u in "${all_users[@]}"; do
        if is_safe_user "$u"; then
            log_info "  Keeping safe user: $u"
            continue
        fi
        if id "$u" &>/dev/null; then
            log_warn "Removing unauthorized user: $u"
            REMOVED_USERS+=("$u")
            add_change "User Management" "Removed user $u"
            # userdel without -r to avoid deleting home dirs (remove manually if needed)
            [[ "$DRY_RUN" != true ]] && userdel "$u" 2>/dev/null || true
        fi
    done

    # Audit sudo: remove unauthorized from sudo/sudoers.d (except greyteam/scoring)
    for sudofile in /etc/sudoers /etc/sudoers.d/*; do
        [[ -f "$sudofile" ]] || continue
        # Only report; automatic removal of sudo can lock out; log only
        log_info "  Sudo file present: $sudofile"
    done

    # Ensure authorized admins exist and are in sudo
    # Rule 14: Password changes limited to 3 per host per comp session - creating admin counts as one.
    for admin in "${AUTHORIZED_ADMINS[@]}"; do
        if ! id "$admin" &>/dev/null; then
            log_info "  Creating admin user: $admin"
            add_change "User Management" "Created user $admin"
            [[ "$DRY_RUN" != true ]] && useradd -m -s /bin/bash "$admin" && echo "$admin:$SET_ALL_USER_PASSWORDS" | chpasswd
            log_info "  Rule 14 reminder: max 3 password changes per host per comp session (this creation counts as one)."
        fi
        if ! getent group sudo | grep -q "\b$admin\b"; then
            log_info "  Adding $admin to sudo"
            add_change "User Management" "Added $admin to sudo"
            [[ "$DRY_RUN" != true ]] && usermod -aG sudo "$admin" 2>/dev/null || usermod -aG wheel "$admin" 2>/dev/null || true
        fi
    done
    log_ok "Phase 1 complete. Removed: ${#REMOVED_USERS[@]} users"
}

# ---------------------------------------------------------------------------
# PHASE 2: Password policy (login.defs + chage only - NO PAM)
# ---------------------------------------------------------------------------
phase2_password_policy() {
    log_info "PHASE 2: Password policy (login.defs + chage; PAM NOT modified)"
    local defs="/etc/login.defs"
    [[ ! -f "$defs" ]] && log_warn "login.defs not found" && return

    set_option() {
        local key="$1" val="$2"
        if grep -q "^${key}[[:space:]]" "$defs"; then
            sed -i "s/^${key}[[:space:]].*/${key} ${val}/" "$defs"
        else
            echo "${key} ${val}" >> "$defs"
        fi
    }
    [[ "$DRY_RUN" != true ]] && set_option PASS_MAX_DAYS "$PASS_MAX_DAYS"
    [[ "$DRY_RUN" != true ]] && set_option PASS_MIN_DAYS "$PASS_MIN_DAYS"
    [[ "$DRY_RUN" != true ]] && set_option PASS_MIN_LEN  "$PASS_MIN_LEN"
    [[ "$DRY_RUN" != true ]] && set_option PASS_WARN_AGE "$PASS_WARN_AGE"
    [[ "$DRY_RUN" != true ]] && set_option FAIL_DELAY   "$FAIL_DELAY"
    [[ "$DRY_RUN" != true ]] && set_option UMASK        "$UMASK"
    add_change "Password Policy" "login.defs: PASS_MAX_DAYS=$PASS_MAX_DAYS, PASS_MIN_LEN=$PASS_MIN_LEN"
    # Apply chage to existing human users (not system)
    for u in $(getent passwd | awk -F: '$3 >= 1000 {print $1}'); do
        if is_safe_user "$u"; then
            [[ "$DRY_RUN" != true ]] && chage -M "$PASS_MAX_DAYS" -m "$PASS_MIN_DAYS" -W "$PASS_WARN_AGE" "$u" 2>/dev/null || true
        fi
    done
    log_ok "Phase 2 complete (PAM untouched)"
}

# ---------------------------------------------------------------------------
# PHASE 3: Firewall (ufw) - allow SSH first, then service ports
# ---------------------------------------------------------------------------
phase3_firewall() {
    log_info "PHASE 3: Firewall (ufw)"
    if ! command -v ufw &>/dev/null; then
        log_warn "ufw not installed; skipping firewall"
        return
    fi
    # Service -> ports (Linux scored services)
    # ponyville=Apache2, seaddle=MariaDB, trotsylvania=CUPS, crystal-empire=vsftpd, everfree-forest=IRC, griffonstone=Nginx
    log_info "Select which scored service runs on this host:"
    echo "  1) Apache2 (ponyville) - 80,443"
    echo "  2) MariaDB (seaddle) - 3306"
    echo "  3) CUPS (trotsylvania) - 631"
    echo "  4) vsftpd (crystal-empire) - 21"
    echo "  5) IRC (everfree-forest) - 6667"
    echo "  6) Nginx (griffonstone) - 80,443"
    echo "  7) Workstation / none - SSH only"
    read -r -p "Choice [1-7] (default 7): " choice
    choice="${choice:-7}"
    local ports=(22)
    case "$choice" in
        1) ports+=(80 443) ;;
        2) ports+=(3306) ;;
        3) ports+=(631) ;;
        4) ports+=(21) ;;
        5) ports+=(6667) ;;
        6) ports+=(80 443) ;;
        7) ;;
        *) ports=(22) ;;
    esac

    if [[ "$DRY_RUN" == true ]]; then
        log_info "Dry-run: would set ufw default deny, allow ${ports[*]} and safe IPs"
        return
    fi
    ufw --force reset 2>/dev/null || true
    # Fail-safe: allow SSH (22) FIRST before default deny so we never lock out the current session.
    ufw allow 22/tcp comment "BlueTeam SSH (fail-safe)"
    # Rule 7: No subnet blocking - we only ALLOW specific ports and safe IPs/ranges; no block rules on contiguous ranges.
    ufw default deny incoming
    ufw default allow outgoing
    for p in "${ports[@]}"; do
        [[ "$p" == "22" ]] && continue
        ufw allow "$p/tcp" comment "BlueTeam service"
    done
    for ip in "${SAFE_IP_ADDRESSES[@]}"; do
        ufw allow from "$ip" comment "BlueTeam safe IP"
    done
    for range in "${SAFE_IP_RANGES[@]}"; do
        ufw allow from "$range" comment "BlueTeam range"
    done
    ufw --force enable
    add_change "Firewall" "ufw: default deny, allow ${ports[*]}"
    log_ok "Phase 3 complete"
}

# ---------------------------------------------------------------------------
# PHASE 4: SSH hardening (sshd_config) - syntax check before reload
# ---------------------------------------------------------------------------
phase4_ssh() {
    log_info "PHASE 4: SSH hardening (sshd_config)"
    local cfg="/etc/ssh/sshd_config"
    local backup="${cfg}.bak.$(date +%Y%m%d%H%M%S)"
    if [[ ! -f "$cfg" ]]; then
        log_warn "sshd_config not found"
        return
    fi
    # Options that harden SSH (modern; avoid deprecated e.g. HostRSAAuthentication)
    # Do not set AllowUsers/DenyUsers here - can lock out greyteam/scoring.
    local opts=(
        "PermitRootLogin prohibit-password"
        "PasswordAuthentication yes"
        "PubkeyAuthentication yes"
        "PermitEmptyPasswords no"
        "X11Forwarding no"
        "MaxAuthTries 3"
        "ClientAliveInterval 300"
        "ClientAliveCountMax 2"
    )
    if [[ "$DRY_RUN" == true ]]; then
        log_info "Dry-run: would set sshd options and run sshd -t before reload"
        return
    fi
    cp -a "$cfg" "$backup"
    local line key val
    for line in "${opts[@]}"; do
        key="${line%% *}"
        val="${line#* }"
        if grep -q "^${key}[[:space:]]" "$cfg"; then
            sed -i "s/^${key}[[:space:]].*/${key} ${val}/" "$cfg"
        else
            echo "${key} ${val}" >> "$cfg"
        fi
    done
    # Critical: syntax check before reload (avoids locking out SSH)
    if ! sshd -t 2>/dev/null; then
        log_err "sshd_config syntax check FAILED - restoring backup"
        cp -a "$backup" "$cfg"
        return 1
    fi
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service ssh reload 2>/dev/null || true
    add_change "SSH" "sshd_config hardened; sshd -t passed; reloaded"
    log_ok "Phase 4 complete (sshd -t passed)"
}

# ---------------------------------------------------------------------------
# PHASE 5: Network/host hardening (sysctl)
# ---------------------------------------------------------------------------
phase5_network() {
    log_info "PHASE 5: Network hardening"
    local sysctl_conf="/etc/sysctl.d/99-BlueTeam.conf"
    if [[ "$DRY_RUN" != true ]]; then
        cat > "$sysctl_conf" << 'SYSCTL'
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
SYSCTL
        sysctl -p "$sysctl_conf" 2>/dev/null || true
        add_change "Network" "sysctl hardening applied"
    fi
    log_ok "Phase 5 complete"
}

# ---------------------------------------------------------------------------
# PHASE 6: Backdoor detection (cron, systemd) - skip greyteam-named
# Rule 5: Do not modify system artifacts with "greyteam" in their name.
# Rule 15: /greyteam_key must not be modified - we never touch it.
# ---------------------------------------------------------------------------
phase6_backdoor() {
    log_info "PHASE 6: Backdoor detection (skip greyteam/grayteam named)"
    # Explicit: never modify /greyteam_key (Rule 5 / Rule 15)
    if [[ -f /greyteam_key ]]; then
        log_info "  /greyteam_key present - will not modify (Rule 5/15)"
    fi
    local found=0
    # Cron: list and flag suspicious (do not auto-remove)
    for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
        [[ -f "$f" ]] || continue
        if [[ "$f" == *greyteam* || "$f" == *grayteam* ]]; then
            log_info "  Skipping (protected): $f"
            continue
        fi
        # Log unusual cron entries
        while IFS= read -r line; do
            [[ "$line" =~ ^# ]] && continue
            if [[ "$line" == *curl* ]] || [[ "$line" == *wget* ]] || [[ "$line" == *bash*-c* ]]; then
                log_warn "Suspicious cron entry in $f: $line"
                ((found++)) || true
            fi
        done < "$f" 2>/dev/null
    done
    # systemd user / system services in /etc - skip greyteam
    for u in /etc/systemd/system/*.service /lib/systemd/system/*.service; do
        [[ -f "$u" ]] || continue
        if [[ "$u" == *greyteam* || "$u" == *grayteam* ]]; then continue; fi
        # Optional: list custom services
        [[ "$u" =~ /etc/ ]] && log_info "  Custom service: $u"
    done
    log_ok "Phase 6 complete (suspicious items: $found)"
}

# ---------------------------------------------------------------------------
# PHASE 7: Audit and logging
# ---------------------------------------------------------------------------
phase7_audit() {
    log_info "PHASE 7: Audit and logging"
    if [[ -d /etc/rsyslog.d ]]; then
        if [[ "$DRY_RUN" != true ]]; then
            echo "auth,authpriv.* /var/log/auth.log" > /etc/rsyslog.d/99-BlueTeam.conf 2>/dev/null || true
            systemctl restart rsyslog 2>/dev/null || true
        fi
        add_change "Audit" "rsyslog auth logging ensured"
    fi
    log_ok "Phase 7 complete"
}

# ---------------------------------------------------------------------------
# Run selected phases
# ---------------------------------------------------------------------------
$RUN_PHASE1 && phase1_users
$RUN_PHASE2 && phase2_password_policy
$RUN_PHASE3 && phase3_firewall
$RUN_PHASE4 && phase4_ssh
$RUN_PHASE5 && phase5_network
$RUN_PHASE6 && phase6_backdoor
$RUN_PHASE7 && phase7_audit

# Summary
log_info "=============================================="
log_info "Summary: Changes=${#CHANGES[@]} RemovedUsers=${#REMOVED_USERS[@]} Issues=${#SECURITY_ISSUES[@]}"
log_info "Log: $LOG_FILE"
log_info "Rule 14: Password changes are limited to 3 per host per comp session."
log_ok "Hardening complete. Recommend: test SSH in another session before closing."
exit 0
