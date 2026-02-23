#!/bin/bash
# =============================================================================
# Blue Team Hardening Script (Linux) — Competition-safe
# Target: Debian 13, Ubuntu 24.04. Filesystem/permission hardening + kernel
#         hardening where permitted. NO firewall, SSH config content, DNS,
#         or package removals. Idempotent. Safe for scored services.
#
# Usage:
#   sudo ./linux_hardening.sh           # apply hardening (logs to $LOG_FILE)
#   sudo ./linux_hardening.sh --verify  # read-only, no changes
#   sudo ./linux_hardening.sh --limits # apply hardening + optional nproc limits
# =============================================================================

set -euo pipefail
VERIFY=0
APPLY_LIMITS=0
LOG_FILE="${BLUE_TEAM_LOG:-/var/log/blue_team_hardening.log}"

log()   { printf '[*] %s\n' "$*"; }
warn()  { printf '[!] %s\n' "$*"; }
skip()  { printf '[-] %s\n' "$*"; }
v()     { printf '  %s %s %s\n' "$1" "${2:-}" "${3:-}"; }

log_change() {
    if [ "$VERIFY" -eq 0 ] && [ -n "${1:-}" ]; then
        echo "$(date -Iseconds) $*" >> "${LOG_FILE}" 2>/dev/null || true
        CHANGED="${CHANGED:-}${CHANGED:+ }$1"
    fi
}

# --- Permissions: only /tmp, /var/tmp, /root; do NOT chmod /var/log or cron spool ---
harden_dirs() {
    log "Hardening directory permissions (minimal safe set)..."
    # /tmp and /var/tmp: sticky 1777
    for d in /tmp /var/tmp; do
        if [ ! -d "$d" ]; then continue; fi
        p=$(stat -c '%a' "$d" 2>/dev/null || true)
        if [ -n "$p" ] && [ "$p" != "1777" ]; then
            if chmod 1777 "$d" 2>/dev/null; then
                log "Set $d to 1777 (sticky)"
                log_change "chmod 1777 $d (was $p)"
            else
                warn "Could not chmod $d"
            fi
        fi
    done
    # /root: 700
    if [ -d /root ]; then
        p=$(stat -c '%a' /root 2>/dev/null || true)
        if [ -n "$p" ] && [ "$p" != "700" ]; then
            if chmod 700 /root 2>/dev/null; then
                log "Set /root to 700"
                log_change "chmod 700 /root (was $p)"
            else
                warn "Could not chmod /root"
            fi
        fi
    fi
    # /var/cache/apt and archives: only if dangerously permissive (world-writable)
    for d in /var/cache/apt /var/cache/apt/archives; do
        if [ ! -d "$d" ]; then continue; fi
        p=$(stat -c '%a' "$d" 2>/dev/null || true)
        if [ "$p" = "777" ] || [ "$p" = "776" ]; then
            if chmod 755 "$d" 2>/dev/null; then
                log "Set $d to 755 (was world-writable)"
                log_change "chmod 755 $d (was $p)"
            else
                warn "Could not chmod $d"
            fi
        fi
    done
    # .iocache only if present and not 700
    if [ -d /var/cache/apt/.iocache ]; then
        p=$(stat -c '%a' /var/cache/apt/.iocache 2>/dev/null || true)
        if [ -n "$p" ] && [ "$p" != "700" ]; then
            chmod 700 /var/cache/apt/.iocache 2>/dev/null && { log "Set /var/cache/apt/.iocache to 700"; log_change "chmod 700 /var/cache/apt/.iocache (was $p)"; } || true
        fi
    fi
    # Cron dirs under /etc: only if >755 (do not touch /var/spool/cron*)
    for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do
        if [ ! -d "$d" ]; then continue; fi
        p=$(stat -c '%a' "$d" 2>/dev/null || true)
        if [ -n "$p" ] && [ "$p" -gt 755 ] 2>/dev/null; then
            chmod 755 "$d" 2>/dev/null && { log "Set $d to 755"; log_change "chmod 755 $d (was $p)"; } || true
        fi
    done
    # /etc/pam.d: only if world/group writable (avoid churn)
    if [ -d /etc/pam.d ]; then
        p=$(stat -c '%a' /etc/pam.d 2>/dev/null || true)
        if [ -n "$p" ] && { [ "$p" = "777" ] || [ "$p" = "776" ] || [ "$p" = "775" ]; }; then
            chmod 755 /etc/pam.d 2>/dev/null && { log "Set /etc/pam.d to 755 (was world/group writable)"; log_change "chmod 755 /etc/pam.d (was $p)"; } || true
        fi
    fi
    # /var/lib/dpkg/info: only if 777
    if [ -d /var/lib/dpkg/info ]; then
        p=$(stat -c '%a' /var/lib/dpkg/info 2>/dev/null || true)
        if [ "$p" = "777" ]; then
            chmod 755 /var/lib/dpkg/info 2>/dev/null && { log "Set /var/lib/dpkg/info to 755 (was 777)"; log_change "chmod 755 /var/lib/dpkg/info (was $p)"; } || true
        fi
    fi
}

# --- Files: sudoers, SSH host keys only (no sshd_config content); log files only if world-writable ---
harden_files() {
    log "Hardening file permissions..."
    # Log files: only fix if world-writable
    for f in /var/log/auth.log /var/log/syslog /var/log/secure; do
        if [ ! -f "$f" ]; then continue; fi
        p=$(stat -c '%a' "$f" 2>/dev/null || true)
        if [ "$p" = "666" ] || [ "$p" = "777" ]; then
            if chmod 640 "$f" 2>/dev/null; then
                log "Set $f to 640 (was world-writable)"
                log_change "chmod 640 $f (was $p)"
            else
                warn "Could not chmod $f"
            fi
        fi
    done
    # Sudoers: 440 / 750 / 440 (warn only if cannot set)
    if [ -f /etc/sudoers ]; then
        p=$(stat -c '%a' /etc/sudoers 2>/dev/null || true)
        if [ -n "$p" ] && [ "$p" != "440" ] && [ "$p" != "400" ]; then
            if chmod 440 /etc/sudoers 2>/dev/null; then
                log "Set /etc/sudoers to 440"
                log_change "chmod 440 /etc/sudoers (was $p)"
            else
                warn "Could not chmod /etc/sudoers (current $p); fix manually"
            fi
        fi
    fi
    if [ -d /etc/sudoers.d ]; then
        p=$(stat -c '%a' /etc/sudoers.d 2>/dev/null || true)
        if [ -n "$p" ] && [ "$p" != "750" ] && [ "$p" != "700" ]; then
            if chmod 750 /etc/sudoers.d 2>/dev/null; then
                log "Set /etc/sudoers.d to 750"
                log_change "chmod 750 /etc/sudoers.d (was $p)"
            else
                warn "Could not chmod /etc/sudoers.d (current $p)"
            fi
        fi
        for f in /etc/sudoers.d/*; do
            if [ ! -f "$f" ]; then continue; fi
            p=$(stat -c '%a' "$f" 2>/dev/null || true)
            if [ -n "$p" ] && [ "$p" != "440" ] && [ "$p" != "400" ]; then
                chmod 440 "$f" 2>/dev/null && { log "Set $f to 440"; log_change "chmod 440 $f (was $p)"; } || true
            fi
        done
    fi
    # SSH host private keys only (600); do not modify sshd_config content
    for f in /etc/ssh/ssh_host_*_key; do
        if [ ! -f "$f" ]; then continue; fi
        p=$(stat -c '%a' "$f" 2>/dev/null || true)
        if [ -n "$p" ] && [ "$p" != "600" ]; then
            if chmod 600 "$f" 2>/dev/null; then
                log "Set $f to 600"
                log_change "chmod 600 $f (was $p)"
            else
                warn "Could not chmod $f"
            fi
        fi
    done
    # /root/.ssh dir
    if [ -d /root/.ssh ]; then
        p=$(stat -c '%a' /root/.ssh 2>/dev/null || true)
        if [ -n "$p" ] && [ "$p" != "700" ]; then
            chmod 700 /root/.ssh 2>/dev/null && { log "Set /root/.ssh to 700"; log_change "chmod 700 /root/.ssh (was $p)"; } || true
        fi
    fi
}

# --- Home dirs: correct passwd parsing; warn only; skip uid<1000 and nologin ---
# Format: user:x:uid:gid:gecos:homedir:shell (fields 1-7)
harden_homedirs() {
    log "Checking home directory permissions (warn only)..."
    while IFS=: read -r _ _ uid _ _ homedir shell || [ -n "${homedir:-}" ]; do
        [ -z "${homedir:-}" ] && continue
        [ ! -d "$homedir" ] && continue
        [ "${uid:-0}" -lt 1000 ] 2>/dev/null && continue
        case "${shell:-}" in
            *nologin*|*false*) continue ;;
        esac
        p=$(stat -c '%a' "$homedir" 2>/dev/null || true)
        if [ -n "$p" ] && [ "$p" != "700" ] && [ "$p" != "750" ] && [ "$p" != "755" ]; then
            if [ "$p" = "777" ] || [ "$p" = "775" ]; then
                warn "Loose home dir: $homedir ($p). Consider: chmod 750 $homedir"
            fi
        fi
    done < /etc/passwd 2>/dev/null || true
}

# --- World-writable: report only (no chmod) ---
harden_no_world_writable() {
    log "Checking for world-writable files in sensitive paths..."
    for base in /etc /usr/bin /usr/sbin /var/log; do
        if [ ! -d "$base" ]; then continue; fi
        while IFS= read -r -d '' f; do
            p=$(stat -c '%a' "$f" 2>/dev/null || true)
            case "$p" in 666|777|776|766) warn "World-writable: $f ($p) — fix manually if needed" ;; esac
        done < <(find "$base" -type f -perm -0002 2>/dev/null | head -50) 2>/dev/null || true
    done
}

# --- Cron spool: verify + warn if world-writable; do NOT chmod ---
check_cron_spool() {
    log "Checking cron spool permissions (verify only, no change)..."
    for d in /var/spool/cron /var/spool/cron/crontabs; do
        if [ ! -d "$d" ]; then continue; fi
        p=$(stat -c '%a' "$d" 2>/dev/null || true)
        if [ -n "$p" ] && { [ "$p" = "777" ] || [ "$p" = "776" ] || [ "$p" = "775" ]; }; then
            warn "Cron spool $d has loose permissions ($p). Consider: chmod 750 $d (manual)"
            MANUAL="${MANUAL:-}${MANUAL:+ }chmod 750 $d"
        fi
    done
}

# --- World-writable directories: report only (outside temp) ---
audit_world_writable_dirs() {
    log "Checking for world-writable directories (outside /tmp,/var/tmp)..."
    while IFS= read -r -d '' d; do
        case "$d" in
            /tmp|/tmp/*|/var/tmp|/var/tmp/*) continue ;;
        esac
        perms=$(stat -c '%a' "$d" 2>/dev/null || true)
        warn "World-writable dir: $d ($perms) — investigate; fix manually if unsafe"
    done < <(find / -xdev -type d -perm -0002 -print0 2>/dev/null | head -z -n 80) 2>/dev/null || true
}

# --- PATH directory permissions: report only ---
audit_path_dirs() {
    log "Checking PATH directory permissions (root + current env)..."
    # Root PATH (what matters most)
    root_path="$(sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin bash -lc 'echo $PATH' 2>/dev/null || echo '/usr/sbin:/usr/bin:/sbin:/bin')"
    for p in "$root_path" "$PATH"; do
        echo "$p" | tr ':' '\n' | while read -r d; do
            [ -d "$d" ] || continue
            # Flag if directory is writable by group/other
            if find "$d" -maxdepth 0 -perm -0020 -o -perm -0002 2>/dev/null | grep -q .; then
                warn "PATH dir writable by group/other: $d — risk of PATH hijack"
            fi
        done
    done
}

# --- SUID/SGID inventory + baseline (detect changes) ---
inventory_suid_sgid() {
    log "SUID/SGID inventory (baseline + verify changes)..."
    BASE_DIR="/root/baselines"
    BASE_FILE="${BASE_DIR}/suid_sgid.list"
    CUR_FILE="/tmp/suid_sgid.current"

    mkdir -p "$BASE_DIR" 2>/dev/null || true

    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort > "$CUR_FILE" || true

    if [ ! -f "$BASE_FILE" ]; then
        cp "$CUR_FILE" "$BASE_FILE" 2>/dev/null && log "Created baseline: $BASE_FILE" && log_change "created $BASE_FILE"
    else
        if ! diff -u "$BASE_FILE" "$CUR_FILE" >/tmp/suid_sgid.diff 2>/dev/null; then
            warn "SUID/SGID list changed since baseline! See: /tmp/suid_sgid.diff"
        fi
    fi
}

# --- Critical binary hash baseline (detect tampering) ---
baseline_hashes() {
    log "Critical binary hash baseline (sudo/su/sshd if present)..."
    BASE_DIR="/root/baselines"
    BASE_FILE="${BASE_DIR}/core_bins.sha256"
    CUR_FILE="/tmp/core_bins.current.sha256"

    mkdir -p "$BASE_DIR" 2>/dev/null || true

    # Only hash files that exist
    files=""
    for f in /usr/bin/sudo /bin/su /usr/sbin/sshd; do
        [ -f "$f" ] && files="${files} $f"
    done

    if [ -z "$files" ]; then
        skip "No core binaries found to baseline (unexpected); skipping"
        return 0
    fi

    sha256sum $files 2>/dev/null | sort > "$CUR_FILE" || true

    if [ ! -f "$BASE_FILE" ]; then
        cp "$CUR_FILE" "$BASE_FILE" 2>/dev/null && log "Created baseline: $BASE_FILE" && log_change "created $BASE_FILE"
    else
        if ! sha256sum -c "$BASE_FILE" >/tmp/core_bins.hashcheck 2>&1; then
            warn "Hash mismatch detected! See: /tmp/core_bins.hashcheck"
        fi
    fi
}

# --- Competition-aware checks (warn only; never modify or abort) ---
comp_checks() {
    log "Competition / persistence checks (warn only)..."
    # Files in /var/cache/apt that shouldn't be there
    for x in /var/cache/apt/pkgcache.py /var/cache/apt/.launcher.sh /var/cache/apt/.portd.py; do
        if [ -f "$x" ]; then warn "Suspicious file in /var/cache/apt: $x"; fi
    done
    [ -d /var/cache/apt/.iocache ] && warn "Suspicious dir in /var/cache/apt: .iocache"
    # systemd units
    for u in apt-cache-manager apt-socket-mgr; do
        if systemctl is-enabled "$u" 2>/dev/null | grep -q enabled; then
            warn "Suspicious service enabled: $u. Disable with: systemctl disable --now $u"
        fi
    done
    # Immutable attribute on those files
    for x in /var/cache/apt/pkgcache.py /var/cache/apt/.launcher.sh /var/cache/apt/.portd.py \
             /etc/systemd/system/apt-cache-manager.service /etc/systemd/system/apt-socket-mgr.service; do
        if [ -f "$x" ]; then
            if lsattr "$x" 2>/dev/null | grep -q '^....i'; then warn "Immutable attribute set on: $x"; fi
        fi
    done
    # /var/lib/apt/sudo
    if [ -f /var/lib/apt/sudo ] && [ -x /var/lib/apt/sudo ]; then
        warn "Found /var/lib/apt/sudo (real sudo moved?). Restore: cp /var/lib/apt/sudo /usr/bin/sudo && chmod 4755 /usr/bin/sudo"
    fi
    # ponypasswords.txt
    for base in /root /tmp /home; do
        [ ! -d "$base" ] && continue
        ( find "$base" -maxdepth 3 -name 'ponypasswords.txt' 2>/dev/null | while read -r f; do warn "Credential dump?: $f"; done ) || true
    done
    # debsums for sudo binary (optional)
    if [ -f /usr/bin/sudo ] && command -v debsums >/dev/null 2>&1; then
        debsums -s /usr/bin/sudo 2>/dev/null || warn "sudo binary may be modified. Consider: apt reinstall sudo"
    fi
}

# --- Mount options: warn only if separate mount; do NOT modify fstab ---
harden_mounts() {
    log "Checking mount options (warn only; no fstab changes)..."
    for mnt in /tmp /var/tmp /dev/shm; do
        if [ ! -d "$mnt" ]; then continue; fi
        opts=$(findmnt -no OPTIONS "$mnt" 2>/dev/null || true)
        if [ -z "$opts" ]; then continue; fi
        # Only warn if it's a separate mount (findmnt returns options for the mount point)
        case "$mnt" in
            /tmp|/var/tmp)
                if echo "$opts" | grep -q nosuid; then :; else
                    warn "Consider mounting $mnt with nosuid (add to fstab manually; no change by this script)"
                fi
                ;;
            /dev/shm)
                if echo "$opts" | grep -q noexec && echo "$opts" | grep -q nosuid; then :; else
                    warn "Consider /dev/shm with noexec,nosuid (add to fstab manually; no change by this script)"
                fi
                ;;
        esac
    done
}

# --- Process limits: core 0 always (safe); nproc only with --limits, exclude root ---
harden_limits() {
    log "Process limits..."
    # Core dumps: disable (safe for services)
    CORE_CONF="/etc/security/limits.d/98-blue-team-core.conf"
    if [ ! -f "$CORE_CONF" ]; then
        printf '%s\n' "# Blue team: disable core dumps" "* soft core 0" "* hard core 0" > "$CORE_CONF"
        log "Created $CORE_CONF (core 0)"
        log_change "created $CORE_CONF"
    else
        skip "Core limits already in $CORE_CONF"
    fi
    # nproc: only with --limits; safe defaults, exclude root
    if [ "$APPLY_LIMITS" -eq 1 ]; then
        LIMITS_CONF="/etc/security/limits.d/99-blue-team-nproc.conf"
        if [ ! -f "$LIMITS_CONF" ]; then
            printf '%s\n' "# Blue team: optional nproc (exclude root)" "* soft nproc 4096" "* hard nproc 8192" "root soft nproc unlimited" "root hard nproc unlimited" > "$LIMITS_CONF"
            log "Created $LIMITS_CONF (nproc 4096/8192, root unlimited)"
            log_change "created $LIMITS_CONF"
        else
            skip "Process limits already in $LIMITS_CONF"
        fi
    else
        SKIPPED="${SKIPPED:-}${SKIPPED:+ }nproc limits (use --limits to enable)"
    fi
}

# --- Sysctl: only if writable; create file then sysctl --system or -p ---
harden_sysctl() {
    log "Kernel/sysctl hardening..."
    if [ ! -w /proc/sys ]; then
        warn "Cannot write sysctl (e.g. container); skipping. Manual: add /etc/sysctl.d/99-blue-team.conf and run sysctl --system"
        SKIPPED="${SKIPPED:-}${SKIPPED:+ }sysctl (read-only)"
        return
    fi
    SYSCTL_CONF="/etc/sysctl.d/99-blue-team.conf"
    if [ ! -f "$SYSCTL_CONF" ]; then
        cat > "$SYSCTL_CONF" << 'EOF'
# Blue team: safe kernel hardening (Debian 13 / Ubuntu 24.04)
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
vm.mmap_min_addr = 65536
fs.suid_dumpable = 0
EOF
        log "Created $SYSCTL_CONF"
        log_change "created $SYSCTL_CONF"
        if command -v sysctl >/dev/null 2>&1; then
            if sysctl --system >/dev/null 2>&1; then
                log "Applied sysctl (sysctl --system)"
            elif sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1; then
                log "Applied sysctl (sysctl -p)"
            else
                warn "Could not apply sysctl; run manually: sysctl --system or sysctl -p $SYSCTL_CONF"
                MANUAL="${MANUAL:-}${MANUAL:+ }sysctl --system"
            fi
        fi
    else
        skip "Sysctl config already exists: $SYSCTL_CONF"
    fi
}

# --- Summary ---
print_summary() {
    echo ""
    echo "=== Summary ==="
    if [ -n "$CHANGED" ]; then
        echo "Changed: $CHANGED"
    else
        echo "Changed: (none)"
    fi
    if [ -n "$SKIPPED" ]; then
        echo "Skipped: $SKIPPED"
    fi
    if [ -n "$MANUAL" ]; then
        echo "Manual follow-up: $MANUAL"
    fi
    echo "Log: $LOG_FILE"
    echo "Verify: $0 --verify"
}

# ========== Verify mode (read-only) ==========
verify_dirs() {
    log "Directory permissions (current state)"
    for path in /tmp /var/tmp /root /var/cache/apt /var/cache/apt/archives /var/cache/apt/.iocache; do
        if [ ! -e "$path" ]; then v "$path" "missing" "(OK if not present)"; continue; fi
        p=$(stat -c '%a' "$path" 2>/dev/null || true)
        case "$path" in
            /tmp|/var/tmp) exp="1777" ;;
            /root) exp="700" ;;
            /var/cache/apt/.iocache) exp="700" ;;
            *) exp="755" ;;
        esac
        if [ "$p" = "$exp" ]; then v "$path" "$p" "OK"; else v "$path" "$p" "(expected $exp)"; fi
    done
    for d in /var/spool/cron /var/spool/cron/crontabs; do
        if [ ! -d "$d" ]; then continue; fi
        p=$(stat -c '%a' "$d" 2>/dev/null || true)
        v "$d" "$p" "(verify only; script does not chmod)"
    done
}

verify_files() {
    log "File permissions (current state)"
    [ -f /etc/sudoers ] && p=$(stat -c '%a' /etc/sudoers 2>/dev/null) && v "/etc/sudoers" "$p" "$([ "$p" = "440" ] || [ "$p" = "400" ] && echo "OK" || echo "(expected 440)")"
    [ -d /etc/sudoers.d ] && p=$(stat -c '%a' /etc/sudoers.d 2>/dev/null) && v "/etc/sudoers.d" "$p" "$([ "$p" = "750" ] || [ "$p" = "700" ] && echo "OK" || echo "(expected 750)")"
    for f in /etc/ssh/ssh_host_*_key; do
        [ ! -f "$f" ] && continue
        p=$(stat -c '%a' "$f" 2>/dev/null) && v "$f" "$p" "$([ "$p" = "600" ] && echo "OK" || echo "(expected 600)")"
    done
    [ -d /root/.ssh ] && p=$(stat -c '%a' /root/.ssh 2>/dev/null) && v "/root/.ssh" "$p" "$([ "$p" = "700" ] && echo "OK" || echo "(expected 700)")"
}

verify_limits() {
    log "Limits"
    CORE_CONF="/etc/security/limits.d/98-blue-team-core.conf"
    LIMITS_CONF="/etc/security/limits.d/99-blue-team-nproc.conf"
    if [ -f "$CORE_CONF" ]; then v "$CORE_CONF" "present" "OK"; else v "$CORE_CONF" "missing" ""; fi
    if [ -f "$LIMITS_CONF" ]; then v "$LIMITS_CONF" "present" "OK"; else v "$LIMITS_CONF" "missing" "(use --limits to create)"; fi
}

verify_sysctl() {
    log "Sysctl"
    SYSCTL_CONF="/etc/sysctl.d/99-blue-team.conf"
    if [ -f "$SYSCTL_CONF" ]; then v "$SYSCTL_CONF" "present" "OK"; else v "$SYSCTL_CONF" "missing" ""; fi
    for key in kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope kernel.randomize_va_space vm.mmap_min_addr fs.suid_dumpable; do
        val=$(sysctl -n "$key" 2>/dev/null || true)
        [ -n "$val" ] && v "  $key" "=" "$val"
    done
}

verify_all() {
    echo "=== Verify mode (read-only, no changes) ==="
    [ "$(id -u)" -ne 0 ] && echo "Run as root for full verify: sudo $0 --verify"
    verify_dirs
    verify_files
    verify_limits
    verify_sysctl
    log "Competition / persistence (warn only)"
    comp_checks
    audit_world_writable_dirs
    audit_path_dirs
    inventory_suid_sgid
    baseline_hashes
    echo ""
    echo "=== End verify ==="
    echo "Log (if hardening was run): $LOG_FILE"
}

# --- Main ---
main() {
    for a in "$@"; do
        a="${a%%$'\r'}"
        case "$a" in
            --verify|-v|--verify*) VERIFY=1 ;;
            --limits)              APPLY_LIMITS=1 ;;
            -h|--help)
                echo "Usage: $0 [--verify] [--limits] [--help]"
                echo "  (no args)  Apply hardening. Changes logged to: $LOG_FILE"
                echo "  --verify   Read-only: show state, no changes."
                echo "  --limits   Also apply optional nproc limits (4096/8192, root excluded)."
                echo "  --help     This help."
                exit 0
                ;;
        esac
    done

    if [ "$VERIFY" -eq 1 ]; then
        verify_all
        return 0
    fi

    echo "=== Blue Team Hardening (competition-safe) ==="
    if [ "$(id -u)" -ne 0 ]; then
        echo "Run as root: sudo $0"
        exit 1
    fi

    CHANGED=""
    SKIPPED=""
    MANUAL=""

    harden_dirs
    harden_files
    harden_homedirs
    harden_no_world_writable
    audit_world_writable_dirs
    audit_path_dirs
    inventory_suid_sgid
    baseline_hashes
    check_cron_spool
    comp_checks
    harden_mounts
    harden_limits
    harden_sysctl
    print_summary
}

main "$@"