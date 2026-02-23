#!/bin/bash
# =============================================================================
# Blue Team Monitoring Script (Linux) — Behavior-based, tool-agnostic
# Read-only, safe for cron. Debian 13, Ubuntu 24.04.
# Usage: sudo ./linux_monitor.sh [--quiet] [--json]
# =============================================================================

set -u
FINDINGS=0
QUIET=0
JSON=0
ALERTS_JSON=""

trap 'echo "[!] Unexpected error in $0 at line $LINENO (exit $?)" >&2' ERR

log()   { [ "$QUIET" -eq 0 ] && printf '[*] %s\n' "$*"; }
alert() {
    printf '[ALERT] %s\n' "$*"
    FINDINGS=$((FINDINGS + 1))
    if [ "$JSON" -eq 1 ]; then
        msg="${*//\\/\\\\}"; msg="${msg//\"/\\\"}"; msg="${msg//$'\n'/ }"
        ALERTS_JSON="${ALERTS_JSON}${ALERTS_JSON:+, }{\"message\": \"$msg\"}"
    fi
}
section() { [ "$QUIET" -eq 0 ] && echo "" && printf '=== %s ===\n' "$*"; }

# --- A) Privilege-escalation tampering ---
check_privilege_escalation() {
    section "Privilege-escalation tampering"

    # sudo binary must exist, root:root, setuid (e.g. 4755)
    if [ ! -e /usr/bin/sudo ]; then
        alert "Privilege binary missing: /usr/bin/sudo"
    else
        owner=$(stat -c '%U:%G' /usr/bin/sudo 2>/dev/null || true)
        mode=$(stat -c '%a' /usr/bin/sudo 2>/dev/null || true)
        if [ -n "$owner" ] && [ "$owner" != "root:root" ]; then
            alert "Privilege binary wrong owner: /usr/bin/sudo ($owner)"
        fi
        if [ -n "$mode" ]; then
            case "$mode" in
                4755|4750|4700|rwsr-xr-x) ;;
                *) alert "Privilege binary missing setuid or wrong mode: /usr/bin/sudo ($mode)" ;;
            esac
        fi
    fi

    if command -v debsums >/dev/null 2>&1; then
        if ! debsums -s /usr/bin/sudo 2>/dev/null; then
            alert "Binary integrity mismatch: /usr/bin/sudo (verify package)"
        fi
    fi
}

# --- B) Suspicious persistence ---
check_persistence() {
    section "Suspicious persistence"

    _writable_paths_re='/tmp|/var/tmp|/dev/shm|/var/cache|/home|/\.[^/]+'

    if command -v systemctl >/dev/null 2>&1; then
        while read -r unit; do
            [ -z "$unit" ] && continue
            path=""
            if [ -f "/etc/systemd/system/${unit}" ]; then
                path="/etc/systemd/system/${unit}"
            else
                path=$(systemctl show -p FragmentPath "$unit" 2>/dev/null) || true
                path="${path#FragmentPath=}"
            fi
            [ -z "$path" ] || [ ! -f "$path" ] && continue
            while read -r line; do
                case "$line" in
                    ExecStart=*|ExecStartPre=*|ExecStartPost=*)
                        cmd="${line#*=}"
                        if echo "$cmd" | grep -qE "$_writable_paths_re"; then
                            alert "Service runs from writable path: $unit (${line%%=*})"
                        fi
                        ;;
                esac
            done < "$path" 2>/dev/null || true
        done < <(systemctl list-unit-files --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1}' | grep -E '\.(service|timer)$') || true
    fi

    for cron_base in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly /var/spool/cron/crontabs; do
        [ ! -d "$cron_base" ] && continue
        while read -r f; do
            [ -z "$f" ] || [ ! -f "$f" ] && continue
            if grep -v '^[[:space:]]*#' "$f" 2>/dev/null | grep -qE "$_writable_paths_re"; then
                alert "Cron references writable path: $f"
            fi
        done < <(find "$cron_base" -type f 2>/dev/null) || true
    done
    if [ -f /etc/crontab ]; then
        grep -v '^[[:space:]]*#' /etc/crontab 2>/dev/null | grep -qE "$_writable_paths_re" && alert "Crontab references writable path: /etc/crontab" || true
    fi
}

# --- C) Writable attack surface ---
check_writable_surface() {
    section "Writable attack surface"

    # World-writable files (process substitution so FINDINGS increments in main shell)
    for base in /etc /usr/bin /usr/sbin /var/log; do
        [ ! -d "$base" ] && continue
        while read -r f; do
            [ -z "$f" ] && continue
            alert "World-writable file: $f"
        done < <(find "$base" -type f -perm -0002 2>/dev/null | head -30) || true
    done

    for base in /etc /usr /var/log; do
        [ ! -d "$base" ] && continue
        while read -r f; do
            [ -z "$f" ] && continue
            alert "World-writable dir: $f"
        done < <(find "$base" -type d -perm -0002 2>/dev/null | head -20) || true
    done

    for f in /var/log/auth.log /var/log/syslog /var/log/secure; do
        [ ! -f "$f" ] && continue
        p=$(stat -c '%a' "$f" 2>/dev/null || true)
        if [ "${p:-}" = "666" ] || [ "${p:-}" = "777" ]; then
            alert "Overly permissive log: $f ($p)"
        fi
    done

    if [ -f /etc/sudoers ]; then
        p=$(stat -c '%a' /etc/sudoers 2>/dev/null || true)
        if [ -n "${p:-}" ] && [ "$p" != "440" ] && [ "$p" != "400" ]; then
            alert "Loose /etc/sudoers: $p"
        fi
    fi
    if [ -d /etc/sudoers.d ]; then
        p=$(stat -c '%a' /etc/sudoers.d 2>/dev/null || true)
        if [ -n "${p:-}" ] && [ "$p" -gt 750 ] 2>/dev/null; then
            alert "Loose /etc/sudoers.d: $p"
        fi
    fi

    # SSH: allow sshd_config, ssh_config, moduli 644; known_hosts 644; private keys 600; .ssh dir 700
    _ssh_allow_644="sshd_config ssh_config moduli known_hosts"
    _ssh_private_pattern="id_rsa id_ed25519 id_ecdsa id_dsa id_xmss id_ed25519_sk id_ecdsa_sk"

    for base in /etc/ssh /root/.ssh; do
        [ ! -d "$base" ] && continue
        while read -r f; do
            [ -z "$f" ] && continue
            bn=$(basename "$f")
            p=$(stat -c '%a' "$f" 2>/dev/null || true)
            [ -z "${p:-}" ] && continue
            allowed_644=0
            for a in $_ssh_allow_644; do
                [ "$bn" = "$a" ] && allowed_644=1 && break
            done
            if [ "$allowed_644" -eq 1 ]; then
                [ "$p" != "644" ] && [ "$p" != "600" ] && alert "SSH config/pub perms (expected 644): $f ($p)"
            elif echo "$bn" | grep -q '\.pub$'; then
                [ "$p" != "644" ] && [ "$p" != "600" ] && alert "SSH public key perms (expected 644): $f ($p)"
            else
                is_private=0
                for pat in $_ssh_private_pattern; do
                    [ "$bn" = "$pat" ] && is_private=1 && break
                done
                if [ "$is_private" -eq 1 ]; then
                    [ "$p" != "600" ] && alert "SSH private key perms (expected 600): $f ($p)"
                else
                    [ "$p" != "600" ] && [ "$p" != "644" ] && alert "SSH file perms: $f ($p)"
                fi
            fi
        done < <(find "$base" -type f 2>/dev/null) || true
    done

    if [ -d /home ]; then
        for homedir in /home/*/; do
            [ ! -d "${homedir}.ssh" ] && continue
            dirp=$(stat -c '%a' "${homedir}.ssh" 2>/dev/null || true)
            if [ -n "${dirp:-}" ] && [ "$dirp" != "700" ]; then
                alert "SSH dir perms (expected 700): ${homedir}.ssh ($dirp)"
            fi
            while read -r f; do
                [ -z "$f" ] && continue
                bn=$(basename "$f")
                p=$(stat -c '%a' "$f" 2>/dev/null || true)
                [ -z "${p:-}" ] && continue
                allowed_644=0
                for a in $_ssh_allow_644; do [ "$bn" = "$a" ] && allowed_644=1 && break; done
                if [ "$bn" = "known_hosts" ]; then allowed_644=1; fi
                if [ "$allowed_644" -eq 1 ]; then
                    [ "$p" != "644" ] && [ "$p" != "600" ] && alert "SSH config/pub perms (expected 644): $f ($p)"
                elif echo "$bn" | grep -q '\.pub$'; then
                    [ "$p" != "644" ] && [ "$p" != "600" ] && alert "SSH public key perms (expected 644): $f ($p)"
                else
                    is_private=0
                    for pat in $_ssh_private_pattern; do [ "$bn" = "$pat" ] && is_private=1 && break; done
                    if [ "$is_private" -eq 1 ]; then
                        [ "$p" != "600" ] && alert "SSH private key perms (expected 600): $f ($p)"
                    else
                        [ "$p" != "600" ] && [ "$p" != "644" ] && alert "SSH file perms: $f ($p)"
                    fi
                fi
            done < <(find "${homedir}.ssh" -type f 2>/dev/null) || true
        done
    fi

    [ -d /root/.ssh ] && dirp=$(stat -c '%a' /root/.ssh 2>/dev/null || true) && [ -n "${dirp:-}" ] && [ "$dirp" != "700" ] && alert "SSH dir perms (expected 700): /root/.ssh ($dirp)"

    if [ -d /tmp ]; then
        p=$(stat -c '%a' /tmp 2>/dev/null || true)
        [ -n "${p:-}" ] && [ "$p" != "1777" ] && alert "/tmp missing sticky bit: $p"
    fi
    if [ -d /var/tmp ]; then
        p=$(stat -c '%a' /var/tmp 2>/dev/null || true)
        [ -n "${p:-}" ] && [ "$p" != "1777" ] && alert "/var/tmp missing sticky bit: $p"
    fi

    for base in /tmp /var/tmp /home /var/cache /var/lib; do
        [ ! -d "$base" ] && continue
        while read -r f; do
            [ -z "$f" ] && continue
            alert "Setuid/setgid in writable dir: $f"
        done < <(find "$base" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20) || true
    done
}

# --- E) Baseline drift (SUID/SGID + core binary hashes) ---
check_baseline_drift() {
    section "Baseline drift (SUID/SGID + core hashes)"

    BASE_DIR="/root/baselines"
    SUID_BASE="${BASE_DIR}/suid_sgid.list"
    HASH_BASE="${BASE_DIR}/core_bins.sha256"

    # 1) SUID/SGID drift (anywhere on root FS)
    if [ -f "$SUID_BASE" ]; then
        CUR="/tmp/suid_sgid.current"
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort > "$CUR" || true
        if ! diff -u "$SUID_BASE" "$CUR" >/tmp/suid_sgid.diff 2>/dev/null; then
            alert "SUID/SGID baseline changed! See /tmp/suid_sgid.diff"
        fi
    else
        # Not an alert; means hardening baseline not created yet
        log "No SUID baseline found at $SUID_BASE (run hardening script once to create it)"
    fi

    # 2) Core binary hash drift (sudo/su/sshd)
    if [ -f "$HASH_BASE" ]; then
        if ! sha256sum -c "$HASH_BASE" >/tmp/core_bins.hashcheck 2>&1; then
            alert "Core binary hash mismatch! See /tmp/core_bins.hashcheck"
        fi
    else
        log "No hash baseline found at $HASH_BASE (run hardening script once to create it)"
    fi
}

# --- F) PATH hijack risk (writable PATH dirs) ---
check_path_hijack_risk() {
    section "PATH hijack risk (writable PATH directories)"

    # Check root's default PATH (most important)
    root_path="$(sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin bash -lc 'echo $PATH' 2>/dev/null || echo '/usr/sbin:/usr/bin:/sbin:/bin')"

    for p in "$root_path" "$PATH"; do
        echo "$p" | tr ':' '\n' | while read -r d; do
            [ -d "$d" ] || continue
            # Flag if writable by group or others
            if find "$d" -maxdepth 0 -perm -0020 -o -perm -0002 2>/dev/null | grep -q .; then
                alert "PATH directory writable (risk): $d"
            fi
        done
    done
}

# --- D) Covert channel / unusual network ---
check_covert_network() {
    section "Covert channel / unusual network"

    _writable_bases="/tmp /var/tmp /dev/shm /var/cache /home"

    if command -v ss >/dev/null 2>&1; then
        while read -r pid; do
            [ -z "$pid" ] && continue
            [ ! -d "/proc/$pid" ] && continue
            exe=""
            [ -r "/proc/${pid}/exe" ] && exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null) || true
            [ -z "$exe" ] && continue
            cmdline=""
            [ -r "/proc/${pid}/cmdline" ] && cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null) || true
            interp=0
            echo "$exe" | grep -qE 'python|perl|ruby|bash' && interp=1
            echo "$cmdline" | grep -qE 'python|perl|ruby|bash' && interp=1
            [ "$interp" -ne 1 ] && continue
            under=0
            for base in $_writable_bases; do
                case "$exe" in
                    ${base}/*) under=1; break ;;
                esac
            done
            if [ "$under" -eq 1 ]; then
                alert "Interpreter with network from writable path: pid=$pid exe=$exe"
                continue
            fi
            for base in $_writable_bases; do
                case "$cmdline" in
                    *${base}*) under=1; break ;;
                esac
            done
            [ "$under" -eq 1 ] && alert "Interpreter script from writable path with network: pid=$pid"
        done < <(ss -tpn 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u) || true
    fi

    if command -v getcap >/dev/null 2>&1; then
        while read -r cap_line; do
            [ -z "$cap_line" ] && continue
            path="${cap_line%% =*}"
            caps="${cap_line#* = }"
            echo "$caps" | grep -qE 'cap_net_raw|cap_net_admin' || continue
            case "$path" in
                /usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*) continue ;;
            esac
            alert "Binary with cap_net_raw/cap_net_admin outside system paths: $path"
        done < <(getcap -r / 2>/dev/null | grep -E 'cap_net_raw|cap_net_admin') || true
    fi
}

# --- Summary ---
summary() {
    section "Summary"
    if [ "$FINDINGS" -eq 0 ]; then
        [ "$QUIET" -eq 0 ] && echo "No alerts. Exit 0."
        if [ "$JSON" -eq 1 ]; then
            printf '{"findings": 0, "alerts": []}\n'
        fi
        exit 0
    fi
    echo "Total findings: $FINDINGS (exit 1)"
    if [ "$JSON" -eq 1 ]; then
        printf '{"findings": %s, "alerts": [%s]}\n' "$FINDINGS" "${ALERTS_JSON:-}"
    fi
    exit 1
}

# --- Args ---
for a in "$@"; do
    case "$a" in
        --quiet) QUIET=1 ;;
        --json)  JSON=1 ;;
        -h|--help)
            echo "Usage: $0 [--quiet] [--json]"
            echo "  --quiet  Only alerts."
            echo "  --json   Print JSON summary at end."
            exit 0
            ;;
    esac
done

check_privilege_escalation
check_persistence
check_writable_surface
check_baseline_drift
check_path_hijack_risk
check_covert_network
summary