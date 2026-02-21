# Blue Team Tools (Linux)

Attack-surface reduction and monitoring: **permissions, directory hardening, mount options, process limits, kernel settings**. Target: **Debian 13, Ubuntu 24.04**. No firewall or DNS configuration.

Focus: effectiveness vs complexity, ease of use, low risk to normal operations.

## What they do

### Hardening (`linux_hardening.sh`)

| Area | Actions |
|------|--------|
| **Directories** | `/tmp`, `/var/tmp` → sticky (1777); `/var/cache/apt`, `.iocache` → 755/700; cron dirs → 755; `/var/log` → 755; **`/root` → 700**; `/boot` → 755; **`/var/spool/cron`(crontabs) → 750**; **`/etc/ld.so.conf.d`, `/etc/pam.d`, `/etc/security`, `/etc/apparmor.d` → 755**; **`/etc/apt/trusted.gpg.d`, `sources.list.d` → 755** |
| **Files** | Log files → 640; sudoers/sudoers.d → 440/750; SSH configs 644, host keys 600; **`/etc/shadow`, `/etc/gshadow` → 640**; **`/etc/crontab` → 640**; **`/root/.ssh` → 700**; **APT trusted GPG keys → 644** |
| **Home dirs** | Warn on loose home dirs (777/775); suggest 750 |
| **World-writable** | Report world-writable files under `/etc`, `/usr/bin`, `/usr/sbin`, `/var/log` |
| **Mounts** | **Check `/tmp`, `/var/tmp`, `/dev/shm` mount options; suggest nosuid (and noexec for /dev/shm)** |
| **Process limits** | `limits.d` nproc (512/1024); **core dumps disabled** (`98-blue-team-core.conf`: core 0) |
| **Kernel/sysctl** | `sysctl.d`: kptr_restrict, dmesg_restrict, ptrace_scope, ASLR, mmap_min_addr, **fs.suid_dumpable=0** |
| **Debian/Ubuntu** | **`/var/lib/dpkg/info` 755 if 777; `/etc/init.d` 755** |
| **Sudo** | Check for moved real sudo, debsums, credential dumps |
| **Persistence** | Warn on known-bad systemd units |

### Monitoring (`linux_monitor.sh`)

| Area | Checks |
|------|--------|
| **Permissions** | World-writable files/dirs in `/etc`, `/usr`, `/var/log`; loose log files; sudoers/sudoers.d; SSH key and `.ssh` dir perms; `/tmp`/`/var/tmp` sticky bit; setuid/setgid under `/tmp`, `/var/tmp`, `/home`, `/var/cache/apt` |
| **Artifacts** | payloads, ghost processes, high process count, sudo paths, C2-related scripts/services |

Both scripts are **idempotent** and avoid firewall/DNS changes.

## Usage

### Hardening (run as root)

```bash
sudo ./linux_hardening.sh
```

Safe to run repeatedly. Only applies permission and config changes listed above. **Each change is appended to a log file** so you can see what was done:

- Default log: `/var/log/blue_team_hardening.log`
- Override: `BLUE_TEAM_LOG=/path/to/log sudo ./linux_hardening.sh`

**Check that hardening worked (read-only, no changes):**

```bash
sudo ./linux_hardening.sh --verify
```

This prints the current state of every path and config the script hardens (e.g. `/tmp 1777 OK` or `(expected 1777)`). Use it before/after a run to confirm.

### Monitoring (read-only; root recommended)

```bash
sudo ./linux_monitor.sh        # Full output
sudo ./linux_monitor.sh --quiet   # Only alerts
```

Exit code: **0** if no findings, **1** if any (for automation).

**Cron example (every 15 minutes):**

```bash
*/15 * * * * root /path/to/blue_team_tools/linux_monitor.sh 2>&1 | tee -a /var/log/blue_team_monitor.log
```

## Requirements

- Linux: **Debian 13**, **Ubuntu 24.04** (script is tuned for these)
- Root for hardening and for full monitoring (e.g. `/proc`, systemd)
- Optional: `debsums` for sudo binary verification (`apt install debsums`)

**Mount options:** The script only *checks* and *warns* about `/tmp`, `/var/tmp`, `/dev/shm`. To apply `nosuid` (and for `/dev/shm` also `noexec`), add or adjust entries in `/etc/fstab` and reboot or remount. The script does not modify fstab.

## Safety

- **Hardening**: Only tightens permissions and adds one limits file and one sysctl.d file; suggests manual steps for things like restoring sudo.
- **Monitoring**: Read-only; no changes to the system.
