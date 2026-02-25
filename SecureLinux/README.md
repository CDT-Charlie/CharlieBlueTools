# SecureLinux – Blue Team Linux Hardening

Linux counterpart to **SecureWin.ps1** for the CDT Blue vs Red competition (Team Charlie, Spring 2026). It hardens SSH, firewall, user accounts, and scored services on Linux hosts. **Access to Linux infrastructure is SSH-only**; this script never disables or breaks SSH.

---

## What It Does

| Phase | Description |
|-------|-------------|
| **1 – User account management** | Removes unauthorized local users; keeps competition users, greyteam, scoring, and your blue team admins. Ensures authorized admins exist and are in `sudo`. |
| **2 – Password policy** | Sets `PASS_MAX_DAYS`, `PASS_MIN_LEN`, etc. in `/etc/login.defs` and applies `chage` to existing users. **Does not modify PAM** (`/etc/pam.d/common-auth`, `common-account`, `common-password`). |
| **3 – Firewall** | Configures **ufw**: default deny incoming, allow SSH (22) first, then service-specific ports and safe IPs/ranges. Interactive menu to choose which scored service runs on the host. |
| **4 – SSH hardening** | Updates `sshd_config` (e.g. `PermitRootLogin prohibit-password`, `MaxAuthTries 3`). **Runs `sshd -t` before reload** so bad config is not applied. |
| **5 – Network hardening** | Drops a sysctl file (e.g. rp_filter, syncookies, no source routing). |
| **6 – Backdoor detection** | Scans cron and systemd for suspicious entries. **Skips any artifact whose name contains `greyteam` or `grayteam`** (Rule 5). |
| **7 – Audit / logging** | Ensures auth logging (e.g. rsyslog → `/var/log/auth.log`) is in place. |

---

## Competition rules compliance

| Rule | Requirement | How the script complies |
|------|-------------|---------------------------|
| **5** | Do not attack out-of-scope infra; do not modify artifacts with “greyteam” in their name | greyteam/grayteam users and cron/systemd paths containing “greyteam”/“grayteam” are never modified; `/greyteam_key` is never touched (Phase 6 logs it and skips). |
| **6** | Do not migrate scored services to other hosts | Script only configures firewall for the service you select on *this* host; it does not move or reinstall services. |
| **7** | No subnet blocking (no firewall rules that block a large contiguous IP range) | Only **allow** rules are used (ports, specific IPs, specific ranges). No deny rules on subnets. |
| **8** | No physical tampering with devices | Script is software-only; no physical actions. |
| **9** | Do not disable any valid packet user; packet admin users must keep admin | All packet users and greyteam/scoring are in `SAFE_USERS` and are never removed or disabled. Sudo is only *added* for blue team admins; existing sudo membership is not stripped. |
| **10** | Do not disable SSH on Linux (or RDP on Windows) | SSH is only **hardened** (Phase 4); it is never disabled or blocked. |
| **11** | No irreversible changes (no disk wipe, scored service uninstall, full encryption) | `userdel` is used without `-r` (no home wipe); no service uninstalls; no encryption. |
| **12** | Tools must be publicly accessible | Script is plain bash and standard Linux tools (ufw, sshd, chage, etc.). |
| **13** | No VirusTotal, cloud AV, Windows Defender | Script does not use any of these. |
| **14** | Password changes limited to 3 per host per comp session | Script logs a Rule 14 reminder when creating an admin (each new admin password counts as one). Operator must ensure total password changes per host per session stay ≤ 3. |
| **15** | `/greyteam_key` (Linux) must not be modified | Script never modifies or deletes `/greyteam_key`; Phase 6 only checks for its presence and logs that it is left unchanged. |
| **16** | Blue Team may request up to 3 host reverts per day | No script logic; operator responsibility. |

---

## Critical Design Choices

- **SSH-only access**  
  SSH is the only way onto Linux. The script hardens SSH; it does not disable or restrict it in a way that would lock you out.

- **No PAM edits**  
  Modifying `/etc/pam.d/common-auth`, `common-account`, or `common-password` has broken **all** PAM authentication in the past. This script **does not touch those files**. Password policy is done only via:
  - `/etc/login.defs`
  - `chage` for existing users

- **Config syntax checks**  
  Before applying SSH changes, the script runs **`sshd -t`**. If the check fails, it restores the previous `sshd_config` and does not reload sshd. Use this pattern for any manual SSH (or other critical) config changes.

- **greyteam and scoring**  
  Users such as **greyteam** and **scoring** may not appear in the written “authorized” list in the packet but must remain valid. The script always treats them as protected and does not remove them or make global user/SSH changes that would break their use.

- **Deprecated SSH options**  
  Avoid deprecated `sshd_config` options (e.g. `HostRSAAuthentication`). The script uses current options only. When editing SSH config by hand, run `sshd -t` after changes.

---

## Before Running

1. **Edit the script**  
   Set at the top:
   - `AUTHORIZED_ADMINS` – your blue team usernames (will be given sudo).
   - `SET_ALL_USER_PASSWORDS` – your team password (subject to max 3 password changes per host per comp session).
   - `SAFE_IP_ADDRESSES` / `SAFE_IP_RANGES` – scoring engine, jumpboxes, etc. (already pre-filled for the competition).

2. **Run as root**  
   Use `sudo ./SecureLinux.sh` (or run as root). The script checks for root and exits if not.

3. **Keep an SSH session open**  
  Run from a terminal that will stay connected until you’ve confirmed SSH still works (e.g. from a second session or jumpbox).

---

## Usage

```bash
# Run all phases (default)
sudo ./SecureLinux.sh

# Run all phases explicitly
sudo ./SecureLinux.sh --all

# Run only specific phases
sudo ./SecureLinux.sh --phase 3
sudo ./SecureLinux.sh --phases 1,4,7

# See what would be done (where supported)
sudo ./SecureLinux.sh --dry-run
```

Logs are written under `/var/log/BlueTeam/`; a run counter is stored in `/var/lib/BlueTeam/script-run-counter.txt`.

---

## Scored Linux Services (for firewall phase)

When prompted, choose the service that runs on **this** host so only the right ports are opened:

| Option | Host (example) | Service  | Ports   |
|--------|----------------|----------|---------|
| 1      | ponyville      | Apache2  | 80, 443 |
| 2      | seaddle        | MariaDB  | 3306    |
| 3      | trotsylvania   | CUPS     | 631     |
| 4      | crystal-empire | vsftpd   | 21      |
| 5      | everfree-forest| IRC      | 6667    |
| 6      | griffonstone   | Nginx    | 80, 443 |
| 7      | Workstation    | (none)   | SSH only|

---

## Testing and Safety

- **Test on a lab or clone first** – especially user removal and firewall.
- **Verify SSH** in another session after running (especially after Phase 4). If `sshd -t` fails, the script restores the previous config and does not reload.
- **User list** – ensure `SAFE_USERS` (and the script’s built-in protection for greyteam/scoring) matches every account that must keep access, including any not explicitly listed in the packet.
- **PAM** – if you ever need to change PAM, do it only after thorough testing and with a backup; this script intentionally does not touch it.

---

## Relation to SecureWin.ps1

- **SecureWin.ps1** (Windows): removes SSH, keeps RDP, manages Windows users/firewall/GPO-style hardening.
- **SecureLinux.sh** (this): keeps and hardens SSH (no SSH removal), uses ufw and login.defs, and does not modify PAM.

Both scripts respect competition rules (e.g. Rule 5 – greyteam, Rule 7 – no full subnet blocking, Rule 9 – do not disable valid users) and the same safe IP list and authorized admins concept.
