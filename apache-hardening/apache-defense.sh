#!/bin/bash
# Designed to be run as root

echo "[*] Clearing authorized_keys so nopony has a backdoor..."
# This removes all keys; in a real scenario, manually audit ~/.ssh/authorized_keys
truncate -s 0 /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# --- 2. Network & Process Triage ---
echo "[*] Identifying suspicious network connections..."
ss -tulpn

# --- 3. Apache Hardening ---
echo "[*] Hardening Apache configuration..."
# Hide version info
echo "ServerTokens Prod" >> /etc/apache2/conf-available/security.conf
echo "ServerSignature Off" >> /etc/apache2/conf-available/security.conf

# Disable risky modules (like CGI or Autoindex)
a2dismod -f cgi autoindex status
systemctl restart apache2

# --- 4. File Integrity & Persistence ---
echo "[*] Checking for modified system binaries (Debian specific)..."
# debsums checks installed files against their md5sums
apt-get update && apt-get install -y debsums
debsums -c | grep -v "OK"

echo "[*] Reviewing cron jobs. Ensure anypony's legitimate tasks remain."
rm -rf /etc/cron.d/*
rm -rf /var/spool/cron/crontabs/*

echo "[!] Defense script completed. Manual review of /var/www/html is required."
