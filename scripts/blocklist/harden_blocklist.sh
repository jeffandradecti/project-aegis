#!/bin/bash
# ==============================================================================
# Project Aegis - Droplet Hardening Script
# Description: Automates defense-in-depth for the Threat Intel Web Server
# ==============================================================================

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root."
  exit 1
fi

echo "[*] Starting Project Aegis Hardening Process..."

# ------------------------------------------------------------------------------
# 1. Install Required Security Packages
# ------------------------------------------------------------------------------
echo "[*] Installing security packages (Fail2Ban, Auditd, AppArmor, UFW)..."
apt-get update -qq
apt-get install -y fail2ban auditd ufw apparmor-profiles apparmor-utils unattended-upgrades -qq

# Enable automatic unattended security upgrades
echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades

# ------------------------------------------------------------------------------
# 2. Least Privilege (Service Account & Permissions)
# ------------------------------------------------------------------------------
echo "[*] Configuring dedicated aegis_svc user and file permissions..."
if ! id "aegis_svc" &>/dev/null; then
    useradd -m -s /bin/bash aegis_svc
fi

# Ensure project directory exists in the new home folder
mkdir -p /home/aegis_svc/aegis
# Move existing data if it's still in /root
if [ -d "/root/aegis/scripts" ]; then
    cp -r /root/aegis/* /home/aegis_svc/aegis/
fi

# Set core project permissions
chown -R aegis_svc:aegis_svc /home/aegis_svc/aegis

# Set web directory permissions (Aegis writes, Nginx reads)
mkdir -p /var/www/html/threatintel
chown -R aegis_svc:www-data /var/www/html/threatintel
chmod 750 /var/www/html/threatintel

# ------------------------------------------------------------------------------
# 3. Network & Kernel Hardening (sysctl & modprobe)
# ------------------------------------------------------------------------------
echo "[*] Applying Sysctl network hardening and disabling IPv6..."
cat << 'EOF' > /etc/sysctl.d/99-aegis-hardening.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl --system > /dev/null

echo "[*] Blacklisting obscure kernel modules..."
cat << 'EOF' > /etc/modprobe.d/aegis-hardening.conf
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
EOF

# ------------------------------------------------------------------------------
# 4. SSH Hardening
# ------------------------------------------------------------------------------
echo "[*] Hardening SSH daemon..."
sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^#*LoginGraceTime .*/LoginGraceTime 30s/' /etc/ssh/sshd_config
sed -i 's/^#*MaxAuthTries .*/MaxAuthTries 3/' /etc/ssh/sshd_config
systemctl restart ssh

# ------------------------------------------------------------------------------
# 5. Nginx Hardening
# ------------------------------------------------------------------------------
echo "[*] Hardening Nginx (Server Tokens & Security Headers)..."
# Hide Nginx version
sed -i 's/# server_tokens off;/server_tokens off;/' /etc/nginx/nginx.conf

# Add security headers and method restrictions to the default site
# Note: This simply injects the headers right after the server_name directive
sed -i '/server_name _;/a \
    \n    # Project Aegis Hardening\n    if ($request_method !~ ^(GET|HEAD)$ ) {\n        return 405;\n    }\n    add_header X-Content-Type-Options nosniff;\n    add_header X-Frame-Options DENY;\n    add_header X-XSS-Protection "1; mode=block";\n' /etc/nginx/sites-available/default

systemctl restart nginx

# ------------------------------------------------------------------------------
# 6. Sandboxed Systemd Timer
# ------------------------------------------------------------------------------
echo "[*] Creating sandboxed Systemd Service and Timer..."
cat << 'EOF' > /etc/systemd/system/aegis-processor.service
[Unit]
Description=Project Aegis Intelligence Processor
After=network.target

[Service]
Type=oneshot
User=aegis_svc
Group=aegis_svc
WorkingDirectory=/home/aegis_svc/aegis/scripts
ExecStart=/bin/bash -c '../venv/bin/python parser.py && ../venv/bin/python exporter.py'

# Sandboxing
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
ProtectHome=read-only
ReadWritePaths=/home/aegis_svc/aegis/data /var/www/html/threatintel
EOF

cat << 'EOF' > /etc/systemd/system/aegis-processor.timer
[Unit]
Description=Run Aegis Processor Hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now aegis-processor.timer
# Remove root cron just in case it still exists
crontab -r 2>/dev/null

# ------------------------------------------------------------------------------
# 7. Auditd Monitoring (.env File)
# ------------------------------------------------------------------------------
echo "[*] Setting up Auditd rules for AWS keys..."
cat << 'EOF' > /etc/audit/rules.d/aegis.rules
-w /home/aegis_svc/aegis/.env -p rwa -k aegis_aws_keys_accessed
EOF
systemctl restart auditd

# ------------------------------------------------------------------------------
# 8. Strict Egress Filtering (UFW)
# ------------------------------------------------------------------------------
echo "[*] Configuring UFW (Default Deny In/Out)..."
ufw --force reset
ufw default deny incoming
ufw default deny outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow out 53
ufw allow out 80/tcp
ufw allow out 443/tcp
ufw --force enable

# ------------------------------------------------------------------------------
# 9. AppArmor Preparation
# ------------------------------------------------------------------------------
echo "[*] Setting Nginx AppArmor profile to complain mode..."
aa-complain /usr/sbin/nginx 2>/dev/null

echo "=========================================================================="
echo "[+] Hardening Complete!"
echo "=========================================================================="
echo "[!] IMPORTANT NEXT STEP: AppArmor needs to learn Nginx's behavior."
echo "    Run the following command, then browse to your blocklist URL:"
echo "    sudo aa-logprof"
echo "    Press 'A' to allow required paths, then enforce it with:"
echo "    sudo aa-enforce /usr/sbin/nginx"
echo "=========================================================================="