#!/bin/bash

#########################################
# Fullstack VPS Hardening & Docker Setup Script
# For Ubuntu/Debian based systems
# Includes: Security hardening + Nginx + Docker + PostgreSQL + Node.js Apps
#########################################

# Don't use set -e for the entire script as it causes issues with UFW commands
set -uo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
SSH_PORT=${SSH_PORT:-22}
ADMIN_EMAIL=${ADMIN_EMAIL:-""}
ENABLE_CLOUDFLARE=${ENABLE_CLOUDFLARE:-"yes"}
# TLS/HTTPS configuration
ENABLE_TLS=${ENABLE_TLS:-"no"}
DOMAIN=${DOMAIN:-""}
DOMAIN_ALIASES=${DOMAIN_ALIASES:-""} # space-separated list
CERTBOT_EMAIL=${CERTBOT_EMAIL:-""}
CERTBOT_STAGING=${CERTBOT_STAGING:-"no"}
# Cloudflare Real IP support (restore original client IPs in Nginx)
ENABLE_CLOUDFLARE_REAL_IP=${ENABLE_CLOUDFLARE_REAL_IP:-"yes"}

DB_NAME="appdb"
DB_USER="appuser"
# Generate a safe password without problematic characters
DB_PASS=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 20)
APP_PORT=${APP_PORT:-3000}
API_PORT=${API_PORT:-3001}

# Paths
APP_DIR="/var/www/app"
LOG_FILE="/var/log/vps-setup.log"

# Function to log messages
log_message() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO:${NC} $1" | tee -a "$LOG_FILE"
}

# Ensure nginx.conf includes sites-enabled (so our vhosts load)
ensure_sites_enabled_included() {
  if ! grep -qE "include\s+/etc/nginx/sites-enabled/\*;" /etc/nginx/nginx.conf; then
    log_warning "Adding include /etc/nginx/sites-enabled/*; to nginx.conf http block"
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.$(date +%F-%H%M)
    sed -i '/http\s*{/a\    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
  fi
}

# After Certbot configures HTTPS, add HSTS + OCSP stapling to the TLS server block
harden_tls_server_block() {
  local conf="/etc/nginx/sites-available/app"
  if [ ! -f "$conf" ]; then
    log_warning "Nginx site $conf not found; skipping TLS hardening"
    return 0
  fi
  if ! grep -qE "listen[[:space:]]+443" "$conf"; then
    log_warning "No TLS (443) server block found in $conf; skipping TLS hardening"
    return 0
  fi
  cp "$conf" "$conf.bak.$(date +%F-%H%M)"

  # Choose anchor: prefer ssl_certificate_key; fallback to options-ssl include
  local anchor_regex='ssl_certificate_key'
  if ! grep -q "$anchor_regex" "$conf"; then
    anchor_regex='include[[:space:]]+/etc/letsencrypt/options-ssl-nginx\.conf;'
  fi

  # Add HSTS if missing
  if ! grep -q "Strict-Transport-Security" "$conf"; then
    sed -i -E "/$anchor_regex/a\\    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;" "$conf" || true
  fi

  # Add OCSP stapling/resolver if missing
  if ! grep -q "ssl_stapling on;" "$conf"; then
    sed -i -E "/$anchor_regex/a\\    resolver_timeout 5s;" "$conf" || true
    sed -i -E "/$anchor_regex/a\\    resolver 1.1.1.1 1.0.0.1 valid=300s;" "$conf" || true
    sed -i -E "/$anchor_regex/a\\    ssl_stapling_verify on;" "$conf" || true
    sed -i -E "/$anchor_regex/a\\    ssl_stapling on;" "$conf" || true
  fi

  if nginx -t; then
    systemctl reload nginx
  else
    log_warning "TLS hardening changes caused nginx -t to fail; restoring backup"
    mv -f "$conf.bak.$(date +%F-%H%M)" "$conf" || true
    nginx -t && systemctl reload nginx || true
  fi
}

# Interactive prompting helpers
PROMPT_ALL=${PROMPT_ALL:-yes}

is_interactive() {
  [ -t 0 ]
}

prompt_with_default() {
  # $1 var name, $2 prompt text, $3 default value (may be empty string)
  local var_name="$1"; shift
  local prompt_text="$1"; shift
  local default_val="${1:-}"
  local current_val="${!var_name-}"
  local shown_default
  if [ -n "$current_val" ]; then
    shown_default="$current_val"
  else
    shown_default="$default_val"
  fi
  if [ -n "$shown_default" ]; then
    read -rp "$prompt_text [$shown_default]: " input
    input="${input:-$shown_default}"
  else
    read -rp "$prompt_text: " input
  fi
  # Trim whitespace
  input="$(echo "$input" | xargs)"
  eval "$var_name=\"$input\""
}

secure_prompt() {
  # $1 var name, $2 prompt text
  local var_name="$1"; shift
  local prompt_text="$1"; shift
  read -rsp "$prompt_text: " input
  echo
  eval "$var_name=\"$input\""
}

confirm_yes() {
  # $1 prompt text, default Y
  local prompt_text="$1"; shift
  read -rp "$prompt_text [Y/n]: " ans
  ans=${ans:-Y}
  case "$ans" in
    y|Y|yes|YES) return 0;;
    *) return 1;;
  esac
}

collect_configuration() {
  if ! is_interactive || [ "$PROMPT_ALL" != "yes" ]; then
    return 0
  fi
  echo
  echo "=== Interactive configuration ==="
  prompt_with_default SSH_PORT "SSH port" "$SSH_PORT"
  prompt_with_default ADMIN_EMAIL "Admin email (for notifications)" "$ADMIN_EMAIL"
  prompt_with_default ENABLE_CLOUDFLARE "Enable Cloudflare UFW IP rules? (yes/no)" "$ENABLE_CLOUDFLARE"
  prompt_with_default ENABLE_CLOUDFLARE_REAL_IP "Enable Cloudflare Real IP in Nginx? (yes/no)" "$ENABLE_CLOUDFLARE_REAL_IP"
  prompt_with_default ENABLE_TLS "Enable TLS/HTTPS with Let's Encrypt? (yes/no)" "$ENABLE_TLS"
  if [ "$ENABLE_TLS" = "yes" ]; then
    # DOMAIN and CERTBOT_EMAIL required if TLS enabled
    while :; do
      prompt_with_default DOMAIN "Primary domain (e.g., example.com)" "$DOMAIN"
      [ -n "$DOMAIN" ] && break
      echo "Domain is required when TLS is enabled."
    done
    prompt_with_default DOMAIN_ALIASES "Domain aliases (space-separated, can be blank)" "$DOMAIN_ALIASES"
    while :; do
      prompt_with_default CERTBOT_EMAIL "Email for Let's Encrypt registration" "$CERTBOT_EMAIL"
      [ -n "$CERTBOT_EMAIL" ] && break
      echo "Certbot email is required when TLS is enabled."
    done
    prompt_with_default CERTBOT_STAGING "Use Let's Encrypt staging? (yes/no)" "$CERTBOT_STAGING"
  fi
  prompt_with_default APP_PORT "Frontend port on localhost (host: ${APP_PORT})" "$APP_PORT"
  prompt_with_default API_PORT "API port on localhost (host: ${API_PORT})" "$API_PORT"
  prompt_with_default DB_NAME "Database name" "$DB_NAME"
  prompt_with_default DB_USER "Database user" "$DB_USER"
  if confirm_yes "Auto-generate a random database password?"; then
    : # keep generated DB_PASS
  else
    while :; do
      secure_prompt DB_PASS "Enter database password"
      [ -n "$DB_PASS" ] && break
      echo "Database password cannot be empty."
    done
  fi

  echo
  echo "Selected configuration:"
  echo "  SSH_PORT                  : $SSH_PORT"
  echo "  ADMIN_EMAIL               : ${ADMIN_EMAIL:-<none>}"
  echo "  ENABLE_CLOUDFLARE         : $ENABLE_CLOUDFLARE"
  echo "  ENABLE_CLOUDFLARE_REAL_IP : $ENABLE_CLOUDFLARE_REAL_IP"
  echo "  ENABLE_TLS                : $ENABLE_TLS"
  if [ "$ENABLE_TLS" = "yes" ]; then
    echo "  DOMAIN                    : $DOMAIN"
    echo "  DOMAIN_ALIASES            : ${DOMAIN_ALIASES:-<none>}"
    echo "  CERTBOT_EMAIL             : $CERTBOT_EMAIL"
    echo "  CERTBOT_STAGING           : $CERTBOT_STAGING"
  fi
  echo "  APP_PORT                  : $APP_PORT"
  echo "  API_PORT                  : $API_PORT"
  echo "  DB_NAME                   : $DB_NAME"
  echo "  DB_USER                   : $DB_USER"
  echo "  DB_PASS                   : ********"
  echo
  confirm_yes "Proceed with these settings?" || { echo "Aborted by user."; exit 1; }
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

# Create log file
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"

# Collect interactive configuration if running in a TTY and PROMPT_ALL=yes
collect_configuration

log_message "Starting VPS setup and hardening with Docker..."
log_message "Configuration: SSH_PORT=$SSH_PORT, ENABLE_CLOUDFLARE=$ENABLE_CLOUDFLARE, ENABLE_TLS=$ENABLE_TLS, DOMAIN=${DOMAIN:-unset}, ENABLE_CLOUDFLARE_REAL_IP=${ENABLE_CLOUDFLARE_REAL_IP}"

#########################################
# PART 1: SYSTEM HARDENING
#########################################

log_message "=== PART 1: SYSTEM HARDENING ==="

# Update system
log_message "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq

# Install essential packages
log_message "Installing essential packages..."
apt-get install -y -q \
    curl \
    wget \
    git \
    ufw \
    unattended-upgrades \
    apt-listchanges \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common \
    iptables-persistent \
    rsyslog \
    logrotate

# Configure automatic security updates
log_message "Configuring automatic security updates..."
cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOCONFIG'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
    "${distro_id}:${distro_codename}-updates";
};
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOCONFIG

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOCONFIG'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOCONFIG

# SSH Hardening
log_message "Hardening SSH configuration..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

groupadd -f sshusers
usermod -a -G sshusers root

# Add common users to sshusers
for user in ubuntu debian admin; do
    if id "$user" &>/dev/null; then
        usermod -a -G sshusers "$user"
        log_message "Added $user to sshusers group"
    fi
done

mkdir -p /etc/ssh/sshd_config.d/
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOCONFIG
Port $SSH_PORT
Protocol 2
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
AllowGroups sshusers
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
X11Forwarding no
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
UsePAM yes
Banner /etc/issue.net
EOCONFIG

# Install Fail2ban
log_message "Installing and configuring Fail2ban..."
apt-get install -y -q fail2ban

cat > /etc/fail2ban/jail.local <<EOCONFIG
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

# SSH Protection - Critical
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200

[sshd-ddos]
enabled = true
port = $SSH_PORT
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 10
bantime = 3600

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = iptables-allports[name=recidive]
bantime = 86400
maxretry = 3
EOCONFIG

# Create SSH DDoS filter
cat > /etc/fail2ban/filter.d/sshd-ddos.conf <<'EOCONFIG'
[Definition]
failregex = ^.*sshd.*: (Connection closed by|Received disconnect from|Connection reset by) <HOST>.*$
            ^.*sshd.*: (Did not receive identification string from) <HOST>.*$
ignoreregex =
EOCONFIG

# Restart services
systemctl restart sshd
systemctl enable fail2ban
systemctl restart fail2ban

# Configure UFW Firewall
log_message "Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH
ufw allow $SSH_PORT/tcp comment 'SSH'

# Allow HTTP and HTTPS
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

# Cloudflare IPs (if enabled)
if [ "$ENABLE_CLOUDFLARE" = "yes" ]; then
    log_message "Adding Cloudflare IP ranges to firewall..."
    
    # Cloudflare IPv4 ranges
    for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
        ufw allow from $ip to any port 80 proto tcp comment 'Cloudflare IPv4'
        ufw allow from $ip to any port 443 proto tcp comment 'Cloudflare IPv4'
    done
    
    # Cloudflare IPv6 ranges
    for ip in $(curl -s https://www.cloudflare.com/ips-v6); do
        ufw allow from $ip to any port 80 proto tcp comment 'Cloudflare IPv6'
        ufw allow from $ip to any port 443 proto tcp comment 'Cloudflare IPv6'
    done
fi

# Enable UFW
echo "y" | ufw enable

# Kernel hardening
log_message "Applying kernel hardening parameters..."
cat > /etc/sysctl.d/99-security.conf <<'EOCONFIG'
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore Directed pings
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Accept ICMP redirects only for gateways listed in default gateway list
net.ipv4.conf.all.secure_redirects = 1

# Enable packet forwarding required for Docker networking
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 0

# Enable TCP/IP SYN cookies
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Increase system file descriptor limit
fs.file-max = 65535

# Increase number of incoming connections
net.core.somaxconn = 65535

# Docker specific settings
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOCONFIG

# Load sysctl settings
sysctl -p /etc/sysctl.d/99-security.conf

# Create login banner
cat > /etc/issue.net <<'EOCONFIG'
***************************************************************************
                            AUTHORIZED ACCESS ONLY
***************************************************************************
This system is for authorized use only. All activity is monitored and logged.
Unauthorized access attempts will be investigated and reported to authorities.
***************************************************************************
EOCONFIG

#########################################
# PART 2: DOCKER INSTALLATION
#########################################

log_message "=== PART 2: DOCKER INSTALLATION ==="

# Install Docker
log_message "Installing Docker..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -qq
apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start and enable Docker
systemctl start docker
systemctl enable docker

# Configure Docker for security
log_message "Configuring Docker security..."
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOCONFIG'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "iptables": true,
  "live-restore": true,
  "userland-proxy": false
}
EOCONFIG

systemctl restart docker

#########################################
# PART 3: NGINX SETUP (HOST)
#########################################

log_message "=== PART 3: NGINX SETUP ==="

# Install Nginx
log_message "Installing Nginx..."
apt-get install -y -q nginx

# Ensure nginx loads sites-enabled vhosts
ensure_sites_enabled_included

# Remove default site
rm -f /etc/nginx/sites-enabled/default

# Compute server_name for Nginx
SERVER_NAME="_"
if [ -n "$DOMAIN" ]; then
  SERVER_NAME="$DOMAIN"
  if [ -n "$DOMAIN_ALIASES" ]; then
    SERVER_NAME="$SERVER_NAME $DOMAIN_ALIASES"
  fi
fi

# Create Nginx configuration for Docker apps
cat > /etc/nginx/sites-available/app <<EOCONFIG
# Rate limiting zones
limit_req_zone \$binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone \$binary_remote_addr zone=api:10m rate=30r/s;
limit_conn_zone \$binary_remote_addr zone=addr:10m;

# Upstream for Docker containers
upstream frontend {
    server 127.0.0.1:${APP_PORT};
}

upstream api {
    server 127.0.0.1:${API_PORT};
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name ${SERVER_NAME};

    # If present, apply Cloudflare Real IP config
    include /etc/nginx/conf.d/cloudflare-real-ip.conf;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Rate limiting
    limit_req zone=general burst=20 nodelay;
    limit_conn addr 10;

    # Logging
    access_log /var/log/nginx/app_access.log;
    error_log /var/log/nginx/app_error.log;

    # Frontend proxy
    location / {
        proxy_pass http://frontend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_read_timeout 90;
    }

    # API proxy with higher rate limit
    location /api {
        limit_req zone=api burst=50 nodelay;

        proxy_pass http://api;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 90;
    }

    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOCONFIG

# Enable site
ln -s /etc/nginx/sites-available/app /etc/nginx/sites-enabled/ 2>/dev/null || true

# Test and reload Nginx
nginx -t && systemctl reload nginx
systemctl enable nginx

# Cloudflare Real IP support (place in http context via conf.d)
if [ "$ENABLE_CLOUDFLARE_REAL_IP" = "yes" ]; then
  log_message "Configuring Cloudflare Real IP support for Nginx..."
  cat > /usr/local/bin/update-cloudflare-real-ip.sh <<'EOS'
#!/bin/bash
set -euo pipefail
TARGET="/etc/nginx/conf.d/cloudflare-real-ip.conf"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
{
  echo "# Cloudflare Real IP ranges - auto-generated"
  echo "# See: https://www.cloudflare.com/ips/"
  echo "real_ip_header CF-Connecting-IP;"
  echo "real_ip_recursive on;"
  curl -fsS https://www.cloudflare.com/ips-v4 | awk '{print "set_real_ip_from "$1";"}'
  curl -fsS https://www.cloudflare.com/ips-v6 | awk '{print "set_real_ip_from "$1";"}'
} > "$TMP"
if [ ! -f "$TARGET" ] || ! diff -q "$TMP" "$TARGET" >/dev/null 2>&1; then
  install -m 0644 "$TMP" "$TARGET"
  nginx -t && systemctl reload nginx || true
fi
exit 0
EOS
  chmod +x /usr/local/bin/update-cloudflare-real-ip.sh
  /usr/local/bin/update-cloudflare-real-ip.sh || log_warning "Failed to update Cloudflare real IP list"
  # Refresh daily at 03:15, avoid duplicate cron lines
  tmp_cron="$(mktemp)"; crontab -l 2>/dev/null > "$tmp_cron" || true
  if ! grep -q "/usr/local/bin/update-cloudflare-real-ip.sh" "$tmp_cron"; then
    echo "15 3 * * * /usr/local/bin/update-cloudflare-real-ip.sh >/dev/null 2>&1" >> "$tmp_cron"
    crontab "$tmp_cron"
  fi
  rm -f "$tmp_cron"
else
  log_info "Cloudflare Real IP support disabled (ENABLE_CLOUDFLARE_REAL_IP=no)."
fi

# Optional TLS setup using Let's Encrypt Certbot
if [ "$ENABLE_TLS" = "yes" ]; then
  if [ -z "$DOMAIN" ] || [ -z "$CERTBOT_EMAIL" ]; then
    log_error "ENABLE_TLS is 'yes' but DOMAIN or CERTBOT_EMAIL is not set. Skipping TLS setup."
  else
    log_message "Installing/Configuring HTTPS for: $DOMAIN ${DOMAIN_ALIASES}"
    # Ensure certbot and nginx plugin are installed
    apt-get install -y -q certbot python3-certbot-nginx
    domains_args=""
    for d in $DOMAIN $DOMAIN_ALIASES; do
      domains_args="$domains_args -d $d"
    done
    staging_flag=""
    if [ "$CERTBOT_STAGING" = "yes" ]; then
      staging_flag="--staging"
      log_warning "Using Let's Encrypt staging environment (no trusted certs)."
    fi
    # Obtain/renew certs and update Nginx with HTTPS + redirect
    if certbot --nginx ${domains_args} --non-interactive --agree-tos -m "$CERTBOT_EMAIL" --redirect ${staging_flag}; then
      log_message "TLS certificates obtained and Nginx configured for HTTPS."
      # Apply HSTS + OCSP stapling on the TLS server block
      harden_tls_server_block
      nginx -t && systemctl reload nginx
    else
      log_error "Certbot failed to obtain certificates. Check DNS records and that ports 80/443 are reachable."
    fi
  fi
else
  log_info "TLS is disabled (ENABLE_TLS=no). Skipping Certbot/HTTPS setup."
fi

#########################################
# PART 4: APPLICATION SETUP WITH DOCKER
#########################################

log_message "=== PART 4: APPLICATION SETUP WITH DOCKER ==="

# Create app directory structure
log_message "Creating application structure..."
mkdir -p $APP_DIR/{api,frontend,postgres-data}
cd $APP_DIR

# Create .env file for Docker Compose
cat > .env <<EOFILE
# Database
POSTGRES_DB=$DB_NAME
POSTGRES_USER=$DB_USER
POSTGRES_PASSWORD=$DB_PASS
DB_HOST=postgres
DB_PORT=5432

# API
API_PORT=$API_PORT
NODE_ENV=production

# Frontend
APP_PORT=$APP_PORT
NEXT_PUBLIC_API_URL=http://localhost/api
EOFILE

# Create Docker Compose file (use prebuilt images, no Dockerfiles)
cat > docker-compose.yml <<'EOFILE'
services:
  postgres:
    image: postgres:16-alpine
    container_name: app-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - ./postgres-data:/var/lib/postgresql/data
      - ./init-db.sql:/docker-entrypoint-initdb.d/init.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
    security_opt:
      - no-new-privileges:true

  api:
    image: node:20-alpine
    container_name: app-api
    working_dir: /usr/src/app
    restart: unless-stopped
    depends_on:
      - postgres
    environment:
      DB_NAME: ${POSTGRES_DB}
      DB_USER: ${POSTGRES_USER}
      DB_PASS: ${POSTGRES_PASSWORD}
      DB_HOST: ${DB_HOST}
      DB_PORT: ${DB_PORT}
      API_PORT: 3001
      NODE_ENV: ${NODE_ENV}
    volumes:
      - ./api:/usr/src/app
      - api_node_modules:/usr/src/app/node_modules
    command: sh -c "npm install --omit=dev && node server.js"
    ports:
      - "127.0.0.1:${API_PORT}:3001"
    healthcheck:
      test: ["CMD", "node", "-e", "require('http').get('http://localhost:3001/api/health',res=>process.exit(res.statusCode===200?0:1)).on('error',()=>process.exit(1))"]
      interval: 30s
      timeout: 10s
      retries: 3
    security_opt:
      - no-new-privileges:true

  frontend:
    image: node:20-alpine
    container_name: app-frontend
    working_dir: /usr/src/app
    restart: unless-stopped
    depends_on:
      - api
    environment:
      NODE_ENV: ${NODE_ENV}
      PORT: ${APP_PORT}
      # Ensure devDependencies (typescript, tailwind, etc.) are installed for build
      NPM_CONFIG_PRODUCTION: "false"
      NEXT_TELEMETRY_DISABLED: "1"
    volumes:
      - ./frontend:/usr/src/app
      - frontend_node_modules:/usr/src/app/node_modules
    # Install libc6-compat to avoid Next.js SWC issues on Alpine, install devDeps, build, then start
    command: sh -c "apk add --no-cache libc6-compat && npm ci --include=dev || npm install --include=dev && npm run build && npx next start -H 0.0.0.0 -p ${APP_PORT}"
    ports:
      - "127.0.0.1:${APP_PORT}:${APP_PORT}"
    healthcheck:
      test: ["CMD", "node", "-e", "require('http').get('http://localhost:${APP_PORT}',res=>process.exit(res.statusCode===200?0:1)).on('error',()=>process.exit(1))"]
      interval: 30s
      timeout: 10s
      retries: 3
    security_opt:
      - no-new-privileges:true

networks:
  default:
    name: app-network
    driver: bridge

volumes:
  api_node_modules:
  frontend_node_modules:
EOFILE

# Create database initialization script
cat > init-db.sql <<'EOFILE'
-- Create posts table
CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create update trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_posts_updated_at BEFORE UPDATE
    ON posts FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert sample data
INSERT INTO posts (title, content) VALUES 
    ('Welcome to your Dockerized VPS!', 'Your fullstack application is running successfully in Docker containers.'),
    ('Security First', 'This server has been hardened with security best practices and containerization.'),
    ('Ready for Development', 'You can now build your application on this containerized foundation.');
EOFILE

# Create API package.json
cat > $APP_DIR/api/package.json <<'EOFILE'
{
  "name": "api",
  "version": "1.0.0",
  "description": "Dockerized API with PostgreSQL",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "pg": "^8.11.3",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "helmet": "^7.1.0",
    "morgan": "^1.10.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
EOFILE
# Create API server
cat > $APP_DIR/api/server.js <<'EOFILE'
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const port = process.env.API_PORT || 3001;

// Trust Nginx proxy (loopback) so req.ip reflects the real client IP
app.set('trust proxy', 'loopback');

// Middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost'],
  credentials: true
}));
app.use(express.json());
app.use(morgan('combined'));

// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000,
  max: 20
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected successfully at:', res.rows[0].now);
  }
});

// Routes
app.get('/api/posts', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM posts ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching posts:', err);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

app.get('/api/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM posts WHERE id = $1', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching post:', err);
    res.status(500).json({ error: 'Failed to fetch post' });
  }
});

app.post('/api/posts', async (req, res) => {
  try {
    const { title, content } = req.body;

    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }

    const result = await pool.query(
      'INSERT INTO posts (title, content) VALUES ($1, $2) RETURNING *',
      [title, content]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error creating post:', err);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

app.put('/api/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content } = req.body;

    const result = await pool.query(
      'UPDATE posts SET title = $1, content = $2 WHERE id = $3 RETURNING *',
      [title, content, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating post:', err);
    res.status(500).json({ error: 'Failed to update post' });
  }
});

app.delete('/api/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM posts WHERE id = $1 RETURNING id',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }

    res.json({ message: 'Post deleted successfully', id: result.rows[0].id });
  } catch (err) {
    console.error('Error deleting post:', err);
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

// Health check
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status: 'healthy',
      uptime: process.uptime(),
      database: 'connected'
    });
  } catch (err) {
    res.status(503).json({
      status: 'unhealthy',
      database: 'disconnected',
      error: err.message
    });
  }
});

// Start server
app.listen(port, '0.0.0.0', () => {
  console.log(`API server running on port ${port}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  pool.end(() => {
    console.log('Database pool closed');
    process.exit(0);
  });
});
EOFILE

# Create Frontend package.json
cat > $APP_DIR/frontend/package.json <<'EOFILE'
{
  "name": "frontend",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint"
  },
  "dependencies": {
    "next": "14.0.4",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "axios": "^1.6.2"
  },
  "devDependencies": {
    "eslint": "^8.55.0",
    "eslint-config-next": "14.0.4",
    "@types/node": "^20.10.5",
    "@types/react": "^18.2.45",
    "@types/react-dom": "^18.2.18",
    "typescript": "^5.3.3",
    "tailwindcss": "^3.4.0",
    "autoprefixer": "^10.4.16",
    "postcss": "^8.4.32"
  }
}
EOFILE

# Create Next.js config
cat > $APP_DIR/frontend/next.config.js <<'EOFILE'
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: 'standalone',
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://api:3001/api/:path*',
      },
    ];
  },
}

module.exports = nextConfig
EOFILE

# Create remaining frontend files (tsconfig, tailwind, etc.)
cat > $APP_DIR/frontend/tsconfig.json <<'EOFILE'
{
  "compilerOptions": {
    "target": "es5",
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "forceConsistentCasingInFileNames": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "node",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "paths": {
      "@/*": ["./*"]
    }
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx"],
  "exclude": ["node_modules"]
}
EOFILE

cat > $APP_DIR/frontend/tailwind.config.js <<'EOFILE'
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
EOFILE

cat > $APP_DIR/frontend/postcss.config.js <<'EOFILE'
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
EOFILE

# Create app directory structure
mkdir -p $APP_DIR/frontend/app

# Create layout.tsx
cat > $APP_DIR/frontend/app/layout.tsx <<'EOFILE'
import './globals.css'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Dockerized VPS App',
  description: 'A secure, containerized fullstack application',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
EOFILE

# Create globals.css
cat > $APP_DIR/frontend/app/globals.css <<'EOFILE'
@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
  --foreground-rgb: 0, 0, 0;
  --background-start-rgb: 214, 219, 220;
  --background-end-rgb: 255, 255, 255;
}

@media (prefers-color-scheme: dark) {
  :root {
    --foreground-rgb: 255, 255, 255;
    --background-start-rgb: 0, 0, 0;
    --background-end-rgb: 0, 0, 0;
  }
}

body {
  color: rgb(var(--foreground-rgb));
  background: linear-gradient(
      to bottom,
      transparent,
      rgb(var(--background-end-rgb))
    )
    rgb(var(--background-start-rgb));
}
EOFILE

# Create page.tsx
cat > $APP_DIR/frontend/app/page.tsx <<'EOFILE'
'use client';

import { useState, useEffect } from 'react';
import axios from 'axios';

interface Post {
  id: number;
  title: string;
  content: string;
  created_at: string;
  updated_at: string;
}

export default function Home() {
  const [posts, setPosts] = useState<Post[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [newPost, setNewPost] = useState({ title: '', content: '' });

  useEffect(() => {
    fetchPosts();
  }, []);

  const fetchPosts = async () => {
    try {
      const response = await axios.get('/api/posts');
      setPosts(response.data);
      setLoading(false);
    } catch (err) {
      setError('Failed to fetch posts');
      setLoading(false);
    }
  };

  const createPost = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await axios.post('/api/posts', newPost);
      setNewPost({ title: '', content: '' });
      fetchPosts();
    } catch (err) {
      setError('Failed to create post');
    }
  };

  const deletePost = async (id: number) => {
    try {
      await axios.delete(`/api/posts/${id}`);
      fetchPosts();
    } catch (err) {
      setError('Failed to delete post');
    }
  };

  if (loading) return <div className="flex justify-center items-center h-screen">Loading...</div>;
  if (error) return <div className="flex justify-center items-center h-screen text-red-500">{error}</div>;

  return (
    <main className="container mx-auto p-4 max-w-4xl">
      <h1 className="text-4xl font-bold mb-8 text-center">Dockerized VPS Application</h1>
      
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 mb-8">
        <h2 className="text-2xl font-semibold mb-4">Create New Post</h2>
        <form onSubmit={createPost} className="space-y-4">
          <input
            type="text"
            placeholder="Title"
            value={newPost.title}
            onChange={(e) => setNewPost({ ...newPost, title: e.target.value })}
            className="w-full p-2 border rounded dark:bg-gray-700 dark:border-gray-600"
            required
          />
          <textarea
            placeholder="Content"
            value={newPost.content}
            onChange={(e) => setNewPost({ ...newPost, content: e.target.value })}
            className="w-full p-2 border rounded h-32 dark:bg-gray-700 dark:border-gray-600"
          />
          <button
            type="submit"
            className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
          >
            Create Post
          </button>
        </form>
      </div>

      <div className="space-y-4">
        <h2 className="text-2xl font-semibold mb-4">Posts</h2>
        {posts.map((post) => (
          <div key={post.id} className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
            <div className="flex justify-between items-start">
              <div className="flex-1">
                <h3 className="text-xl font-semibold mb-2">{post.title}</h3>
                <p className="text-gray-600 dark:text-gray-300 mb-2">{post.content}</p>
                <p className="text-sm text-gray-500">
                  Created: {new Date(post.created_at).toLocaleString()}
                </p>
              </div>
              <button
                onClick={() => deletePost(post.id)}
                className="ml-4 text-red-500 hover:text-red-700"
              >
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>
    </main>
  );
}
EOFILE

#########################################
# PART 5: DOCKER COMPOSE STARTUP
#########################################

log_message "=== PART 5: STARTING DOCKER CONTAINERS ==="

# Pull and start containers
cd $APP_DIR
docker compose pull
docker compose up -d

# Wait for services to be healthy
log_message "Waiting for services to be healthy..."
sleep 30

# Check container status
docker compose ps

#########################################
# PART 6: MONITORING AND LOGGING
#########################################

log_message "=== PART 6: SETTING UP MONITORING ==="

# Create Docker log rotation
cat > /etc/logrotate.d/docker-containers <<'EOCONFIG'
/var/lib/docker/containers/*/*.log {
    rotate 7
    daily
    compress
    missingok
    delaycompress
    copytruncate
}
EOCONFIG

# Create monitoring script
cat > /usr/local/bin/docker-health-check.sh <<'EOFILE'
#!/bin/bash

# Check Docker service
if ! systemctl is-active --quiet docker; then
    echo "Docker service is not running!"
    systemctl start docker
fi

# Check for any unhealthy containers (avoid jq dependency)
cd /var/www/app
unhealthy=$(docker ps --format '{{.Names}} {{.Status}}' | grep -i '(unhealthy)' | wc -l)

if [ "${unhealthy}" -gt 0 ]; then
    echo "Unhealthy containers detected. Restarting..."
    docker compose restart
fi
EOFILE

chmod +x /usr/local/bin/docker-health-check.sh

# Add to crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/docker-health-check.sh >> /var/log/docker-health.log 2>&1") | crontab -

#########################################
# FINAL SUMMARY
#########################################

# Add TLS summary if enabled
if [ "${ENABLE_TLS:-no}" = "yes" ] && [ -n "${DOMAIN}" ] && [ -n "${CERTBOT_EMAIL}" ]; then
  TLS_SUMMARY="- HTTPS enabled for domain(s): ${DOMAIN} ${DOMAIN_ALIASES}"
else
  TLS_SUMMARY="- HTTPS not enabled (set ENABLE_TLS=yes and provide DOMAIN and CERTBOT_EMAIL to enable)"
fi

# Cloudflare Real IP summary
if [ "${ENABLE_CLOUDFLARE_REAL_IP:-no}" = "yes" ]; then
  CF_REAL_IP_SUMMARY="- Cloudflare Real IP support enabled (auto-refreshed daily)"
else
  CF_REAL_IP_SUMMARY="- Cloudflare Real IP support disabled"
fi

log_message "=== SETUP COMPLETE ==="
log_info "Your Dockerized VPS has been successfully configured!"
log_info ""
log_info "Security Features:"
log_info "- SSH hardened on port $SSH_PORT"
log_info "- Fail2ban configured"
log_info "- UFW firewall enabled"
log_info "- Automatic security updates"
log_info "- Docker security best practices"
log_info "$TLS_SUMMARY"
log_info "$CF_REAL_IP_SUMMARY"
log_info ""
log_info "Application Stack:"
log_info "- Nginx (reverse proxy) on host"
log_info "- PostgreSQL (database) in Docker"
log_info "- Express API (backend) in Docker (using official Node image)"
log_info "- Next.js (frontend) in Docker (using official Node image)"
log_info ""
log_info "Database Credentials:"
log_info "- Database: $DB_NAME"
