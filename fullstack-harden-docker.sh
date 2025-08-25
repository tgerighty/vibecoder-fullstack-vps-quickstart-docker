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
# Cloudflare Zone config (optional): switch to Full (Strict) via API
CONFIGURE_CLOUDFLARE_STRICT=${CONFIGURE_CLOUDFLARE_STRICT:-"no"}
CF_API_TOKEN=${CF_API_TOKEN:-""}
CF_ZONE_ID=${CF_ZONE_ID:-""}
CF_ZONE_NAME=${CF_ZONE_NAME:-""}
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

# Function to log messages (to console + log file)
log_message() {
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    # Console (original stdout fd3) and log (current stdout)
    echo -e "${GREEN}[${ts}]${NC} $1" >&3
    echo -e "${GREEN}[${ts}]${NC} $1"
}

log_error() {
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[${ts}] ERROR:${NC} $1" >&3
    echo -e "${RED}[${ts}] ERROR:${NC} $1"
}

log_warning() {
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[${ts}] WARNING:${NC} $1" >&3
    echo -e "${YELLOW}[${ts}] WARNING:${NC} $1"
}

log_info() {
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[${ts}] INFO:${NC} $1" >&3
    echo -e "${BLUE}[${ts}] INFO:${NC} $1"
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
    echo -ne "$prompt_text [$shown_default]: " >&3
  else
    echo -ne "$prompt_text: " >&3
  fi
  local input=""
  IFS= read -r input < /dev/tty || true
  input="${input:-$shown_default}"
  # Trim whitespace
  input="$(echo "$input" | xargs)"
  eval "$var_name=\"$input\""
}

secure_prompt() {
  # $1 var name, $2 prompt text
  local var_name="$1"; shift
  local prompt_text="$1"; shift
  echo -ne "$prompt_text: " >&3
  # Disable echo on TTY
  stty -echo < /dev/tty
  local input=""
  IFS= read -r input < /dev/tty || true
  stty echo < /dev/tty
  echo >&3
  eval "$var_name=\"$input\""
}

secure_prompt_optional() {
  # $1 var name, $2 prompt text (user can press Enter to keep current value)
  local var_name="$1"; shift
  local prompt_text="$1"; shift
  local current_val="${!var_name-}"
  echo -ne "$prompt_text (leave blank to keep current): " >&3
  stty -echo < /dev/tty
  local input=""
  IFS= read -r input < /dev/tty || true
  stty echo < /dev/tty
  echo >&3
  if [ -n "$input" ]; then
    eval "$var_name=\"$input\""
  else
    # keep existing value
    :
  fi
}

confirm_yes() {
  # $1 prompt text, default Y
  local prompt_text="$1"; shift
  echo -ne "$prompt_text [Y/n]: " >&3
  local ans=""
  IFS= read -r ans < /dev/tty || true
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
  echo >&3
  echo "=== Interactive configuration ===" >&3
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
      echo "Domain is required when TLS is enabled." >&3
    done
    prompt_with_default DOMAIN_ALIASES "Domain aliases (space-separated, can be blank)" "$DOMAIN_ALIASES"
    while :; do
      prompt_with_default CERTBOT_EMAIL "Email for Let's Encrypt registration" "$CERTBOT_EMAIL"
      [ -n "$CERTBOT_EMAIL" ] && break
      echo "Certbot email is required when TLS is enabled." >&3
    done
    prompt_with_default CERTBOT_STAGING "Use Let's Encrypt staging? (yes/no)" "$CERTBOT_STAGING"
    # Cloudflare Strict configuration (optional)
    prompt_with_default CONFIGURE_CLOUDFLARE_STRICT "Switch Cloudflare zone to Full (Strict) SSL after issuing cert? (yes/no)" "$CONFIGURE_CLOUDFLARE_STRICT"
    if [ "$CONFIGURE_CLOUDFLARE_STRICT" = "yes" ]; then
      _guess_zone="$(guess_zone_from_domain "$DOMAIN")"
      prompt_with_default CF_ZONE_NAME "Cloudflare zone name (parent domain)" "${CF_ZONE_NAME:-$_guess_zone}"
      # Prompt for API token securely; leave blank to keep current value
      secure_prompt_optional CF_API_TOKEN "Enter Cloudflare API Token (Zone:Read, Zone Settings:Edit)"
    fi
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
      echo "Database password cannot be empty." >&3
    done
  fi

  echo >&3
  echo "Selected configuration:" >&3
  echo "  SSH_PORT                  : $SSH_PORT" >&3
  echo "  ADMIN_EMAIL               : ${ADMIN_EMAIL:-<none>}" >&3
  echo "  ENABLE_CLOUDFLARE         : $ENABLE_CLOUDFLARE" >&3
  echo "  ENABLE_CLOUDFLARE_REAL_IP : $ENABLE_CLOUDFLARE_REAL_IP" >&3
  echo "  ENABLE_TLS                : $ENABLE_TLS" >&3
  if [ "$ENABLE_TLS" = "yes" ]; then
    echo "  DOMAIN                    : $DOMAIN" >&3
    echo "  DOMAIN_ALIASES            : ${DOMAIN_ALIASES:-<none>}" >&3
    echo "  CERTBOT_EMAIL             : $CERTBOT_EMAIL" >&3
    echo "  CERTBOT_STAGING           : $CERTBOT_STAGING" >&3
    echo "  CONFIGURE_CLOUDFLARE_STRICT: $CONFIGURE_CLOUDFLARE_STRICT" >&3
    if [ "$CONFIGURE_CLOUDFLARE_STRICT" = "yes" ]; then
      echo "  CF_ZONE_NAME              : ${CF_ZONE_NAME:-<none>}" >&3
      echo "  CF_ZONE_ID                : ${CF_ZONE_ID:-<auto-resolve>}" >&3
      echo "  CF_API_TOKEN              : ${CF_API_TOKEN:+*** set ***}" >&3
    fi
  fi
  echo "  APP_PORT                  : $APP_PORT" >&3
  echo "  API_PORT                  : $API_PORT" >&3
  echo "  DB_NAME                   : $DB_NAME" >&3
  echo "  DB_USER                   : $DB_USER" >&3
  echo "  DB_PASS                   : ********" >&3
  echo >&3
  confirm_yes "Proceed with these settings?" || { echo "Aborted by user." >&3; exit 1; }
}

# Simple DNS check to ensure a domain has at least one A/AAAA record
# (Does not require matching server IP because Cloudflare proxy may be enabled.)
domain_has_dns() {
  local d="$1"
  getent ahosts "$d" | awk '{print $1}' | grep -Eq '^[0-9]'
}

# --- Cloudflare helpers (optional) ---
ensure_jq_installed() {
  if ! command -v jq >/dev/null 2>&1; then
    log_info "Installing jq for Cloudflare API calls..."
    apt-get update -qq
    apt-get install -y -q jq
  fi
}

guess_zone_from_domain() {
  local d="$1"
  # naive guess: last two labels (works for most common zones)
  echo "$d" | awk -F. '{n=NF; if (n>=2) print $(n-1)"."$n; else print $0}'
}

get_zone_id_from_name() {
  local token="$1"; shift
  local zone_name="$1"; shift
  curl -fsS -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' \
    "https://api.cloudflare.com/client/v4/zones?name=${zone_name}" | jq -r '.result[0].id // empty'
}

# Try progressively less specific names: app.example.co.uk -> example.co.uk -> co.uk
resolve_zone_id_for_domain() {
  local token="$1"; shift
  local host="$1"; shift
  local candidate="$host"
  while [ -n "$candidate" ]; do
    local zid
    zid="$(get_zone_id_from_name "$token" "$candidate")"
    if [ -n "$zid" ]; then
      echo "$zid"
      return 0
    fi
    if [[ "$candidate" == *.* ]]; then
      candidate="${candidate#*.}"
    else
      break
    fi
  done
  echo ""
}

cf_patch_setting() {
  local zone_id="$1"; shift
  local setting="$1"; shift
  local value="$1"; shift
  local token="$1"; shift
  curl -fsS -X PATCH \
    -H "Authorization: Bearer ${token}" \
    -H 'Content-Type: application/json' \
    --data "{\"value\":\"${value}\"}" \
    "https://api.cloudflare.com/client/v4/zones/${zone_id}/settings/${setting}" | jq -r '.success'
}

# Raw GET and PATCH helpers for richer error handling
cf_get_setting_raw() {
  local zone_id="$1"; shift
  local setting="$1"; shift
  local token="$1"; shift
  curl -sS -X GET \
    -H "Authorization: Bearer ${token}" \
    -H 'Content-Type: application/json' \
    "https://api.cloudflare.com/client/v4/zones/${zone_id}/settings/${setting}"
}

cf_patch_setting_raw() {
  local zone_id="$1"; shift
  local setting="$1"; shift
  local value="$1"; shift
  local token="$1"; shift
  curl -sS -X PATCH \
    -H "Authorization: Bearer ${token}" \
    -H 'Content-Type: application/json' \
    --data "{\"value\":\"${value}\"}" \
    "https://api.cloudflare.com/client/v4/zones/${zone_id}/settings/${setting}"
}

cf_setting_success() {
  local json="$1"
  echo "$json" | jq -r '.success // false'
}

cf_first_error_code() {
  local json="$1"
  echo "$json" | jq -r '.errors[0].code // empty'
}

cf_first_error_message() {
  local json="$1"
  echo "$json" | jq -r '.errors[0].message // empty'
}

configure_cloudflare_full_strict() {
  if [ "$CONFIGURE_CLOUDFLARE_STRICT" != "yes" ]; then
    return 0
  fi
  if [ -z "$CF_API_TOKEN" ]; then
    log_warning "CONFIGURE_CLOUDFLARE_STRICT=yes but CF_API_TOKEN is empty. Skipping Cloudflare configuration."
    return 0
  fi
  ensure_jq_installed

  # Determine zone ID
  if [ -z "$CF_ZONE_ID" ]; then
    if [ -z "$CF_ZONE_NAME" ]; then
      CF_ZONE_NAME="$(guess_zone_from_domain "$DOMAIN")"
    fi
    log_message "Resolving Cloudflare Zone ID for ${CF_ZONE_NAME}..."
    CF_ZONE_ID="$(get_zone_id_from_name "$CF_API_TOKEN" "$CF_ZONE_NAME" || true)"
    if [ -z "$CF_ZONE_ID" ]; then
      log_error "Failed to resolve Cloudflare Zone ID for ${CF_ZONE_NAME}. Ensure token has Zone:Read and the zone exists."
      return 1
    fi
  fi

  # Preflight: check we can read SSL setting (detect 9109 early)
  local preflight resp ok code msg
  preflight="$(cf_get_setting_raw "$CF_ZONE_ID" "ssl" "$CF_API_TOKEN" || true)"
  ok="$(cf_setting_success "$preflight")"
  if [ "$ok" != "true" ]; then
    code="$(cf_first_error_code "$preflight")"
    msg="$(cf_first_error_message "$preflight")"
    log_error "Cloudflare preflight failed for zone ${CF_ZONE_ID}. Code: ${code:-?}, Message: ${msg:-?}"
    echo "$preflight" >&3
    if [ "$code" = "9109" ]; then
      log_error "The API token is unauthorized for this zone. Ensure the token has: 'Zone:Read' and 'Zone Settings:Edit' permissions for this zone (or All zones)."
      log_error "You can set CF_ZONE_NAME to the parent zone (e.g., example.com) or CF_ZONE_ID directly, and use a token scoped to that zone."
    fi
    return 1
  fi

  log_message "Setting Cloudflare SSL mode to Full (Strict) for zone ${CF_ZONE_ID} (${CF_ZONE_NAME:-unknown})"
  resp="$(cf_patch_setting_raw "$CF_ZONE_ID" "ssl" "strict" "$CF_API_TOKEN" || true)"
  ok="$(cf_setting_success "$resp")"
  if [ "$ok" != "true" ]; then
    code="$(cf_first_error_code "$resp")"; msg="$(cf_first_error_message "$resp")"
    log_error "Cloudflare: failed to set SSL mode to strict. Code: ${code:-?}, Message: ${msg:-?}"
    echo "$resp" >&3
    return 1
  fi

  log_message "Enabling Cloudflare 'Always Use HTTPS'..."
  resp="$(cf_patch_setting_raw "$CF_ZONE_ID" "always_use_https" "on" "$CF_API_TOKEN" || true)"
  ok="$(cf_setting_success "$resp")"
  if [ "$ok" != "true" ]; then
    code="$(cf_first_error_code "$resp")"; msg="$(cf_first_error_message "$resp")"
    log_warning "Cloudflare: could not enable Always Use HTTPS. Code: ${code:-?}, Message: ${msg:-?}"
    echo "$resp" >&3
  fi

  log_message "Enabling Cloudflare 'Automatic HTTPS Rewrites'..."
  resp="$(cf_patch_setting_raw "$CF_ZONE_ID" "automatic_https_rewrites" "on" "$CF_API_TOKEN" || true)"
  ok="$(cf_setting_success "$resp")"
  if [ "$ok" != "true" ]; then
    code="$(cf_first_error_code "$resp")"; msg="$(cf_first_error_message "$resp")"
    log_warning "Cloudflare: could not enable Automatic HTTPS Rewrites. Code: ${code:-?}, Message: ${msg:-?}"
    echo "$resp" >&3
  fi

  log_message "Cloudflare SSL set to Full (Strict)."
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" >&2
   exit 1
fi

# Create log file
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"

# Redirect all stdout/stderr to the log file, but keep a copy of the original stdout/stderr
exec 3>&1 4>&2
exec >>"$LOG_FILE" 2>&1

log_message "Starting VPS setup and hardening with Docker... (showing progress only; detailed logs: $LOG_FILE)"
log_message "Configuration: SSH_PORT=$SSH_PORT, ENABLE_CLOUDFLARE=$ENABLE_CLOUDFLARE, ENABLE_TLS=$ENABLE_TLS, DOMAIN=${DOMAIN:-unset}, ENABLE_CLOUDFLARE_REAL_IP=${ENABLE_CLOUDFLARE_REAL_IP}"

# Collect interactive configuration if running in a TTY and PROMPT_ALL=yes
collect_configuration

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
# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable Source Routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6 router advertisements acceptance
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOCONFIG
sysctl --system >/dev/null 2>&1 || true

#########################################
# PART 2: DOCKER INSTALLATION
#########################################

log_message "=== PART 2: DOCKER INSTALLATION ==="

# Install Docker Engine + Compose plugin if missing
if ! command -v docker >/dev/null 2>&1; then
  log_message "Installing Docker Engine and Docker Compose plugin..."
  apt-get update -y -q || true
  apt-get install -y -q ca-certificates curl gnupg lsb-release || apt-get install -y -q ca-certificates curl gnupg || true
  install -m 0755 -d /etc/apt/keyrings
  if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg || true
    chmod a+r /etc/apt/keyrings/docker.gpg || true
  fi
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -y -q || true
  # Prefer official packages; fall back to Ubuntu's docker.io if repository not available
  if ! apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
    log_warning "Falling back to Ubuntu docker.io packages"
    apt-get install -y -q docker.io docker-compose-plugin containerd || true
  fi
fi

# Ensure Docker directory exists before writing daemon.json
mkdir -p /etc/docker

cat > /etc/docker/daemon.json <<'EOCONFIG'
{
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {"max-size": "10m", "max-file": "3"},
  "no-new-privileges": true,
  "userland-proxy": false
}
EOCONFIG

# Enable and (re)start Docker
systemctl enable --now docker || systemctl restart docker

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

# Ensure Cloudflare Real IP include file exists to avoid nginx -t failing if disabled
mkdir -p /etc/nginx/conf.d
[ -f /etc/nginx/conf.d/cloudflare-real-ip.conf ] || touch /etc/nginx/conf.d/cloudflare-real-ip.conf

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

    # Build domain list, skipping those without DNS records
    domains_args=""
    valid_count=0
    for d in $DOMAIN $DOMAIN_ALIASES; do
      [ -z "$d" ] && continue
      if domain_has_dns "$d"; then
        domains_args="$domains_args -d $d"
        valid_count=$((valid_count+1))
      else
        log_warning "Skipping domain '$d' for TLS: no A/AAAA DNS records found."
      fi
    done
    if [ "$valid_count" -eq 0 ]; then
      log_error "No valid domains with DNS records available for TLS. Skipping Certbot."
    else
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
        # Configure Cloudflare SSL Strict if requested
        configure_cloudflare_full_strict || true
      else
        log_error "Certbot failed to obtain certificates. Check DNS records and that ports 80/443 are reachable."
      fi
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
NEXT_PUBLIC_API_URL=/api
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
log_message "Pulling images and starting containers..."
docker compose pull
docker compose up -d

# Wait for services to be healthy
log_message "Waiting for services to be healthy..."
sleep 30

# Show container status
log_message "Container status:"
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

# Check containers
if ! docker ps >/dev/null 2>&1; then
    echo "Docker is not responding to 'docker ps'"
    systemctl restart docker
fi

# Restart unhealthy containers
for c in $(docker ps --format '{{.Names}}'); do
  status=$(docker inspect --format='{{.State.Health.Status}}' "$c" 2>/dev/null || echo "unknown")
  if [ "$status" = "unhealthy" ]; then
    echo "Container $c is unhealthy, restarting..."
    docker restart "$c"
  fi
done
EOFILE
chmod +x /usr/local/bin/docker-health-check.sh

log_message "Setup complete. Progress was shown above; full logs at $LOG_FILE. Visit your domain to verify."