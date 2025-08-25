#!/bin/bash
# setup-nginx-https.sh
# One-shot script to configure Nginx for your domain, proxy to the Dockerized frontend/api,
# enable Cloudflare Real IP support, and attach Let's Encrypt certificates via certbot.
#
# Usage (run on the server as root):
#   DOMAIN=example.com \
#   DOMAIN_ALIASES="www.example.com" \
#   CERTBOT_EMAIL=you@example.com \
#   ENABLE_CLOUDFLARE_REAL_IP=yes \
#   FRONTEND_PORT=3000 API_PORT=3001 \
#   bash setup-nginx-https.sh
#
# Notes:
# - Requires Ubuntu/Debian-like system with apt.
# - Expects your frontend on 127.0.0.1:$FRONTEND_PORT and api on 127.0.0.1:$API_PORT (as in the provided fullstack script).
# - Safe: backs up existing Nginx app site if present, validates Nginx config before reload.

set -euo pipefail

# --- Config inputs ---
DOMAIN=${DOMAIN:-}
DOMAIN_ALIASES=${DOMAIN_ALIASES:-}
CERTBOT_EMAIL=${CERTBOT_EMAIL:-}
ENABLE_CLOUDFLARE_REAL_IP=${ENABLE_CLOUDFLARE_REAL_IP:-yes}
FRONTEND_PORT=${FRONTEND_PORT:-3000}
API_PORT=${API_PORT:-3001}
CERTBOT_STAGING=${CERTBOT_STAGING:-no}

# --- Logging helpers ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
log() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERR ]${NC} $*" >&2; }

require_root() {
  if [ "$EUID" -ne 0 ]; then
    err "Please run as root (sudo)."
    exit 1
  fi
}

# Prompt helper (only if variable is empty)
prompt_if_empty() {
  local var_name="$1"; shift
  local prompt_text="$1"; shift
  local default_val="${1:-}"
  local current_val="${!var_name:-}"
  if [ -z "$current_val" ]; then
    if [ -n "$default_val" ]; then
      read -rp "$prompt_text [$default_val]: " input
      input="${input:-$default_val}"
    else
      read -rp "$prompt_text: " input
    fi
    # Trim whitespace
    input="$(echo "$input" | xargs)"
    eval "$var_name=\"$input\""
  fi
}

# Gather inputs interactively if not provided
gather_inputs() {
  prompt_if_empty DOMAIN "Enter primary domain (e.g., example.com)"
  prompt_if_empty DOMAIN_ALIASES "Enter domain aliases (space-separated), or leave blank" ""
  prompt_if_empty CERTBOT_EMAIL "Enter email for Let's Encrypt (for expiry notices)"
  prompt_if_empty ENABLE_CLOUDFLARE_REAL_IP "Enable Cloudflare Real IP support? (yes/no)" "yes"
  prompt_if_empty CERTBOT_STAGING "Use Let's Encrypt staging? (yes/no)" "no"
  prompt_if_empty FRONTEND_PORT "Frontend port on localhost" "3000"
  prompt_if_empty API_PORT "API port on localhost" "3001"

  echo
  echo "Selected configuration:"
  echo "  DOMAIN                 : $DOMAIN"
  echo "  DOMAIN_ALIASES         : ${DOMAIN_ALIASES:-<none>}"
  echo "  CERTBOT_EMAIL          : $CERTBOT_EMAIL"
  echo "  ENABLE_CLOUDFLARE_REAL_IP : $ENABLE_CLOUDFLARE_REAL_IP"
  echo "  CERTBOT_STAGING        : $CERTBOT_STAGING"
  echo "  FRONTEND_PORT          : $FRONTEND_PORT"
  echo "  API_PORT               : $API_PORT"
  echo
  read -rp "Proceed with these settings? [Y/n]: " confirm
  confirm=${confirm:-Y}
  case "$confirm" in
    y|Y|yes|YES) ;; 
    *) err "Aborted by user"; exit 1;;
  esac
}

ensure_nginx_installed() {
  if ! command -v nginx >/dev/null 2>&1; then
    log "Installing Nginx..."
    apt-get update -qq
    apt-get install -y -q nginx
  fi
}

ensure_tools() {
  if ! command -v curl >/dev/null 2>&1; then
    log "Installing curl and CA certificates..."
    apt-get update -qq
    apt-get install -y -q curl ca-certificates
  fi
  if ! command -v crontab >/dev/null 2>&1; then
    log "Installing cron..."
    apt-get install -y -q cron
  fi
}

ensure_sites_enabled_included() {
  if ! grep -qE "include\s+/etc/nginx/sites-enabled/\*;" /etc/nginx/nginx.conf; then
    warn "Adding include /etc/nginx/sites-enabled/*; to nginx.conf http block"
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.$(date +%F-%H%M)
    sed -i '/http\s*{/a\    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
  fi
}

setup_cloudflare_real_ip() {
  if [ "$ENABLE_CLOUDFLARE_REAL_IP" != "yes" ]; then
    warn "Cloudflare Real IP support disabled (ENABLE_CLOUDFLARE_REAL_IP=$ENABLE_CLOUDFLARE_REAL_IP)"
    return 0
  fi
  log "Configuring Cloudflare Real IP support..."
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
  /usr/local/bin/update-cloudflare-real-ip.sh || warn "Failed to update Cloudflare real IP list"
  # Daily refresh, avoid duplicate entries
  tmp_cron="$(mktemp)"; trap 'rm -f "$tmp_cron"' RETURN
  crontab -l 2>/dev/null > "$tmp_cron" || true
  if ! grep -q "/usr/local/bin/update-cloudflare-real-ip.sh" "$tmp_cron"; then
    echo "15 3 * * * /usr/local/bin/update-cloudflare-real-ip.sh >/dev/null 2>&1" >> "$tmp_cron"
    crontab "$tmp_cron"
  fi
}

write_app_site() {
  local server_name="$DOMAIN"
  if [ -n "$DOMAIN_ALIASES" ]; then
    server_name+=" $DOMAIN_ALIASES"
  fi
  log "Writing /etc/nginx/sites-available/app with server_name: $server_name"
  if [ -f /etc/nginx/sites-available/app ]; then
    cp /etc/nginx/sites-available/app /etc/nginx/sites-available/app.backup.$(date +%F-%H%M)
  fi
  cat > /etc/nginx/sites-available/app <<NGINX
# Reverse proxy for Dockerized app
upstream frontend { server 127.0.0.1:${FRONTEND_PORT}; }
upstream api      { server 127.0.0.1:${API_PORT}; }

server {
  listen 80;
  listen [::]:80;
  server_name ${server_name};

  # If present, apply Cloudflare Real IP config
  include /etc/nginx/conf.d/cloudflare-real-ip.conf;

  # Frontend
  location / {
    proxy_pass http://frontend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_cache_bypass \$http_upgrade;
    proxy_read_timeout 90;
  }

  # API
  location /api {
    proxy_pass http://api;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 90;
  }

  # Health
  location /health {
    access_log off;
    return 200 "healthy\n";
    add_header Content-Type text/plain;
  }
}
NGINX
  ln -sf /etc/nginx/sites-available/app /etc/nginx/sites-enabled/app
}

reload_nginx() {
  log "Validating and reloading Nginx..."
  nginx -t
  systemctl reload nginx
}

install_cert() {
  log "Installing certbot (nginx plugin)..."
  apt-get update -qq
  apt-get install -y -q certbot python3-certbot-nginx
  local domains_args="-d ${DOMAIN}"
  for d in ${DOMAIN_ALIASES}; do
    domains_args+=" -d ${d}"
  done
  local staging_flag=""
  if [ "$CERTBOT_STAGING" = "yes" ]; then
    staging_flag="--staging"
    warn "Using Let's Encrypt staging (no trusted cert, for testing only)"
  fi
  log "Running certbot --nginx ${domains_args} --redirect ${staging_flag}"
  if certbot --nginx ${domains_args} --non-interactive --agree-tos -m "${CERTBOT_EMAIL}" --redirect ${staging_flag}; then
    log "Certificate installed and HTTPS redirect enabled."
    # Apply HSTS + OCSP stapling on the TLS server block
    harden_tls_server_block
  else
    warn "Certbot nginx installer failed. The certificate may still be issued; attempting manual install..."
    certbot certificates || true
    warn "If a certificate exists for ${DOMAIN}, you can manually create TLS server blocks using the files under /etc/letsencrypt/live/${DOMAIN}/"
  fi
}

main() {
  require_root
  gather_inputs
  ensure_tools
  ensure_nginx_installed
  ensure_sites_enabled_included
  setup_cloudflare_real_ip
  write_app_site
  reload_nginx
  install_cert
  reload_nginx
  log "Done. Test with: curl -I http://${DOMAIN} and curl -I https://${DOMAIN}"
  log "If using Cloudflare, set SSL/TLS mode to Full (strict)."
}

main "$@"
