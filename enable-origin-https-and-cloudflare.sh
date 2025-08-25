#!/bin/bash
# enable-origin-https-and-cloudflare.sh
# One-shot helper to:
# 1) Enable HTTPS on your origin via Nginx + Let's Encrypt (using setup-nginx-https.sh)
# 2) Flip Cloudflare zone SSL/TLS setting to Full (Strict) and enable HTTPS-related features
#
# Usage (run on the server as root):
#   DOMAIN=example.com \
#   DOMAIN_ALIASES="www.example.com" \
#   CERTBOT_EMAIL=you@example.com \
#   FRONTEND_PORT=3000 API_PORT=3001 \
#   ENABLE_CLOUDFLARE_REAL_IP=yes \
#   CF_API_TOKEN=your_cloudflare_api_token \
#   CF_ZONE_NAME=example.com \
#   bash enable-origin-https-and-cloudflare.sh
#
# Notes:
# - CF_API_TOKEN must have Zone:Read and Zone Settings:Edit permissions for the zone.
# - If DOMAIN is a subdomain (e.g., app.example.com), CF_ZONE_NAME is the parent zone (example.com).
# - This script calls setup-nginx-https.sh in the same directory.

set -euo pipefail

# --- Config inputs (read from env or prompted) ---
DOMAIN=${DOMAIN:-}
DOMAIN_ALIASES=${DOMAIN_ALIASES:-}
CERTBOT_EMAIL=${CERTBOT_EMAIL:-}
FRONTEND_PORT=${FRONTEND_PORT:-3000}
API_PORT=${API_PORT:-3001}
ENABLE_CLOUDFLARE_REAL_IP=${ENABLE_CLOUDFLARE_REAL_IP:-yes}
CERTBOT_STAGING=${CERTBOT_STAGING:-no}

CF_API_TOKEN=${CF_API_TOKEN:-}
CF_ZONE_ID=${CF_ZONE_ID:-}
CF_ZONE_NAME=${CF_ZONE_NAME:-}

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
    input="$(echo "$input" | xargs)"
    eval "$var_name=\"$input\""
  fi
}

ensure_tools() {
  if ! command -v curl >/dev/null 2>&1; then
    log "Installing curl and CA certificates..."
    apt-get update -qq
    apt-get install -y -q curl ca-certificates
  fi
  if ! command -v jq >/dev/null 2>&1; then
    log "Installing jq..."
    apt-get install -y -q jq
  fi
}

# Attempt to guess zone from DOMAIN (best-effort; user will confirm)
guess_zone_from_domain() {
  local d="$1"
  # naive guess: last two labels
  local guess="$(echo "$d" | awk -F. '{n=NF; if (n>=2) print $(n-1)"."$n; else print $0}')"
  echo "$guess"
}

get_zone_id_from_name() {
  local token="$1"; shift
  local zone_name="$1"; shift
  local resp
  resp=$(curl -fsS -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' \
    "https://api.cloudflare.com/client/v4/zones?name=${zone_name}")
  echo "$resp" | jq -r '.result[0].id // empty'
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

run_setup_nginx_https() {
  if [ ! -f ./setup-nginx-https.sh ]; then
    err "setup-nginx-https.sh not found in current directory. Place this script next to it and rerun."
    exit 1
  fi
  log "Running setup-nginx-https.sh for domain: ${DOMAIN}"
  DOMAIN="$DOMAIN" \
  DOMAIN_ALIASES="$DOMAIN_ALIASES" \
  CERTBOT_EMAIL="$CERTBOT_EMAIL" \
  ENABLE_CLOUDFLARE_REAL_IP="$ENABLE_CLOUDFLARE_REAL_IP" \
  FRONTEND_PORT="$FRONTEND_PORT" \
  API_PORT="$API_PORT" \
  CERTBOT_STAGING="$CERTBOT_STAGING" \
  bash ./setup-nginx-https.sh
}

run_cloudflare_full_strict() {
  if [ -z "$CF_API_TOKEN" ]; then
    warn "CF_API_TOKEN is not set. Skipping Cloudflare configuration."
    return 0
  fi
  if [ -z "$CF_ZONE_ID" ]; then
    if [ -z "$CF_ZONE_NAME" ]; then
      local guess
      guess=$(guess_zone_from_domain "$DOMAIN")
      prompt_if_empty CF_ZONE_NAME "Enter Cloudflare zone name (parent domain)" "$guess"
    fi
    log "Resolving Zone ID for ${CF_ZONE_NAME}..."
    CF_ZONE_ID=$(get_zone_id_from_name "$CF_API_TOKEN" "$CF_ZONE_NAME" || true)
    if [ -z "$CF_ZONE_ID" ]; then
      err "Failed to resolve Zone ID for ${CF_ZONE_NAME}. Ensure the token has Zone:Read and the zone exists."
      exit 1
    fi
  fi

  log "Setting Cloudflare SSL mode to Full (Strict) for zone ${CF_ZONE_ID} (${CF_ZONE_NAME:-unknown})"
  local ok
  ok=$(cf_patch_setting "$CF_ZONE_ID" "ssl" "strict" "$CF_API_TOKEN")
  if [ "$ok" != "true" ]; then
    err "Failed to set SSL mode to strict."
    exit 1
  fi

  log "Enabling 'Always Use HTTPS'..."
  ok=$(cf_patch_setting "$CF_ZONE_ID" "always_use_https" "on" "$CF_API_TOKEN")
  if [ "$ok" != "true" ]; then
    warn "Could not enable Always Use HTTPS (continuing)."
  fi

  log "Enabling 'Automatic HTTPS Rewrites'..."
  ok=$(cf_patch_setting "$CF_ZONE_ID" "automatic_https_rewrites" "on" "$CF_API_TOKEN")
  if [ "$ok" != "true" ]; then
    warn "Could not enable Automatic HTTPS Rewrites (continuing)."
  fi

  log "Cloudflare: SSL Strict enabled."
}

main() {
  require_root
  ensure_tools

  # Gather inputs interactively if not provided
  prompt_if_empty DOMAIN "Enter primary domain (e.g., example.com)"
  prompt_if_empty DOMAIN_ALIASES "Enter domain aliases (space-separated), or leave blank" ""
  prompt_if_empty CERTBOT_EMAIL "Enter email for Let's Encrypt (expiry notices)"
  prompt_if_empty CERTBOT_STAGING "Use Let's Encrypt staging? (yes/no)" "no"
  prompt_if_empty FRONTEND_PORT "Frontend port on localhost" "$FRONTEND_PORT"
  prompt_if_empty API_PORT "API port on localhost" "$API_PORT"

  echo
  echo "Selected configuration:"
  echo "  DOMAIN                   : $DOMAIN"
  echo "  DOMAIN_ALIASES           : ${DOMAIN_ALIASES:-<none>}"
  echo "  CERTBOT_EMAIL            : $CERTBOT_EMAIL"
  echo "  CERTBOT_STAGING         : $CERTBOT_STAGING"
  echo "  FRONTEND_PORT            : $FRONTEND_PORT"
  echo "  API_PORT                 : $API_PORT"
  echo "  ENABLE_CLOUDFLARE_REAL_IP: $ENABLE_CLOUDFLARE_REAL_IP"
  echo "  CF_ZONE_NAME             : ${CF_ZONE_NAME:-<not set>}"
  echo "  CF_ZONE_ID               : ${CF_ZONE_ID:-<not set>}"
  echo "  CF_API_TOKEN             : ${CF_API_TOKEN:+*** set ***}"
  echo
  read -rp "Proceed with these settings? [Y/n]: " confirm
  confirm=${confirm:-Y}
  case "$confirm" in
    y|Y|yes|YES) ;; 
    *) err "Aborted by user"; exit 1;;
  esac

  # Step 1: Set up origin HTTPS via Nginx + certbot
  run_setup_nginx_https

  # Step 2: Switch Cloudflare to Full (Strict) + related settings
  run_cloudflare_full_strict

  log "All done. Your origin is now serving HTTPS and Cloudflare is set to Full (Strict)."
}

main "$@"
