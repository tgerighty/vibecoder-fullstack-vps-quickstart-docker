> ⚠️ This project was originally vibecoded in a day. It has now been revised so the Docker setup is minimal, sane, and actually works with official images. For serious production use, still invest in proper security reviews and operations.

# Vibecoder Fullstack VPS Quick Start

Spin up a hardened Ubuntu VPS with Nginx on the host and a fullstack app (Next.js frontend + Express API + Postgres) running in Docker containers.

- Frontend: React + Next.js + Tailwind
- API: Node + Express
- Database: PostgreSQL

Note on output and logs
- The setup script shows only high-level progress in your terminal and sends all command output to /var/log/vps-setup.log.
- To watch detailed logs while it runs: sudo tail -f /var/log/vps-setup.log

## Quick start (Docker-based, recommended)

- Uses official prebuilt images (node:20-alpine, postgres:16-alpine)
- Nginx runs on the host and proxies to containers bound to localhost
- Optional HTTPS via Certbot + Nginx (with HSTS + OCSP stapling)
- Cloudflare Real IP support (ENABLE_CLOUDFLARE_REAL_IP=yes) to restore client IPs in Nginx logs, rate limits, and app code

```bash
curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-harden/main/fullstack-harden-docker.sh | sudo bash && sudo reboot
```

Enable HTTPS and Cloudflare Full (Strict) in one go (replace with your values):
```bash
sudo ENABLE_TLS=yes \
DOMAIN=example.com \
DOMAIN_ALIASES="www.example.com" \
CERTBOT_EMAIL=you@example.com \
CONFIGURE_CLOUDFLARE_STRICT=yes \
CF_API_TOKEN=your_cloudflare_api_token \
CF_ZONE_NAME=example.com \
bash -lc 'curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-harden/main/fullstack-harden-docker.sh | sudo bash'
```

Notes:
- If CERTBOT_STAGING=yes, the script uses Let’s Encrypt staging (untrusted test certs).
- The script auto-skips any domain without A/AAAA records and proceeds with valid ones.

## What the Docker setup installs

- Security
  - SSH hardening (key-only auth, custom port)
  - Fail2ban
  - UFW (with optional Cloudflare allowlist)
  - Kernel hardening tuned to work with Docker networking
  - Unattended security updates
- Reverse proxy (host)
  - Nginx listening on 80 (with optional auto-HTTPS via Certbot)
  - Proxies / to frontend (localhost:3000 by default) and /api to API (localhost:3001 by default)
- Containers (Docker Compose)
  - postgres:16-alpine with persistent volume and init SQL
  - node:20-alpine for API; mounts /var/www/app/api; installs deps then runs server.js
  - node:20-alpine for frontend; mounts /var/www/app/frontend; installs deps, builds, then starts Next.js

## After running the script

- Reconnect to the VPS after reboot
- Check services
```bash
cd /var/www/app
docker compose ps
docker compose logs -f
```
- Visit http://YOUR_SERVER_IP (or https://your-domain once TLS is enabled)
- API is available at /api (proxied by Nginx)

## HTTPS requirements and behavior

- Each domain you request a certificate for must have a public DNS A or AAAA record.
- The script auto-skips any domain without A/AAAA to avoid failing the entire TLS step.
- If you use Cloudflare, proxied records (orange cloud) are fine for HTTP-01 if traffic reaches your origin.

## Enabling HTTPS later (optional)

If you didn’t enable TLS at install time, you can re-run the script with TLS enabled:

```bash
sudo ENABLE_TLS=yes DOMAIN=example.com DOMAIN_ALIASES="www.example.com" CERTBOT_EMAIL=you@example.com \
CONFIGURE_CLOUDFLARE_STRICT=yes CF_API_TOKEN=your_cloudflare_api_token CF_ZONE_NAME=example.com \
bash fullstack-harden-docker.sh
```

## Managing the app (Docker)

- Edit code under /var/www/app (api/ and frontend/)
- Restart containers to pick up changes
```bash
cd /var/www/app
docker compose restart api
docker compose restart frontend
```
- Update base images and restart
```bash
cd /var/www/app
docker compose pull
docker compose up -d
```

## Troubleshooting

- Containers not healthy
```bash
cd /var/www/app
docker compose logs -f
docker ps
```
- TLS issues
```bash
sudo nginx -t && sudo systemctl reload nginx
sudo certbot renew --dry-run
sudo tail -n 200 /var/log/letsencrypt/letsencrypt.log
```

## License

MIT License - Use freely for personal or commercial projects.
