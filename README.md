> ⚠️ This project was originally vibecoded in a day. It has now been revised so the Docker setup is minimal, sane, and actually works with official images. For serious production use, still invest in proper security reviews and operations.

# Vibecoder Fullstack VPS Quick Start

Spin up a hardened Ubuntu VPS with Nginx on the host and a fullstack app (Next.js frontend + Express API + Postgres) running in Docker containers.

- Frontend: React + Next.js + Tailwind
- API: Node + Express
- Database: PostgreSQL

## Choose Your Setup Method

- Option 1: Docker-Based Setup (Recommended)
  - Uses official prebuilt images (node:20-alpine, postgres:16-alpine)
  - Nginx runs on the host and proxies to containers bound to localhost
  - No custom Dockerfiles generated; code is mounted into containers
  - Healthchecks do not depend on extra tools in containers
  - Optional HTTPS via Certbot + Nginx
  - Cloudflare Real IP support (ENABLE_CLOUDFLARE_REAL_IP=yes) to restore client IPs in Nginx logs, rate limits, and app code
  - See README-DOCKER.md for details

  ```bash
  curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-harden/main/fullstack-harden-docker.sh | sudo bash && sudo reboot
  ```

  To enable HTTPS on first run, pass env vars (replace with your domain/email):
  ```bash
  SSH_PORT=22 ENABLE_TLS=yes DOMAIN=example.com DOMAIN_ALIASES="www.example.com" CERTBOT_EMAIL=you@example.com \
  curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-harden/main/fullstack-harden-docker.sh | sudo bash && sudo reboot
  ```

- Option 2: Traditional Setup (Original)
  - Runs services on the host with PM2
  - Simpler to understand, less isolation
  - Not the recommended path going forward

  ```bash
  curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-harden/main/fullstack-harden.sh | sudo bash && sudo reboot
  ```

## What the Docker setup installs

- Security
  - SSH hardening (key-only auth, custom port)
  - Fail2ban
  - UFW (with optional Cloudflare allowlist)
  - Kernel hardening tuned to work with Docker networking
  - Unattended security updates
- Reverse proxy (host)
  - Nginx listening on 80 (with optional auto-HTTPS via Certbot)
  - Proxies / to frontend (localhost:3000) and /api to API (localhost:3001)
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

## Enabling HTTPS later (optional)

If you didn’t enable TLS at install time, you can run:

```bash
sudo ENABLE_TLS=yes DOMAIN=example.com DOMAIN_ALIASES="www.example.com" CERTBOT_EMAIL=you@example.com bash -lc '
  # Reload Nginx config to ensure server_name is set
  systemctl reload nginx
  # Run certbot once with Nginx plugin to obtain certs and enable redirect
  certbot --nginx -d "$DOMAIN" $(for d in $DOMAIN_ALIASES; do printf " -d %s" "$d"; done) \
    --non-interactive --agree-tos -m "$CERTBOT_EMAIL" --redirect
'
```

Make sure your domain’s A record points to this server before running the certbot command.

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

More details in README-DOCKER.md.

## Optional: Install Claude Code on the server

```bash
cd / && curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-hardened-fullstack-webserver/main/CLAUDE.md > CLAUDE.md && \
npm install -g @anthropic-ai/claude-code && \
echo "✅ Claude Code installed! Run 'claude' to start AI-assisted coding"
```

Run Claude in an unrestricted mode (use wisely):
```bash
export IS_SANDBOX=1; claude --dangerously-skip-permissions
```

## Attach a domain (optional)

1. Buy a domain
2. Create a Cloudflare account
3. Point your domain’s nameservers to Cloudflare
4. Create an A record for @ to your VPS IP
5. Enable TLS as shown above

## Troubleshooting

- Containers not healthy
  ```bash
  cd /var/www/app
  docker compose logs -f
  docker ps
  ```
- Database connectivity
  ```bash
  docker exec app-postgres pg_isready -U appuser -d appdb
  docker compose restart postgres
  ```
- TLS issues
  ```bash
  sudo nginx -t && sudo systemctl reload nginx
  sudo certbot renew --dry-run
  sudo tail -n 200 /var/log/letsencrypt/letsencrypt.log
  ```

## License

MIT License - Use freely for personal or commercial projects.
