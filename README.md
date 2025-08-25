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
  - See README-DOCKER.md for details

  ```bash
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
  - Nginx listening on 80 (ready for TLS)
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
- Visit http://YOUR_SERVER_IP to see the Next.js frontend
- API is available at http://YOUR_SERVER_IP/api (proxied by Nginx)

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
5. Add TLS later by installing certbot and updating Nginx

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

## License

MIT License - Use freely for personal or commercial projects.
