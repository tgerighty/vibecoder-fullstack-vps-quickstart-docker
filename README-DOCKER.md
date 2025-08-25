# Dockerized Fullstack VPS Setup

This is a Docker-based version of the fullstack VPS hardening script that provides enhanced security through containerization while maintaining all the original security features.

## Overview

This script sets up a secure, production-ready VPS with:

### Security Features (maintained from original):
- SSH Hardening: Key-only authentication, rate limiting, custom port
- Fail2ban: Protection against brute force attacks
- UFW Firewall: Restrictive firewall rules with optional Cloudflare IP allows
- Kernel Hardening: Security-focused sysctl parameters (with Docker-friendly forwarding)
- Automatic Updates: Unattended security updates

### Infrastructure (Docker-based):
- Nginx: Running on host as main reverse proxy (for security)
- PostgreSQL: Containerized database with persistent storage
- Express API: Containerized Node.js backend using official Node image
- Next.js Frontend: Containerized React application using official Node image
- Docker Compose: Orchestration with health checks

## Architecture

```
Internet → Nginx (Host) → Docker Network → Containers
                ↓
         ┌──────┴──────┐
         │             │
    Frontend:3000  API:3001
         │             │
         └─────┬───────┘
               │
         PostgreSQL:5432
```

## Key Improvements

1. No custom Dockerfiles: uses official prebuilt images (node:20-alpine, postgres:16-alpine)
2. Reliable healthchecks: no wget/curl required in containers
3. Safer firewall: Docker remote API ports are NOT opened
4. Simpler networking: a single compose-managed bridge network
5. Smaller footprint: fewer host packages installed
6. Log rotation for container logs

## Usage

Run on a fresh Ubuntu 24.04 VPS:

```bash
curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-harden/main/fullstack-harden-docker.sh | sudo bash && sudo reboot
```

After reboot, Nginx proxies to the containers bound to localhost only.

## Managing Containers

```bash
cd /var/www/app

# View container status
docker compose ps

# View logs
docker compose logs -f [service]

# Restart a service (applies code changes mounted from host)
docker compose restart [service]

# Stop all services
docker compose down

# Start all services
docker compose up -d

# Update base images and restart
docker compose pull
docker compose up -d
```

Notes:
- API container runs `npm ci --omit=dev` on start and then `node server.js`.
- Frontend container runs `npm ci && npm run build && npm start` on start. Restart it to pick up code changes.

## Security Considerations

1. Nginx on Host: Keeps the main entry point outside containers for better security control
2. No Docker API exposure: UFW does NOT open 2375/2376
3. Internal Network: Database is not exposed to host, only accessible within Compose network
4. Secrets: Database credentials come from `.env`. For production, consider Docker secrets or external secret stores
5. Log Rotation: Automated log rotation prevents disk space issues

## Customization

### Changing Ports
Edit `/var/www/app/.env` and update `docker-compose.yml` port mappings if needed (Nginx already proxies 3000/3001 on localhost).

### Adding SSL/TLS
1. Install certbot on the host
2. Update Nginx configuration in `/etc/nginx/sites-available/app`
3. Add SSL certificates and redirect HTTP to HTTPS

### Scaling
- Use additional Compose replicas behind Nginx or move to Swarm/K8s
- Add Redis for sessions if scaling API horizontally
- Consider using a managed Postgres for production

## Monitoring

A health check script runs every 5 minutes via cron to detect unhealthy containers and restart the stack.
- `/var/log/docker-health.log`
- `/var/log/vps-setup.log`

## Backup Strategy

1. Database:
```bash
docker exec app-postgres pg_dump -U appuser appdb > backup.sql
```

2. Application Code: The `/var/www/app` directory contains all application files

3. Docker Volumes:
```bash
docker run --rm -v app_postgres-data:/data -v $(pwd):/backup alpine tar czf /backup/postgres-backup.tar.gz -C /data .
```

## Troubleshooting

### Container Won't Start
```bash
docker compose logs [service]
docker compose ps
```

### Database Connection Issues
```bash
docker exec app-postgres pg_isready -U appuser -d appdb
docker compose restart postgres
```

### High Memory Usage
Check resource usage:
```bash
docker stats
```

## Security Updates

Keep your system secure:
```bash
# Update host system
apt update && apt upgrade -y

# Update Docker images
cd /var/www/app
docker compose pull
docker compose up -d
```

## License

Same as original project
