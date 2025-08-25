# VPS Server Guide

You are located at `/` 

You are currently working on a hardened Ubuntu VPS that has been configured with a fullstack application.

## 🏗️ Server Architecture

### Traditional Setup
If using the traditional setup, this is a production-ready Ubuntu server with:
- Security: UFW firewall, Fail2ban, SSH hardening
- Web Server: Nginx (reverse proxy)
- Backend: Node.js + Express.js API (PM2 managed)
- Frontend: Next.js with React and Tailwind CSS (PM2 managed)
- Database: PostgreSQL (system service)
- Process Manager: PM2 (keeps apps running)

### Docker Setup
If using the Docker setup, this is a production-ready Ubuntu server with:
- Security: UFW firewall, Fail2ban, SSH hardening
- Web Server: Nginx (reverse proxy on host)
- Backend: Node.js + Express.js API (Docker container using official Node image)
- Frontend: Next.js with React and Tailwind CSS (Docker container using official Node image)
- Database: PostgreSQL (Docker container)
- Orchestration: Docker Compose

## 📁 Application Structure

The main application is located at `/var/www/app/`:

### Traditional Setup Structure
```
/var/www/app/
├── api/                    # Backend API
│   ├── server.js          # Express server (main API file)
│   ├── package.json       # API dependencies
│   └── .env              # Database credentials
├── frontend/              # Next.js frontend
│   ├── pages/
│   │   └── index.tsx     # Main page (React component)
│   ├── styles/
│   │   └── globals.css   # Tailwind CSS imports
│   ├── package.json      # Frontend dependencies
│   ├── next.config.js    # Next.js configuration
│   └── tailwind.config.js # Tailwind configuration
└── ecosystem.config.js    # PM2 configuration
```

### Docker Setup Structure
```
/var/www/app/
├── api/                    # Backend API
│   ├── server.js          # Express server
│   └── package.json       # API dependencies
├── frontend/              # Next.js frontend (App Router)
│   ├── app/
│   │   └── page.tsx      # Main page (React component)
│   ├── app/globals.css   # Tailwind CSS imports
│   ├── package.json      # Frontend dependencies
│   ├── next.config.js    # Next.js configuration
│   └── tailwind.config.js # Tailwind configuration
├── postgres-data/         # PostgreSQL data (persistent)
├── docker-compose.yml     # Docker orchestration
├── .env                  # Environment variables
└── init-db.sql           # Database initialization
```

## 🔧 Common Tasks

### For Traditional Setup

#### 1. Editing the Backend API
```bash
# Navigate to API directory
cd /var/www/app/api

# Edit the server file
nano server.js

# After making changes, restart the API
pm2 restart api
```

#### 2. Viewing Logs
```bash
# View all PM2 logs
pm2 logs

# View specific service logs
pm2 logs api
pm2 logs frontend

# View Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log
```

#### 3. Database Access
```bash
# Connect to PostgreSQL
sudo -u postgres psql -d appdb

# Common database commands:
\dt              # List tables
\d posts         # Describe posts table
SELECT * FROM posts;  # Query data
\q               # Quit
```

### For Docker Setup

#### 1. Editing the Backend API
```bash
# Navigate to app directory
cd /var/www/app

# Edit the server file
nano api/server.js

# After making changes, restart the API container
docker compose restart api
```

If you changed dependencies (package.json), restart will reinstall inside the container on start. If needed:
```bash
docker compose up -d --force-recreate --no-deps api
```

#### 2. Viewing Logs
```bash
# View all container logs
docker compose logs -f

# View specific service logs
docker compose logs -f api
docker compose logs -f frontend
docker compose logs -f postgres

# View Nginx logs (still on host)
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log
```

#### 3. Database Access
```bash
# Connect to PostgreSQL
docker exec -it app-postgres psql -U appuser -d appdb

# Or run SQL directly
docker exec app-postgres psql -U appuser -d appdb -c "SELECT * FROM posts;"
```

#### 4. Container Management
```bash
# View running containers
docker compose ps

# Restart a service
docker compose restart api

# Stop all services
docker compose down

# Start all services
docker compose up -d

# Update base images and restart
docker compose pull
docker compose up -d
```

## 🚀 Service Management

### Traditional Setup
```bash
# PM2 Commands
pm2 status          # Check service status
pm2 restart all     # Restart all services
pm2 save           # Save current process list
pm2 startup        # Configure PM2 to start on boot

# System Services
sudo systemctl status nginx
sudo systemctl status postgresql
sudo systemctl restart nginx
```

### Docker Setup
```bash
# Docker Compose Commands
docker compose ps              # Check container status
docker compose restart         # Restart all containers
docker compose down           # Stop all containers
docker compose up -d          # Start all containers
docker compose logs -f        # Follow all logs

# System Services (still on host)
sudo systemctl status nginx
sudo systemctl status docker
sudo systemctl restart nginx
```

## 🔒 Security Notes

1. Firewall: UFW is configured. Check rules with `sudo ufw status`
2. SSH: Only key-based authentication is allowed
3. Fail2ban: Monitors and blocks suspicious IPs. Check with `sudo fail2ban-client status`
4. Updates: Automatic security updates are enabled

## 📊 Monitoring

### Traditional Setup
```bash
# Check resource usage
htop

# Check PM2 process metrics
pm2 monit

# Check disk usage
df -h

# Check memory usage
free -h
```

### Docker Setup
```bash
# Check container resource usage
docker stats

# Check individual container
docker compose top

# Check disk usage
df -h
docker system df

# Check container health
docker compose ps
```

## 🆘 Troubleshooting

### Traditional Setup
```bash
# If frontend is down
pm2 restart frontend
pm2 logs frontend --lines 50

# If API is down
pm2 restart api
pm2 logs api --lines 50
```

### Docker Setup
```bash
# If frontend is down
docker compose restart frontend
docker compose logs frontend --tail=100

# If API is down
docker compose restart api
docker compose logs api --tail=100

# If database is down
docker compose restart postgres
docker compose logs postgres --tail=100
```
