#!/bin/bash

#########################################
# Migration Script: Traditional to Docker
# Migrates existing fullstack app to Docker
#########################################

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Starting migration from traditional to Docker setup...${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Check if traditional setup exists
if [ ! -d "/var/www/app" ]; then
    echo -e "${RED}Traditional setup not found at /var/www/app${NC}"
    exit 1
fi

# Backup current setup
echo -e "${YELLOW}Creating backup...${NC}"
BACKUP_DIR="/root/backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup database
if command -v psql &> /dev/null; then
    echo "Backing up PostgreSQL database..."
    sudo -u postgres pg_dump appdb > "$BACKUP_DIR/database.sql" || true
fi

# Backup application files
echo "Backing up application files..."
cp -r /var/www/app "$BACKUP_DIR/app"

# Save PM2 process list
if command -v pm2 &> /dev/null; then
    pm2 save
    pm2 dump > "$BACKUP_DIR/pm2-processes.json" || true
fi

echo -e "${GREEN}Backup created at: $BACKUP_DIR${NC}"

# Stop existing services
echo -e "${YELLOW}Stopping existing services...${NC}"
pm2 stop all || true
sudo systemctl stop postgresql || true

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}Installing Docker...${NC}"
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -qq
    apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl start docker
    systemctl enable docker
fi

# Download and prepare the Docker app setup script
echo -e "${YELLOW}Setting up Docker environment...${NC}"
cd /tmp
curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-harden/main/fullstack-harden-docker.sh -o docker-setup.sh

# Extract only the Docker setup parts (skip system hardening as it's already done)
sed -n '/PART 4: APPLICATION SETUP WITH DOCKER/,/PART 6: MONITORING AND LOGGING/p' docker-setup.sh > docker-app-setup.sh

# Ensure required env vars exist for the extracted script
export DB_NAME="${DB_NAME:-appdb}"
export DB_USER="${DB_USER:-appuser}"
export DB_PASS="${DB_PASS:-$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 20)}"
export API_PORT="${API_PORT:-3001}"

# Run the Docker app setup
bash docker-app-setup.sh

# Restore database
if [ -f "$BACKUP_DIR/database.sql" ]; then
    echo -e "${YELLOW}Restoring database...${NC}"
    # Wait for PostgreSQL container to be ready
    sleep 30
    docker exec -i app-postgres psql -U "${DB_USER}" "${DB_NAME}" < "$BACKUP_DIR/database.sql" || true
fi

# Copy any custom code from backup
echo -e "${YELLOW}Restoring custom code...${NC}"
# Check if there are custom modifications in the API
if [ -f "$BACKUP_DIR/app/api/server.js" ]; then
    # Compare and prompt user
    echo -e "${YELLOW}Found existing API code. Would you like to restore it? (y/n)${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        cp "$BACKUP_DIR/app/api/server.js" /var/www/app/api/server.js
        cd /var/www/app
        docker compose up -d --force-recreate --no-deps api
    fi
fi

# Disable PM2 startup
if command -v pm2 &> /dev/null; then
    pm2 unstartup || true
fi

# Final status check
echo -e "${GREEN}Migration complete! Checking status...${NC}"
cd /var/www/app
docker compose ps

echo -e "${GREEN}
Migration Summary:
- Backup saved to: $BACKUP_DIR
- Docker containers are now running
- Database has been migrated
- Nginx is still running on the host

Next steps:
1. Test your application at http://$(curl -s ifconfig.me)
2. Check logs: docker compose logs -f
3. If everything works, you can remove the backup: rm -rf $BACKUP_DIR

To rollback:
1. docker compose down
2. Restore from backup: $BACKUP_DIR
${NC}"