# 🚀 Fullstack VPS Setup & Security Hardening Script

**Transform your Ubuntu VPS into a production-ready, secure fullstack application server in minutes**

[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%20|%2022.04%20|%2024.04-orange)](https://ubuntu.com/)
[![Node.js](https://img.shields.io/badge/Node.js-LTS-green)](https://nodejs.org/)
[![Next.js](https://img.shields.io/badge/Next.js-14-black)](https://nextjs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Latest-blue)](https://postgresql.org/)
[![Tailwind](https://img.shields.io/badge/Tailwind%20CSS-3.4-38bdf8)](https://tailwindcss.com/)
[![PM2](https://img.shields.io/badge/PM2-Process%20Manager-2B3137)](https://pm2.keymetrics.io/)

## 🎯 What Does This Script Do?

This comprehensive script sets up a **complete, production-ready fullstack application** with enterprise-grade security hardening. It's perfect for developers who want to deploy modern web applications quickly and securely.

## ⚡ Quick Start

```bash
# Download and run with defaults
curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-harden/main/fullstack-harden.sh | sudo bash

# Or download first to review
curl -O https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-harden/main/fullstack-harden.sh
chmod +x fullstack-harden.sh
sudo ./fullstack-harden.sh
```

### Configuration Options

```bash
# Custom SSH port
sudo SSH_PORT=2222 ./fullstack-harden.sh

# Enable Cloudflare-only access (recommended)
sudo ENABLE_CLOUDFLARE=yes ./fullstack-harden.sh

# Full configuration
sudo SSH_PORT=2222 ENABLE_CLOUDFLARE=yes ADMIN_EMAIL=admin@example.com ./fullstack-harden.sh
```

## 📋 Installation Steps Explained

### Part 1: Security Hardening 🔒

**What it does:**
- Updates all system packages to latest versions
- Configures automatic security updates (unattended-upgrades)
- Hardens SSH configuration (disables password auth, key-only)
- Sets up Fail2ban to block brute force attempts
- Configures UFW firewall with strict rules
- Applies kernel security parameters
- Creates login banners for legal protection

**Key Security Features:**
- ✅ Password authentication disabled
- ✅ SSH rate limiting
- ✅ Automatic IP blocking after failed attempts
- ✅ SYN flood protection
- ✅ Only ports 22 (or custom), 80, 443 open

### Part 2: Web Server Setup 🌐

**What it does:**
- Installs Nginx as reverse proxy
- Configures proxy for Next.js app (port 3000)
- Sets up API routing to Node.js backend (port 3001)
- Adds security headers (X-Frame-Options, XSS Protection)
- Prepares for Cloudflare SSL configuration

**Nginx Routes:**
- `/` → Next.js frontend (port 3000)
- `/api/*` → Express.js backend (port 3001)
- `/health` → Health check endpoint

### Part 3: Database Setup 🗄️

**What it does:**
- Installs PostgreSQL (latest stable)
- Creates dedicated database and user
- Generates secure random password
- Configures for local connections only
- Creates initial tables with sample data

**Database Details:**
- Database name: `appdb`
- Username: `appuser`
- Password: Auto-generated (shown after install)
- Connection: localhost only (secure)

### Part 4: Node.js & PM2 Setup 📦

**What it does:**
- Installs Node.js LTS version
- Installs PM2 globally for process management
- Configures PM2 to start on system boot
- Sets up PM2 logging directories

**PM2 Features:**
- ✅ Auto-restart on crash
- ✅ Process monitoring
- ✅ Log management
- ✅ Memory limit protection

### Part 5: Application Setup 💻

**What it creates:**

#### Backend (Express.js + PostgreSQL)
- RESTful API with full CRUD operations
- PostgreSQL integration with connection pooling
- Security middleware (Helmet, CORS)
- Environment variables (.env file)
- Endpoints:
  - `GET /api/posts` - List all posts
  - `GET /api/posts/:id` - Get single post
  - `POST /api/posts` - Create post
  - `PUT /api/posts/:id` - Update post
  - `DELETE /api/posts/:id` - Delete post

#### Frontend (Next.js + React + Tailwind)
- Modern React application with TypeScript
- Tailwind CSS for styling
- Responsive design
- Real-time API integration
- Features:
  - Create/Read/Update/Delete posts
  - Beautiful gradient UI
  - Loading states
  - Error handling
  - Mobile responsive

### Part 6: Process Management 🔄

**What it does:**
- Creates PM2 ecosystem configuration
- Starts both frontend and backend apps
- Configures auto-restart policies
- Sets up separate log files for each app
- Saves PM2 configuration for persistence

**PM2 Apps Running:**
- `api` - Express.js backend
- `frontend` - Next.js application

### Part 7: Cloudflare Configuration ☁️

**What it does (when enabled):**
- Restricts HTTP/HTTPS to Cloudflare IPs only
- Downloads latest Cloudflare IP ranges
- Creates weekly cron job to update IPs
- Prevents direct IP access attacks

**To Enable Cloudflare:**
1. Run script with `ENABLE_CLOUDFLARE=yes`
2. Add domain to Cloudflare dashboard
3. Point DNS to your server IP
4. Enable orange proxy cloud
5. Set SSL/TLS to "Flexible" or "Full"

## 📁 Directory Structure

After installation, your application lives in `/var/www/app/`:

```
/var/www/app/
├── api/
│   ├── server.js          # Express API server
│   ├── package.json       # API dependencies
│   └── .env              # Database credentials (auto-generated)
├── frontend/
│   ├── pages/
│   │   └── index.tsx     # Main React page
│   ├── styles/
│   │   └── globals.css   # Tailwind imports
│   ├── package.json      # Frontend dependencies
│   ├── next.config.js    # Next.js configuration
│   ├── tailwind.config.js # Tailwind configuration
│   └── tsconfig.json     # TypeScript config
└── ecosystem.config.js   # PM2 configuration
```

## 🔧 Post-Installation Management

### Managing Your Apps

```bash
# View running applications
pm2 list

# View logs in real-time
pm2 logs

# Restart all applications
pm2 restart all

# Monitor CPU/Memory usage
pm2 monit

# Stop an application
pm2 stop frontend
pm2 stop api

# View specific app logs
pm2 logs frontend
pm2 logs api
```

### Database Access

```bash
# Connect to PostgreSQL
sudo -u postgres psql

# Connect to your app database
psql -U appuser -d appdb -h localhost

# Backup database
pg_dump -U appuser -h localhost appdb > backup.sql
```

### Firewall Management

```bash
# Check firewall status
sudo ufw status numbered

# Add new rule
sudo ufw allow 8080/tcp

# Remove rule
sudo ufw delete [rule-number]

# View detailed status
sudo ufw status verbose
```

### Security Monitoring

```bash
# Check Fail2ban status
sudo fail2ban-client status

# View banned IPs
sudo fail2ban-client status sshd

# Unban an IP
sudo fail2ban-client unban <IP>

# View auth logs
sudo tail -f /var/log/auth.log
```

## 🌐 Accessing Your Application

### Before Cloudflare Setup
- Direct access: `http://YOUR-SERVER-IP`
- API endpoint: `http://YOUR-SERVER-IP/api`

### After Cloudflare Setup
1. Your domain: `https://yourdomain.com`
2. API: `https://yourdomain.com/api`
3. Direct IP access will be blocked (security feature)

## 🔐 Important Security Information

### SSH Access
- **Port**: Check the script output (default 22, or your custom port)
- **Authentication**: SSH keys only (passwords disabled)
- **User Group**: Only users in `sshusers` group can SSH

### Database Credentials
- Saved in `/var/www/app/api/.env`
- Auto-generated secure password
- Local access only (no remote connections)

### Adding SSH Users
```bash
# Add user to SSH access group
sudo usermod -a -G sshusers username
```

## 🚨 Troubleshooting

### Can't Access Website
```bash
# Check if services are running
pm2 list
sudo systemctl status nginx

# Check logs
pm2 logs frontend
sudo tail -f /var/log/nginx/error.log

# Verify firewall rules
sudo ufw status
```

### Database Connection Issues
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# View database logs
sudo tail -f /var/log/postgresql/*.log

# Test connection
psql -U appuser -d appdb -h localhost
```

### SSH Locked Out
1. Use your VPS provider's console (Hetzner, DigitalOcean, etc.)
2. Remove SSH restrictions:
   ```bash
   sudo rm /etc/ssh/sshd_config.d/99-hardening.conf
   sudo systemctl restart ssh
   ```

### Application Errors
```bash
# Check PM2 logs
pm2 logs --lines 100

# Restart applications
pm2 restart all

# Check Node.js errors
pm2 describe api
pm2 describe frontend
```

## 📊 System Requirements

- **OS**: Ubuntu 20.04/22.04/24.04 or Debian 11/12
- **RAM**: Minimum 1GB (2GB recommended)
- **Storage**: At least 10GB free space
- **CPU**: 1 core minimum (2+ recommended)
- **Network**: Public IP address
- **Access**: Root or sudo privileges

## 🤖 AI-Powered Development with Claude Code

After running the main setup script, you can install Claude Code to edit your server directly with AI assistance:

### Quick Setup (One-liner)

```bash
# Install Claude Code and setup AI guide
curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-hardened-fullstack-webserver/main/CLAUDE.md | sudo tee /root/CLAUDE.md > /dev/null && \
npm install -g @anthropic-ai/claude-code && \
echo "✅ Claude Code installed! Run 'claude' in any directory to start AI-assisted coding"
```

### What This Does

1. **Downloads CLAUDE.md** - An AI guide that explains your server architecture to Claude
2. **Installs Claude Code** - Command-line tool for AI-powered development
3. **Enables AI coding** - You can now use `claude` command anywhere in your server

### Using Claude Code

Once installed, you can use Claude directly in your server:

```bash
# Start Claude in any directory
claude

# Examples of what you can ask:
# "Update the frontend to add a dark mode toggle"
# "Add a new API endpoint for user authentication"
# "Modify the database schema to include a users table"
# "Change the UI colors to a blue theme"
# "Add rate limiting to the API"
```

Claude will:
- Understand your server structure (thanks to CLAUDE.md)
- Edit files directly
- Rebuild and restart services automatically
- Follow security best practices
- Show you what changes are being made

### Important Notes

- Claude has full context of your server setup via the CLAUDE.md file
- All changes are made safely with PM2 managing restarts
- Claude won't modify security settings or SSH configuration
- You can review all changes Claude makes in real-time

### Example Claude Session

```bash
cd /var/www/app
claude

# You: "Add a dark mode toggle to the frontend"
# Claude will:
# 1. Edit /var/www/app/frontend/pages/index.tsx
# 2. Update Tailwind classes for dark mode
# 3. Run npm run build
# 4. Restart frontend with PM2
# 5. Confirm the changes are live
```

---

## 🎯 What You Get

After running this script, you have:

1. **Secure Server** - Hardened with industry best practices
2. **Modern Stack** - Next.js + Node.js + PostgreSQL
3. **Beautiful UI** - Tailwind CSS with gradient design
4. **API Ready** - Full CRUD REST API
5. **Process Management** - PM2 handling crashes/restarts
6. **CDN Ready** - Cloudflare integration built-in
7. **Monitoring** - Logs and security monitoring tools
8. **Production Ready** - Everything configured for production use

## 🔄 Updating Your Application

To deploy your own code:

1. **Backend Changes**:
   ```bash
   cd /var/www/app/api
   # Edit server.js or add new files
   pm2 restart api
   ```

2. **Frontend Changes**:
   ```bash
   cd /var/www/app/frontend
   # Edit pages or components
   npm run build
   pm2 restart frontend
   ```

3. **Database Changes**:
   ```bash
   psql -U appuser -d appdb -h localhost
   # Run your SQL commands
   ```

## 📝 Environment Variables

The script creates `/var/www/app/api/.env` with:
```env
DB_NAME=appdb
DB_USER=appuser
DB_PASS=[auto-generated]
DB_HOST=localhost
DB_PORT=5432
API_PORT=3001
NODE_ENV=production
```

Modify as needed for your application.

## ⚠️ Important Notes

1. **Always test SSH access** in a new terminal before closing your current session
2. **Save database credentials** shown after installation
3. **Configure Cloudflare** separately in their dashboard
4. **Regular backups** are your responsibility
5. **Monitor logs** regularly for security events

## 🤝 Support & Contributions

- Report issues: [GitHub Issues](https://github.com/MarcoWorms/ubuntu-vps-harden/issues)
- Contributions welcome via Pull Requests
- Star the repo if it helped you!

## 📜 License

MIT License - Use freely for personal or commercial projects.

---

**Remember**: This script provides a strong foundation, but ongoing maintenance, updates, and monitoring are essential for production systems. Always follow security best practices and keep your applications updated.
