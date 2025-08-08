You are located at `/` 

You are currently working on a **hardened Ubuntu VPS** that has been configured with a fullstack application.

## 🏗️ Server Architecture

This is a production-ready Ubuntu server with:
- **Security**: UFW firewall, Fail2ban, SSH hardening
- **Web Server**: Nginx (reverse proxy)
- **Backend**: Node.js + Express.js API
- **Frontend**: Next.js with React and Tailwind CSS
- **Database**: PostgreSQL (local only)
- **Process Manager**: PM2 (keeps apps running)

## 📁 Application Structure

The main application is located at `/var/www/app/`:

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

## 🔧 Common Tasks

### 1. Editing the Backend API

To modify the Express.js backend:

```bash
# Navigate to API directory
cd /var/www/app/api

# Edit the server file
nano server.js
# or
vim server.js

# After making changes, restart the API
pm2 restart api

# Check if it's running properly
pm2 status api
pm2 logs api --lines 50
```

**Important files:**
- `server.js` - Main API logic and routes
- `.env` - Environment variables (database credentials)
- `package.json` - Dependencies

### 2. Editing the Frontend

To modify the Next.js frontend:

```bash
# Navigate to frontend directory
cd /var/www/app/frontend

# Edit the main page
nano pages/index.tsx

# After making changes, rebuild the frontend
npm run build

# Restart the frontend
pm2 restart frontend

# Check status
pm2 status frontend
pm2 logs frontend --lines 50
```

**Important files:**
- `pages/index.tsx` - Main React component
- `styles/globals.css` - Tailwind CSS imports
- `tailwind.config.js` - Tailwind configuration

### 3. Database Operations

The PostgreSQL database credentials are in `/var/www/app/api/.env`:

```bash
# View database credentials
cat /var/www/app/api/.env

# Connect to PostgreSQL as the app user
psql -U appuser -d appdb -h localhost

# Common SQL operations:
# List all tables
\dt

# View posts table structure
\d posts

# Query data
SELECT * FROM posts;

# Insert new data
INSERT INTO posts (title, content) VALUES ('New Post', 'Content here');

# Exit PostgreSQL
\q
```

### 4. Adding New Dependencies

#### For Backend (API):
```bash
cd /var/www/app/api
npm install package-name
pm2 restart api
```

#### For Frontend:
```bash
cd /var/www/app/frontend
npm install package-name
npm run build
pm2 restart frontend
```

### 5. Viewing Logs

```bash
# View all PM2 apps status
pm2 list

# View combined logs
pm2 logs

# View specific app logs
pm2 logs api
pm2 logs frontend

# View system logs
tail -f /var/log/nginx/error.log
tail -f /var/log/auth.log
```

## 🚀 Deployment Workflow

When the user asks you to update code:

1. **Make the changes** in the appropriate file
   
2. **For API changes:**
   ```bash
   cd /var/www/app/api
   # Edit files
   pm2 restart api
   ```

3. **For Frontend changes:**
   ```bash
   cd /var/www/app/frontend
   # Edit files
   npm run build
   pm2 restart frontend
   ```

4. **Verify the changes:**
   ```bash
   pm2 status
   pm2 logs --lines 20
   ```

## 🔒 Security Considerations

**DO NOT:**
- ❌ Change firewall rules without careful consideration
- ❌ Modify SSH configuration (could lock out user)
- ❌ Expose database to external connections
- ❌ Disable fail2ban or security features
- ❌ Share the contents of `.env` files publicly

**ALWAYS:**
- ✅ Test changes in development first if possible
- ✅ Keep backups before major changes
- ✅ Restart services after configuration changes
- ✅ Check logs after making changes
- ✅ Use PM2 to manage Node.js processes

## 📊 Server Information Commands

```bash
# Check disk space
df -h

# Check memory usage
free -h

# Check running processes
pm2 list
pm2 monit

# Check firewall status
sudo ufw status

# Check fail2ban status
sudo fail2ban-client status

# Check nginx status
sudo systemctl status nginx

# Check PostgreSQL status
sudo systemctl status postgresql
```

## 🆘 Troubleshooting

### If the website is down:
```bash
# Check PM2 processes
pm2 list
pm2 restart all

# Check Nginx
sudo systemctl restart nginx

# Check logs
pm2 logs --lines 100
```

### If API errors occur:
```bash
# Check API logs
pm2 logs api --lines 100

# Check database connection
psql -U appuser -d appdb -h localhost -c "SELECT 1;"

# Restart API
pm2 restart api
```

### If frontend won't build:
```bash
cd /var/www/app/frontend
npm install  # Reinstall dependencies
npm run build
pm2 restart frontend
```

## 📝 Important Notes for Claude

1. **Current Directory**: Always check where you are with `pwd`
2. **File Permissions**: Use `sudo` when editing system files
3. **PM2 Management**: Always use PM2 to start/stop/restart apps
4. **Build Step**: Frontend changes require `npm run build`
5. **Environment Variables**: Database credentials are in `/var/www/app/api/.env`
6. **Nginx Config**: Located at `/etc/nginx/sites-available/default`
7. **Ports**: API runs on 3001, Frontend on 3000, Nginx on 80/443

## 🌐 Network Architecture

```
Internet → Cloudflare (optional) → Nginx (port 80/443)
                                     ↓
                    ┌─────────────────────────────────┐
                    │                                 │
                    ↓                                 ↓
            Next.js Frontend (3000)         Express API (3001)
                    │                                 │
                    └──────── Proxied by Nginx ──────┘
                                                      │
                                                      ↓
                                            PostgreSQL (5432)
```

## 🔄 Quick Reference

| Task | Command |
|------|---------|
| Restart Backend | `pm2 restart api` |
| Restart Frontend | `pm2 restart frontend` |
| Rebuild Frontend | `cd /var/www/app/frontend && npm run build` |
| View All Logs | `pm2 logs` |
| Check Status | `pm2 status` |
| Database Shell | `psql -U appuser -d appdb -h localhost` |
| Edit API | `nano /var/www/app/api/server.js` |
| Edit Frontend | `nano /var/www/app/frontend/pages/index.tsx` |
| Check Firewall | `sudo ufw status` |

---
