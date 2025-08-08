#!/bin/bash

#########################################
# Fullstack VPS Hardening & Setup Script
# For Ubuntu/Debian based systems
# Includes: Security hardening + Nginx + Node.js + PostgreSQL + PM2 + Next.js
#########################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
SSH_PORT=${SSH_PORT:-22}
ADMIN_EMAIL=${ADMIN_EMAIL:-""}
ENABLE_CLOUDFLARE=${ENABLE_CLOUDFLARE:-"no"}
DB_NAME="appdb"
DB_USER="appuser"
# Generate a safe password without problematic characters
DB_PASS=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 20)
APP_PORT=3000
API_PORT=3001

# Paths
APP_DIR="/var/www/app"
LOG_FILE="/var/log/vps-setup.log"

# Function to log messages
log_message() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO:${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    log_error "Cannot detect OS version"
    exit 1
fi

log_message "Starting Fullstack VPS Setup & Hardening..."
log_message "Detected OS: $OS $VER"

# Set non-interactive mode
export DEBIAN_FRONTEND=noninteractive

# Pre-configure packages
log_message "Pre-configuring package selections..."
echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections
echo "postfix postfix/mailname string $(hostname)" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections

#########################################
# PART 1: SECURITY HARDENING
#########################################

log_message "=== PART 1: SECURITY HARDENING ==="

# System Updates
log_message "Updating system packages..."
apt-get update -y
apt-get upgrade -y -q
apt-get dist-upgrade -y -q
apt-get autoremove -y
apt-get autoclean -y

# Configure Automatic Updates
log_message "Setting up automatic security updates..."
apt-get install -y -q unattended-upgrades apt-listchanges

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOCONFIG'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
    "${distro_id}:${distro_codename}-updates";
};
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOCONFIG

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOCONFIG'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOCONFIG

# SSH Hardening
log_message "Hardening SSH configuration..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

groupadd -f sshusers
usermod -a -G sshusers root

# Add common users to sshusers
for user in ubuntu debian admin; do
    if id "$user" &>/dev/null; then
        usermod -a -G sshusers "$user"
        log_message "Added $user to sshusers group"
    fi
done

mkdir -p /etc/ssh/sshd_config.d/
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOCONFIG
Port $SSH_PORT
Protocol 2
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
AllowGroups sshusers
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
X11Forwarding no
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
UsePAM yes
Banner /etc/issue.net
EOCONFIG

# Install Fail2ban
log_message "Installing and configuring Fail2ban..."
apt-get install -y -q fail2ban

cat > /etc/fail2ban/jail.local <<EOCONFIG
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

# SSH Protection - Critical
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200

[sshd-ddos]
enabled = true
port = $SSH_PORT
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 10
bantime = 3600

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = iptables-allports[name=recidive]
bantime = 86400
maxretry = 3
EOCONFIG

# Create SSH DDoS filter
cat > /etc/fail2ban/filter.d/sshd-ddos.conf <<'EOCONFIG'
[Definition]
failregex = ^.*sshd.*: (Connection closed by|Received disconnect from|Connection reset by) <HOST>.*$
            ^.*sshd.*: (Did not receive identification string from) <HOST>.*$
ignoreregex =
EOCONFIG

systemctl enable fail2ban
systemctl restart fail2ban

# Configure UFW Firewall
log_message "Configuring UFW firewall..."
apt-get install -y -q ufw

ufw --force disable
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward

# Allow SSH
ufw allow $SSH_PORT/tcp comment 'SSH'
ufw limit $SSH_PORT/tcp

# Allow web traffic (will be restricted to Cloudflare if enabled later)
if [ "$ENABLE_CLOUDFLARE" != "yes" ]; then
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
fi

ufw logging low
echo "y" | ufw enable

log_message "UFW firewall enabled"

# Kernel Hardening
log_message "Applying kernel hardening..."
cat > /etc/sysctl.d/99-hardening.conf <<'EOCONFIG'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOCONFIG

sysctl -p /etc/sysctl.d/99-hardening.conf

# Login Banner
cat > /etc/issue.net <<'EOCONFIG'
********************************************************************
*                       AUTHORIZED ACCESS ONLY                     *
* Unauthorized access to this system is forbidden and will be     *
* prosecuted by law. By accessing this system, you agree that     *
* your actions may be monitored and recorded.                     *
********************************************************************
EOCONFIG

#########################################
# PART 2: WEB SERVER SETUP
#########################################

log_message "=== PART 2: WEB SERVER SETUP ==="

# Install Nginx
log_message "Installing Nginx..."
apt-get install -y -q nginx

# Configure Nginx - Fixed version without SSL issues
log_message "Configuring Nginx..."
cat > /etc/nginx/sites-available/default <<'EOCONFIG'
# HTTP Server - Works with Cloudflare Flexible SSL
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Get real IP from Cloudflare
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 131.0.72.0/22;
    real_ip_header CF-Connecting-IP;
    
    # Main app (Next.js)
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 90;
    }
    
    # API routes - FIXED: proper routing
    location /api {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 90;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOCONFIG

# Test and reload Nginx
nginx -t && systemctl reload nginx
systemctl enable nginx

#########################################
# PART 3: DATABASE SETUP
#########################################

log_message "=== PART 3: DATABASE SETUP ==="

# Install PostgreSQL
log_message "Installing PostgreSQL..."
apt-get install -y -q postgresql postgresql-contrib

# Start PostgreSQL
systemctl start postgresql
systemctl enable postgresql

# Wait for PostgreSQL to be ready
sleep 5

# Create database and user
log_message "Setting up PostgreSQL database..."
sudo -u postgres psql <<EOSQL
CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';
CREATE DATABASE $DB_NAME OWNER $DB_USER;
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
ALTER DATABASE $DB_NAME SET timezone TO 'UTC';
\q
EOSQL

# Configure PostgreSQL for local connections
PG_VERSION=$(sudo -u postgres psql -t -c "SELECT version();" | awk '{print $3}' | sed 's/\..*//')
PG_CONFIG="/etc/postgresql/$PG_VERSION/main/postgresql.conf"
if [ -f "$PG_CONFIG" ]; then
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = 'localhost'/" "$PG_CONFIG"
fi

# Update pg_hba.conf to trust local connections for the app user
PG_HBA="/etc/postgresql/$PG_VERSION/main/pg_hba.conf"
if [ -f "$PG_HBA" ]; then
    echo "host    $DB_NAME    $DB_USER    127.0.0.1/32    md5" >> "$PG_HBA"
fi

# Restart PostgreSQL
systemctl restart postgresql

#########################################
# PART 4: NODE.JS & PM2 SETUP
#########################################

log_message "=== PART 4: NODE.JS & PM2 SETUP ==="

# Install Node.js LTS
log_message "Installing Node.js LTS..."
curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
apt-get install -y nodejs

# Install build essentials for npm packages
apt-get install -y build-essential

# Install PM2 globally
log_message "Installing PM2..."
npm install -g pm2

# Setup PM2 to start on boot
pm2 startup systemd -u root --hp /root
systemctl enable pm2-root

#########################################
# PART 5: APPLICATION SETUP
#########################################

log_message "=== PART 5: APPLICATION SETUP ==="

# Create app directory
log_message "Creating application structure..."
mkdir -p $APP_DIR/{api,frontend}
cd $APP_DIR

# Create API (Express + PostgreSQL)
log_message "Setting up Express API..."
cd $APP_DIR/api

cat > package.json <<'EOFILE'
{
  "name": "api",
  "version": "1.0.0",
  "description": "Example API with PostgreSQL",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "pg": "^8.11.3",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "helmet": "^7.1.0",
    "morgan": "^1.10.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
EOFILE

# Create .env file for API
cat > .env <<EOFILE
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
DB_HOST=localhost
DB_PORT=5432
API_PORT=$API_PORT
NODE_ENV=production
EOFILE

# Create API server - FIXED: connection and error handling
cat > server.js <<'EOFILE'
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const port = process.env.API_PORT || 3001;

// Middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost'],
  credentials: true
}));
app.use(express.json());
app.use(morgan('combined'));

// PostgreSQL connection with better error handling
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000,
  max: 20
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected successfully at:', res.rows[0].now);
  }
});

// Initialize database table
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS posts (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Check if table is empty and add sample data
    const result = await pool.query('SELECT COUNT(*) FROM posts');
    if (parseInt(result.rows[0].count) === 0) {
      await pool.query(`
        INSERT INTO posts (title, content) VALUES 
        ('Welcome to your VPS!', 'Your fullstack application is running successfully.'),
        ('Security First', 'This server has been hardened with security best practices.'),
        ('Ready for Development', 'You can now build your application on this foundation.')
      `);
      console.log('Sample data inserted');
    }
    
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
    console.error('Make sure PostgreSQL is running and credentials are correct');
  }
}

// Routes
app.get('/api', (req, res) => {
  res.json({ 
    message: 'API is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
    database: pool.totalCount > 0 ? 'connected' : 'disconnected'
  });
});

// GET all posts
app.get('/api/posts', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM posts ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching posts:', err);
    res.status(500).json({ error: 'Failed to fetch posts', details: err.message });
  }
});

// GET single post
app.get('/api/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM posts WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching post:', err);
    res.status(500).json({ error: 'Failed to fetch post' });
  }
});

// POST new post
app.post('/api/posts', async (req, res) => {
  try {
    const { title, content } = req.body;
    
    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }
    
    const result = await pool.query(
      'INSERT INTO posts (title, content) VALUES ($1, $2) RETURNING *',
      [title, content || '']
    );
    
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error creating post:', err);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// UPDATE post
app.put('/api/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content } = req.body;
    
    const result = await pool.query(
      'UPDATE posts SET title = $1, content = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING *',
      [title, content, id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating post:', err);
    res.status(500).json({ error: 'Failed to update post' });
  }
});

// DELETE post
app.delete('/api/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM posts WHERE id = $1 RETURNING id', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    res.json({ message: 'Post deleted successfully', id: result.rows[0].id });
  } catch (err) {
    console.error('Error deleting post:', err);
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

// Health check
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ 
      status: 'healthy', 
      uptime: process.uptime(),
      database: 'connected'
    });
  } catch (err) {
    res.status(503).json({ 
      status: 'unhealthy', 
      database: 'disconnected',
      error: err.message 
    });
  }
});

// Start server
app.listen(port, '127.0.0.1', () => {
  console.log(`API server running on port ${port}`);
  initDB();
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  pool.end(() => {
    console.log('Database pool closed');
    process.exit(0);
  });
});
EOFILE

# Install API dependencies
npm install

# Create Next.js Frontend
log_message "Setting up Next.js frontend..."
cd $APP_DIR/frontend

# Create package.json for Next.js
cat > package.json <<'EOFILE'
{
  "name": "frontend",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start -p 3000",
    "lint": "next lint"
  },
  "dependencies": {
    "next": "14.0.4",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "axios": "^1.6.2"
  },
  "devDependencies": {
    "eslint": "^8.55.0",
    "eslint-config-next": "14.0.4",
    "@types/node": "^20.10.5",
    "@types/react": "^18.2.45",
    "@types/react-dom": "^18.2.18",
    "typescript": "^5.3.3",
    "tailwindcss": "^3.4.0",
    "autoprefixer": "^10.4.16",
    "postcss": "^8.4.32"
  }
}
EOFILE

# Create Next.js config - FIXED: proper API proxy
cat > next.config.js <<'EOFILE'
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://localhost:3001/api/:path*',
      },
    ];
  },
}

module.exports = nextConfig
EOFILE

# Create tsconfig.json
cat > tsconfig.json <<'EOFILE'
{
  "compilerOptions": {
    "target": "es5",
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "forceConsistentCasingInFileNames": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "node",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "paths": {
      "@/*": ["./*"]
    }
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx"],
  "exclude": ["node_modules"]
}
EOFILE

# Create pages directory
mkdir -p pages styles

# Create Tailwind config
cat > tailwind.config.js <<'EOFILE'
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
EOFILE

# Create PostCSS config
cat > postcss.config.js <<'EOFILE'
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
EOFILE

# Create main page - FIXED: proper error handling and loading states
cat > pages/index.tsx <<'EOFILE'
import React, { useState, useEffect } from 'react';
import axios from 'axios';

interface Post {
  id: number;
  title: string;
  content: string;
  created_at: string;
}

export default function Home() {
  const [posts, setPosts] = useState<Post[]>([]);
  const [newPost, setNewPost] = useState({ title: '', content: '' });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [apiStatus, setApiStatus] = useState<'checking' | 'connected' | 'error'>('checking');

  useEffect(() => {
    checkApiStatus();
    fetchPosts();
  }, []);

  const checkApiStatus = async () => {
    try {
      const response = await axios.get('/api/health');
      setApiStatus('connected');
    } catch (err) {
      console.error('API health check failed:', err);
      setApiStatus('error');
    }
  };

  const fetchPosts = async () => {
    try {
      setLoading(true);
      setError('');
      const response = await axios.get('/api/posts');
      setPosts(response.data);
    } catch (err: any) {
      console.error('Failed to fetch posts:', err);
      setError(err.response?.data?.details || 'Failed to fetch posts. Make sure the API is running.');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPost.title.trim()) return;

    try {
      setError('');
      const response = await axios.post('/api/posts', newPost);
      setPosts([response.data, ...posts]);
      setNewPost({ title: '', content: '' });
    } catch (err: any) {
      console.error('Failed to create post:', err);
      setError(err.response?.data?.error || 'Failed to create post');
    }
  };

  const handleDelete = async (id: number) => {
    try {
      setError('');
      await axios.delete(`/api/posts/${id}`);
      setPosts(posts.filter(post => post.id !== id));
    } catch (err: any) {
      console.error('Failed to delete post:', err);
      setError(err.response?.data?.error || 'Failed to delete post');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-600 via-purple-700 to-indigo-800">
      <div className="container mx-auto px-4 py-8 max-w-7xl">
        {/* Header */}
        <header className="text-center text-white mb-12">
          <h1 className="text-5xl md:text-6xl font-bold mb-4 flex items-center justify-center">
            <span className="mr-3">🚀</span>
            Fullstack VPS Application
          </h1>
          <p className="text-xl md:text-2xl text-purple-100 opacity-90">
            Your secure, modern web application is running!
          </p>
        </header>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-12">
          <div className="bg-white/90 backdrop-blur-sm rounded-xl p-6 text-center transform hover:scale-105 transition-transform shadow-xl">
            <h3 className="text-lg font-semibold text-purple-700 mb-2 flex items-center justify-center">
              <span className="mr-2 text-2xl">✅</span>
              Server Status
            </h3>
            <p className="text-gray-700">Hardened & Secure</p>
          </div>
          
          <div className="bg-white/90 backdrop-blur-sm rounded-xl p-6 text-center transform hover:scale-105 transition-transform shadow-xl">
            <h3 className="text-lg font-semibold text-purple-700 mb-2 flex items-center justify-center">
              <span className="mr-2 text-2xl">🔒</span>
              Security
            </h3>
            <p className="text-gray-700">UFW + Fail2ban Active</p>
          </div>
          
          <div className="bg-white/90 backdrop-blur-sm rounded-xl p-6 text-center transform hover:scale-105 transition-transform shadow-xl">
            <h3 className="text-lg font-semibold text-purple-700 mb-2 flex items-center justify-center">
              <span className="mr-2 text-2xl">🌐</span>
              Stack
            </h3>
            <p className="text-gray-700">Next.js + Node + PostgreSQL</p>
          </div>
          
          <div className="bg-white/90 backdrop-blur-sm rounded-xl p-6 text-center transform hover:scale-105 transition-transform shadow-xl">
            <h3 className="text-lg font-semibold text-purple-700 mb-2 flex items-center justify-center">
              <span className={`mr-2 text-2xl ${apiStatus === 'connected' ? '🟢' : apiStatus === 'error' ? '🔴' : '🟡'}`}>
              </span>
              API Status
            </h3>
            <p className="text-gray-700">
              {apiStatus === 'connected' ? 'Connected' : apiStatus === 'error' ? 'Disconnected' : 'Checking...'}
            </p>
          </div>
        </div>

        {/* Main Content */}
        <main className="bg-white rounded-2xl shadow-2xl p-8 mb-8">
          {/* Error Display */}
          {error && (
            <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-4 flex justify-between items-center">
              <span>{error}</span>
              <button onClick={() => setError('')} className="text-red-800 hover:text-red-900">✕</button>
            </div>
          )}

          {/* Create Post Section */}
          <section className="mb-10 pb-8 border-b-2 border-gray-100">
            <h2 className="text-3xl font-bold text-gray-800 mb-6">Create New Post</h2>
            <form onSubmit={handleSubmit} className="space-y-4">
              <input
                type="text"
                placeholder="Post title..."
                value={newPost.title}
                onChange={(e) => setNewPost({ ...newPost, title: e.target.value })}
                className="w-full px-4 py-3 border-2 border-gray-200 rounded-lg focus:border-purple-500 focus:outline-none transition-colors"
                required
              />
              <textarea
                placeholder="Post content..."
                value={newPost.content}
                onChange={(e) => setNewPost({ ...newPost, content: e.target.value })}
                rows={4}
                className="w-full px-4 py-3 border-2 border-gray-200 rounded-lg focus:border-purple-500 focus:outline-none transition-colors resize-none"
              />
              <button
                type="submit"
                className="bg-gradient-to-r from-purple-600 to-indigo-600 text-white font-semibold px-8 py-3 rounded-lg hover:from-purple-700 hover:to-indigo-700 transform hover:-translate-y-0.5 transition-all shadow-lg hover:shadow-xl"
              >
                Create Post
              </button>
            </form>
          </section>

          {/* Posts Section */}
          <section>
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-3xl font-bold text-gray-800">Posts from Database</h2>
              <button 
                onClick={fetchPosts}
                className="text-purple-600 hover:text-purple-700 font-medium"
              >
                🔄 Refresh
              </button>
            </div>
            
            {loading && (
              <div className="flex justify-center py-8">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-600"></div>
              </div>
            )}
            
            {!loading && posts.length === 0 && (
              <p className="text-gray-500 text-center py-8">
                {apiStatus === 'error' 
                  ? 'Cannot connect to database. Check if the API is running.'
                  : 'No posts yet. Create one above!'}
              </p>
            )}
            
            <div className="grid gap-4">
              {posts.map((post) => (
                <article
                  key={post.id}
                  className="bg-gradient-to-r from-purple-50 to-indigo-50 p-6 rounded-xl border-l-4 border-purple-500 hover:shadow-lg transition-shadow"
                >
                  <h3 className="text-xl font-semibold text-gray-800 mb-2">
                    {post.title}
                  </h3>
                  <p className="text-gray-600 mb-4 leading-relaxed">
                    {post.content}
                  </p>
                  <div className="flex justify-between items-center">
                    <small className="text-gray-500">
                      {new Date(post.created_at).toLocaleDateString('en-US', {
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric'
                      })}
                    </small>
                    <button
                      onClick={() => handleDelete(post.id)}
                      className="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors hover:shadow-md"
                    >
                      Delete
                    </button>
                  </div>
                </article>
              ))}
            </div>
          </section>
        </main>

        {/* Footer */}
        <footer className="bg-white/90 backdrop-blur-sm rounded-2xl shadow-2xl p-8 text-center">
          <div className="space-y-3">
            <p className="text-gray-700">
              <span className="font-semibold">📁 Application Directory:</span>{' '}
              <code className="bg-gray-100 px-2 py-1 rounded text-purple-600 font-mono text-sm">
                /var/www/app
              </code>
            </p>
            <p className="text-gray-700">
              <span className="font-semibold">🔧 Manage with PM2:</span>{' '}
              <code className="bg-gray-100 px-2 py-1 rounded text-purple-600 font-mono text-sm">
                pm2 list
              </code>{' '}
              |{' '}
              <code className="bg-gray-100 px-2 py-1 rounded text-purple-600 font-mono text-sm">
                pm2 logs
              </code>
            </p>
            <p className="text-gray-700">
              <span className="font-semibold">📊 Server Logs:</span>{' '}
              <code className="bg-gray-100 px-2 py-1 rounded text-purple-600 font-mono text-sm">
                /var/log/vps-setup.log
              </code>
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
}
EOFILE

# Create _app.tsx
cat > pages/_app.tsx <<'EOFILE'
import '../styles/globals.css';
import type { AppProps } from 'next/app';

export default function App({ Component, pageProps }: AppProps) {
  return <Component {...pageProps} />;
}
EOFILE

# Create global styles
cat > styles/globals.css <<'EOFILE'
@tailwind base;
@tailwind components;
@tailwind utilities;
EOFILE

# Install frontend dependencies
npm install

# Build Next.js app
log_message "Building Next.js application..."
npm run build

#########################################
# PART 6: PM2 PROCESS MANAGEMENT
#########################################

log_message "=== PART 6: PM2 PROCESS MANAGEMENT ==="

# Create PM2 ecosystem file - FIXED: proper working directories
cat > $APP_DIR/ecosystem.config.js <<'EOFILE'
module.exports = {
  apps: [
    {
      name: 'api',
      script: './server.js',
      cwd: '/var/www/app/api',  // Fixed: correct working directory so .env is found
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '512M',
      env: {
        NODE_ENV: 'production'
      },
      error_file: '/var/log/pm2/api-error.log',
      out_file: '/var/log/pm2/api-out.log',
      log_file: '/var/log/pm2/api-combined.log',
      time: true
    },
    {
      name: 'frontend',
      script: 'npm',
      args: 'start',
      cwd: '/var/www/app/frontend',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '512M',
      env: {
        NODE_ENV: 'production',
        PORT: 3000
      },
      error_file: '/var/log/pm2/frontend-error.log',
      out_file: '/var/log/pm2/frontend-out.log',
      log_file: '/var/log/pm2/frontend-combined.log',
      time: true
    }
  ]
};
EOFILE

# Create PM2 log directory
mkdir -p /var/log/pm2

# Start applications with PM2
log_message "Starting applications with PM2..."
cd $APP_DIR
pm2 start ecosystem.config.js
pm2 save

# Wait for apps to start
sleep 10

# Check if apps are running
pm2 status

#########################################
# PART 7: CLOUDFLARE CONFIGURATION
#########################################

if [ "$ENABLE_CLOUDFLARE" = "yes" ]; then
    log_message "=== PART 7: CLOUDFLARE CONFIGURATION ==="
    
    # Create Cloudflare IP update script
    cat > /usr/local/bin/update-cloudflare-ips.sh <<'EOSCRIPT'
#!/bin/bash

echo "Fetching latest Cloudflare IP ranges..."

# Fetch latest IPs directly from Cloudflare
CF_IPV4=$(curl -s https://www.cloudflare.com/ips-v4)
CF_IPV6=$(curl -s https://www.cloudflare.com/ips-v6)

if [ -z "$CF_IPV4" ]; then
    echo "Error: Failed to fetch Cloudflare IPv4 addresses"
    echo "Trying alternative API endpoint..."
    
    # Try the API endpoint as fallback
    CF_IPS=$(curl -s https://api.cloudflare.com/client/v4/ips)
    if [ ! -z "$CF_IPS" ]; then
        CF_IPV4=$(echo "$CF_IPS" | grep -Po '"ipv4_cidrs":\s*\[\K[^]]*' | tr -d '", ' | tr ',' '\n')
        CF_IPV6=$(echo "$CF_IPS" | grep -Po '"ipv6_cidrs":\s*\[\K[^]]*' | tr -d '", ' | tr ',' '\n')
    fi
fi

if [ -z "$CF_IPV4" ]; then
    echo "Error: Could not fetch Cloudflare IPs from any source"
    exit 1
fi

echo "Successfully fetched Cloudflare IPs"
echo "IPv4 ranges: $(echo "$CF_IPV4" | wc -l)"
echo "IPv6 ranges: $(echo "$CF_IPV6" | wc -l)"

# First, remove ALL existing Cloudflare rules
echo "Removing old Cloudflare rules..."
while ufw status numbered | grep -q 'Cloudflare'; do
    RULE_NUM=$(ufw status numbered | grep 'Cloudflare' | head -1 | cut -d']' -f1 | cut -d'[' -f2)
    if [ ! -z "$RULE_NUM" ]; then
        ufw --force delete $RULE_NUM 2>/dev/null || true
    else
        break
    fi
done

# Remove any general HTTP/HTTPS rules to enforce Cloudflare-only
echo "Removing general HTTP/HTTPS access rules..."
ufw delete allow 80/tcp 2>/dev/null || true
ufw delete allow 443/tcp 2>/dev/null || true

# Add Cloudflare IPv4 ranges
echo "Adding Cloudflare IPv4 ranges..."
for ip in $CF_IPV4; do
    ufw allow from $ip to any port 80 comment 'Cloudflare-IPv4' 2>/dev/null || true
    ufw allow from $ip to any port 443 comment 'Cloudflare-IPv4' 2>/dev/null || true
done

# Add Cloudflare IPv6 ranges
echo "Adding Cloudflare IPv6 ranges..."
for ip in $CF_IPV6; do
    ufw allow from $ip to any port 80 comment 'Cloudflare-IPv6' 2>/dev/null || true
    ufw allow from $ip to any port 443 comment 'Cloudflare-IPv6' 2>/dev/null || true
done

# Reload firewall
ufw reload

echo "Cloudflare IP update complete!"
echo "Only Cloudflare IPs can now access ports 80 and 443"

# Save the current IP lists for reference
echo "$CF_IPV4" > /etc/cloudflare-ips-v4.txt
echo "$CF_IPV6" > /etc/cloudflare-ips-v6.txt
echo "IP lists saved to /etc/cloudflare-ips-v4.txt and /etc/cloudflare-ips-v6.txt"
EOSCRIPT

    chmod +x /usr/local/bin/update-cloudflare-ips.sh
    
    # Run it to set up initial Cloudflare IPs
    log_message "Fetching and applying latest Cloudflare IP ranges..."
    bash /usr/local/bin/update-cloudflare-ips.sh || log_warning "Cloudflare IP update had warnings"
    
    # Add daily cron job to keep IPs updated
    (crontab -l 2>/dev/null | grep -v update-cloudflare-ips; echo "0 3 * * * /usr/local/bin/update-cloudflare-ips.sh > /var/log/cloudflare-ip-update.log 2>&1") | crontab -
    
    log_message "Cloudflare IP restrictions enabled with daily auto-update"
    log_message "Update manually anytime with: /usr/local/bin/update-cloudflare-ips.sh"
else
    log_message "Cloudflare restrictions not enabled"
    log_message "Allowing HTTP/HTTPS from anywhere (less secure)"
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    ufw reload
fi

#########################################
# FINAL SUMMARY
#########################################

# Restart services
systemctl restart ssh
systemctl restart nginx
systemctl restart fail2ban
ufw reload

# Final status check
sleep 5
APP_STATUS=$(pm2 list | grep -c "online" || echo "0")

echo ""
log_message "========================================="
log_message "🎉 FULLSTACK VPS SETUP COMPLETE! 🎉"
log_message "========================================="
echo ""

log_info "📊 SERVER STATUS:"
log_message "✅ Security: Hardened (UFW + Fail2ban + SSH secured)"
log_message "✅ Web Server: Nginx (reverse proxy configured)"
log_message "✅ Database: PostgreSQL (local only)"
log_message "✅ Backend: Node.js API on port $API_PORT"
log_message "✅ Frontend: Next.js on port $APP_PORT"
log_message "✅ Process Manager: PM2 (auto-restart enabled)"
log_message "✅ Apps Running: $APP_STATUS/2"
if [ "$ENABLE_CLOUDFLARE" = "yes" ]; then
    log_message "✅ Cloudflare: IP whitelist active (Flexible SSL mode)"
else
    log_message "⚠️  Cloudflare: Not configured (direct access allowed)"
fi
echo ""

log_info "🔑 DATABASE CREDENTIALS (SAVE THESE!):"
log_message "Database: $DB_NAME"
log_message "Username: $DB_USER"
log_message "Password: $DB_PASS"
log_message "Host: localhost"
log_message "Port: 5432"
log_message "Connection: postgresql://$DB_USER:$DB_PASS@localhost:5432/$DB_NAME"
echo ""

log_info "📁 APPLICATION LOCATIONS:"
log_message "App Directory: $APP_DIR"
log_message "API: $APP_DIR/api"
log_message "Frontend: $APP_DIR/frontend"
log_message "PM2 Config: $APP_DIR/ecosystem.config.js"
log_message "Database Credentials: $APP_DIR/api/.env"
echo ""

log_info "🔧 USEFUL COMMANDS:"
log_message "View apps: pm2 list"
log_message "View logs: pm2 logs"
log_message "Restart app: pm2 restart all"
log_message "Monitor: pm2 monit"
log_message "Firewall status: ufw status numbered"
log_message "Fail2ban status: fail2ban-client status"
log_message "Check API: curl http://localhost:$API_PORT/api/health"
echo ""

if [ "$ENABLE_CLOUDFLARE" = "yes" ]; then
    log_info "🌐 CLOUDFLARE SETUP (IMPORTANT!):"
    log_message "1. Add your domain to Cloudflare dashboard"
    log_message "2. Point A record to this server's IP: $(curl -s ifconfig.me)"
    log_message "3. Enable orange proxy cloud (Proxied)"
    log_message "4. Set SSL/TLS to 'Flexible' (not Full or Full Strict)"
    log_message "5. Your site will be available at: https://your-domain.com"
else
    log_info "🌐 ACCESS YOUR APPLICATION:"
    log_message "Direct IP: http://$(curl -s ifconfig.me)"
    log_message "To use Cloudflare, re-run with: ENABLE_CLOUDFLARE=yes"
fi
echo ""

log_warning "⚠️ IMPORTANT REMINDERS:"
log_warning "1. SSH Port: $SSH_PORT (save this!)"
log_warning "2. Test SSH in NEW terminal: ssh -p $SSH_PORT user@$(curl -s ifconfig.me)"
log_warning "3. Save database credentials shown above!"
if [ "$ENABLE_CLOUDFLARE" = "yes" ]; then
    log_warning "4. Set Cloudflare SSL to 'Flexible' mode (not Full)"
fi
echo ""

# Check if reboot required
if [ -f /var/run/reboot-required ]; then
    log_warning "*** SYSTEM RESTART REQUIRED ***"
    log_warning "Run 'sudo reboot' after verifying SSH access"
fi

log_message "Setup log: $LOG_FILE"
log_message "Your fullstack application is ready!"
