# 🔒 Ubuntu VPS Hardening Script

**Secure your Ubuntu VPS in minutes with production-ready security defaults**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-2024.04-orange)](https://ubuntu.com/)
[![Hetzner](https://img.shields.io/badge/Tested%20on-Hetzner-d50c2d)](https://hetzner.com/)

## 🚀 Quick Start

Run this one-liner on your fresh Ubuntu VPS:

```bash
curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-harden/refs/heads/main/harden.sh | sudo bash
```

Or download and review first (recommended):

```bash
curl https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-harden/refs/heads/main/harden.sh > harden.sh
chmod +x harden.sh
sudo bash ./harden.sh
```

## 🎯 What Does It Do?

This script transforms your default VPS into a security-hardened server by implementing industry best practices automatically:

### ✅ Security Features

- **🔐 SSH Hardening**
  - Disables password authentication (key-only login)
  - Configurable SSH port
  - Rate limiting and connection limits
  - Restricted to specific user groups

- **🛡️ Firewall Protection**
  - UFW firewall with deny-all default
  - Only allows SSH, HTTP, and HTTPS
  - Optional Cloudflare-only restriction
  - Rate limiting on SSH connections

- **🚫 Intrusion Prevention**
  - Fail2ban with aggressive policies
  - Automatic IP blocking after failed attempts
  - DDoS protection for SSH
  - Recidive jail for repeat offenders

- **🔄 Automatic Updates**
  - Unattended security updates
  - Auto-removal of old kernels
  - Daily security patches

- **⚙️ Kernel Hardening**
  - SYN flood protection
  - IP spoofing protection
  - ICMP redirect protection
  - Secure shared memory

- **📊 Security Monitoring**
  - AIDE intrusion detection
  - Rkhunter rootkit scanner
  - Auditd system auditing
  - Logwatch reports

## 📋 Prerequisites

- Fresh Ubuntu (tested on 24.04)
- Root or sudo access
- SSH key already configured (script will disable password auth)
- At least 1GB RAM recommended

## 🎛️ Configuration Options

Run with custom settings using environment variables:

```bash
# Change SSH port (default: 22)
sudo SSH_PORT=2222 bash ./harden.sh

# Disable Cloudflare-only access (default: yes)
sudo ENABLE_CLOUDFLARE=no bash ./harden.sh

# Set admin email for notifications (optional)
sudo ADMIN_EMAIL=admin@example.com bash ./harden.sh
```

## 🌐 Cloudflare Integration

When `ENABLE_CLOUDFLARE=yes` is set (this is the default):
- HTTP/HTTPS ports are restricted to Cloudflare IPs only
- Automatic weekly updates of Cloudflare IP ranges
- Prevents direct IP access, forcing traffic through Cloudflare
- Perfect for DDoS protection and hiding your origin IP

**Note:** You still need to:
1. Add your domain to Cloudflare dashboard
2. Update your domain's nameservers
3. Enable the orange proxy cloud in DNS settings
4. Never expose your real server IP

## ⚠️ Important Notes

### Before Running

1. **Ensure SSH key access is working** - The script disables password authentication
2. **Test your SSH key**: `ssh -i ~/.ssh/your-key user@server`
3. **Keep your current SSH session open** until you've tested the new configuration

### After Running

The script will show important information:
- Your SSH port (if changed)
- Users with SSH access
- Current firewall rules
- Any warnings or required actions

**Always test SSH access in a new terminal before closing your current session:**
```bash
ssh -p YOUR_SSH_PORT -i ~/.ssh/your-key user@server
```

## 🔧 What Gets Modified

- `/etc/ssh/sshd_config.d/99-hardening.conf` - SSH configuration
- `/etc/fail2ban/jail.local` - Fail2ban rules
- `/etc/apt/apt.conf.d/` - Automatic updates
- `/etc/sysctl.d/99-hardening.conf` - Kernel parameters
- `/etc/ufw/` - Firewall rules
- `/etc/fstab` - Shared memory settings

All original configs are backed up with timestamps.

## 🆘 Troubleshooting

### Locked Out of SSH?

1. Use your VPS provider's console:
   - Hetzner: Cloud Console
   - DigitalOcean: Droplet Console
   - AWS: EC2 Serial Console

2. Remove SSH restrictions:
   ```bash
   rm /etc/ssh/sshd_config.d/99-hardening.conf
   systemctl restart ssh
   ```

3. Or just remove the group restriction:
   ```bash
   sed -i 's/AllowGroups sshusers/#AllowGroups sshusers/' /etc/ssh/sshd_config.d/99-hardening.conf
   systemctl restart ssh
   ```

### Adding New SSH Users

After hardening, new users need to be in the `sshusers` group:
```bash
usermod -a -G sshusers newusername
```

### Checking Service Status

```bash
# Firewall status
sudo ufw status verbose

# Fail2ban status
sudo fail2ban-client status
sudo fail2ban-client status sshd

# SSH configuration
sudo sshd -T | grep -E "port|permit|password|pubkey"

# View recent auth logs
sudo tail -f /var/log/auth.log
```

## 📊 Compatibility

| OS | Version | Status |
|---|---|---|
| Ubuntu | 24.04 LTS | ✅ Tested |
| Ubuntu | 22.04 LTS | ? |
| Ubuntu | 20.04 LTS | ? |
| Debian | 12 (Bookworm) | ? |
| Debian | 11 (Bullseye) | ? |

| Provider | Status | Notes |
|---|---|---|
| Hetzner | ✅ Tested | Compatibility |
| DigitalOcean | ? | Fully supported |
| Linode | ? | - |
| Vultr | ? | - |
| AWS EC2 | ? | - |
| Google Cloud | ? | - |
| Azure | ? | - |

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

MIT License - feel free to use this script for personal or commercial purposes.

---

**Remember:** Security is a continuous process. This script provides a strong foundation, but always:

- Keep your system updated
- Monitor your logs regularly
- Follow security news and advisories
- Implement application-level security
- Use strong, unique passwords for all services
- Enable 2FA where possible
- Regular security audits

Stay safe! 🔐
