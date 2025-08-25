> ⚠️ this project was vibecoded in a day and I'm now working on the feedbacks from [this post](https://x.com/MarcoWorms/status/1953924284734132356)  
>  **I highly recommend that you invest in security for serious projects and don't just rely on this script**

# Vibecoder Fullstack VPS Quick Start

Run through these steps to have a VPS with your domain attached to it and an instance of claude code ready to create any app that uses:

- a frontend (React + Next + Tailwind)
- an api (Node + Express)
- a database (Postgres)

## Choose Your Setup Method

### Option 1: Docker-Based Setup (Recommended) 🐳
Run services in Docker containers for better isolation, security, and easier management. See [README-DOCKER.md](README-DOCKER.md) for detailed information.

```bash
curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-harden/main/fullstack-harden-docker.sh | sudo bash && sudo reboot
```

### Option 2: Traditional Setup (Original)
Run services directly on the host system with PM2 process management.

```bash
curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-harden/main/fullstack-harden.sh | sudo bash && sudo reboot
```

## Setup Steps

1) Run one of the setup scripts above in a new clean [Ubuntu 24.04 Hetzner VPS](https://console.hetzner.com/projects) and make sure you set at least one SSH key for the creation of VPS as it will be only way to login after running this line.

> To connect with your Hetzner VPS use ssh with key: `ssh root@VPS_IP_ADDRESS -i PATH/TO/SSH_KEY -p 22`

2) Then reconnect to your VPS using the SSH key authorized in Hetzner dashboard, and run this line to install claude code and copy a initial CLAUDE.md and instructions for how to navigate and restart all services in our webserver:

```bash
cd / && curl -sSL https://raw.githubusercontent.com/MarcoWorms/ubuntu-vps-hardened-fullstack-webserver/main/CLAUDE.md > CLAUDE.md && \
npm install -g @anthropic-ai/claude-code && \
echo "✅ Claude Code installed! Run 'claude' to start AI-assisted coding"
```

3) Then to run claude in completely unhinged vibe code mode use this:

```bash
export IS_SANDBOX=1; claude --dangerously-skip-permissions
```

4) Deploying into a domain:

    1) Buy a domain
    2) Create a [Cloudflare](https://dash.cloudflare.com/) account
    3) Set the Cloudflare DNS urls in your domain provider
    4) Create an A record in Cloudflare that points @ to your Hetzner server IP.

## 📜 License

MIT License - Use freely for personal or commercial projects.

---

**Remember**: This script provides a strong foundation, but ongoing maintenance, updates, and monitoring are essential for production systems. Always follow security best practices and keep your applications updated.