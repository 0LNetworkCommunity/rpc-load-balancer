# Installation Guide for OpenLibra RPC Load Balancer

## System Requirements

- Ubuntu 20.04+ (or similar Linux distribution)
- Python 3.6 or higher
- Nginx web server
- Git
- Make utility

## Quick Installation

1. **Clone the repository**
```bash
cd ~
git clone https://github.com/0LNetworkCommunity/rpc-load-balancer
```

2. **Install system dependencies**
```bash
sudo apt update
sudo apt install -y make nginx python3 python3-pip git
pip3 install requests
```

3. **Run the installation**
```bash
cd ~/rpc-load-balancer
sudo make install
```

## Environment Variables

You can customize the installation by setting these environment variables:

- `GIT_ORG`: The GitHub organization (default: `0LNetworkCommunity`)
- `GIT_REPO`: The repository name (default: `rpc-load-balancer`)
- `REPO_PATH`: The path to the repository (default: `~/rpc-load-balancer`)
- `RPC_LB_DOMAIN`: Your domain name (default: `rpc.openlibra.space`)
- `RPC_LB_SITE_FILE`: Nginx site configuration filename (default: `rpc-load-balancer`)

Example with custom values:
```bash
RPC_LB_DOMAIN=my-rpc.example.com REPO_PATH=/opt/rpc-lb sudo -E make install
```

## What the Installation Does

The `make install` command performs the following steps:

1. **Installs required packages**: Python3, nginx, and SSL certificate tools
2. **Creates nginx configuration**: Generates a load balancer configuration for your domain
3. **Enables the site**: Creates symbolic link in nginx sites-enabled
4. **Sets up SSL**: Uses Let's Encrypt to obtain SSL certificates for your domain
5. **Reloads nginx**: Applies the new configuration

## Makefile Targets

### Basic Commands

- **`make install`**: Complete installation process
- **`make update`**: Run endpoint discovery and update nginx configuration
- **`make pull`**: Pull latest changes from the git repository
- **`make push`**: Commit and push local changes to git

### Automation Commands

- **`make cron`**: Full update cycle (pull → update → push) - ideal for cron jobs
- **`make cron-nogit`**: Update endpoints without git operations - for local-only setups

### Configuration Commands

- **`make rpc-load-balancer`**: Regenerate the nginx site configuration file

## Manual Configuration

If you prefer manual setup or need to customize:

1. **Create nginx configuration manually**:
```bash
sudo nano /etc/nginx/sites-available/rpc-load-balancer
```

2. **Add your upstream configuration**:
```nginx
upstream fullnodes {
    server 127.0.0.1:8080;
}

server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 8080 ssl;
    server_name your-domain.com;
    
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    
    location / {
        proxy_pass http://fullnodes;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

3. **Enable the site**:
```bash
sudo ln -sf /etc/nginx/sites-available/rpc-load-balancer /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## Setting Up Automatic Updates

The load balancer should regularly update its endpoint list. Set up a cron job:

1. **Edit crontab**:
```bash
crontab -e
```

2. **Add the update schedule** (runs every 15 minutes):
```cron
*/15 * * * * cd /home/nodeuser/rpc-load-balancer && REPO_PATH=/home/nodeuser/rpc-load-balancer make cron >> /var/log/rpc-lb-cron.log 2>&1
```

Or for local-only updates (without git):
```cron
*/15 * * * * cd /home/nodeuser/rpc-load-balancer && make cron-nogit >> /var/log/rpc-lb-cron.log 2>&1
```

## Troubleshooting

### SSL Certificate Issues

If you encounter issues with Let's Encrypt:

1. Ensure your domain points to this server
2. Check firewall allows port 80 and 443
3. Try manual certificate generation:
```bash
sudo certbot certonly --manual --preferred-challenges=dns --server https://acme-v02.api.letsencrypt.org/directory --domain your-domain.com
```

### Nginx Configuration Issues

Test nginx configuration:
```bash
sudo nginx -t
```

Check nginx error logs:
```bash
sudo tail -f /var/log/nginx/error.log
```

### Python Script Issues

Test the update script manually:
```bash
cd ~/rpc-load-balancer
sudo python3 update_endpoints.py /etc/nginx/sites-available/rpc-load-balancer
```

Check for Python dependencies:
```bash
pip3 list | grep requests
```

### Permission Issues

Ensure proper ownership:
```bash
sudo chown -R $USER:$USER ~/rpc-load-balancer
```

For cron jobs running as root, ensure the repository path is accessible.

## Updating the Installation

To update to the latest version:

```bash
cd ~/rpc-load-balancer
make pull
make update
```

Or simply:
```bash
make cron
```

## Uninstalling

To remove the load balancer:

1. **Disable the nginx site**:
```bash
sudo rm /etc/nginx/sites-enabled/rpc-load-balancer
sudo systemctl reload nginx
```

2. **Remove the configuration**:
```bash
sudo rm /etc/nginx/sites-available/rpc-load-balancer
```

3. **Remove the cron job**:
```bash
crontab -e
# Remove the line containing rpc-load-balancer
```

4. **Optionally remove the repository**:
```bash
rm -rf ~/rpc-load-balancer
```

## Support

For issues or questions:
- Open an issue on [GitHub](https://github.com/0LNetworkCommunity/rpc-load-balancer)
- Check the [README](README.md) for detailed documentation about the endpoint discovery process 