# Nginx Configuration for Quantix

## Subdomains

| Subdomain | Purpose | Backend |
|-----------|---------|---------|
| `rpc.qpqb.org` | JSON-RPC endpoint | Quantix node (127.0.0.1:8545) |
| `testnet.qpqb.org` | Block explorer | Vercel or self-hosted |

## Setup Instructions

### 1. Install Nginx

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nginx

# CentOS/RHEL
sudo yum install nginx
```

### 2. Copy Configuration Files

```bash
sudo cp rpc.qpqb.org.conf /etc/nginx/sites-available/
sudo cp testnet.qpqb.org.conf /etc/nginx/sites-available/

# Enable sites
sudo ln -s /etc/nginx/sites-available/rpc.qpqb.org.conf /etc/nginx/sites-enabled/
sudo ln -s /etc/nginx/sites-available/testnet.qpqb.org.conf /etc/nginx/sites-enabled/
```

### 3. SSL Certificates with Let's Encrypt

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Get certificates
sudo certbot --nginx -d rpc.qpqb.org
sudo certbot --nginx -d testnet.qpqb.org

# Auto-renewal (already set up by certbot)
sudo systemctl enable certbot.timer
```

### 4. Start Quantix Node

Make sure your Quantix node is running on port 8545:

```bash
# Using Docker
docker run -d -p 8545:8545 quantix/node:latest --network testnet

# Or directly
quantix-node --network testnet --rpc.addr 127.0.0.1 --rpc.port 8545
```

### 5. Test and Reload Nginx

```bash
# Test configuration
sudo nginx -t

# Reload
sudo systemctl reload nginx
```

### 6. Verify RPC Endpoint

```bash
curl -X POST https://rpc.qpqb.org \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qtx_blockNumber","params":[],"id":1}'
```

## DNS Records

Add these records to your DNS provider:

```
# A records (if hosting on your own server)
rpc       A     YOUR_SERVER_IP
testnet   A     YOUR_SERVER_IP

# OR CNAME for Vercel (explorer only)
testnet   CNAME cname.vercel-dns.com
```

## Security Notes

- RPC endpoint only allows POST requests
- Rate limited to 100 req/s per IP
- Max 50 concurrent connections per IP
- Request body limited to 1MB
- CORS enabled for browser access

## Monitoring

Check logs:
```bash
sudo tail -f /var/log/nginx/rpc.qpqb.org.access.log
sudo tail -f /var/log/nginx/rpc.qpqb.org.error.log
```

Check status:
```bash
sudo systemctl status nginx
curl https://rpc.qpqb.org/health
```
