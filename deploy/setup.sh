#!/usr/bin/env bash
# Generic setup for freeq on Ubuntu VPS
# Usage: ./deploy/setup.sh <domain> [--nginx] [--iroh]
# Idempotent: safe to run multiple times
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Parse arguments
DOMAIN=""
ENABLE_NGINX=false
ENABLE_IROH=false

for arg in "$@"; do
    case $arg in
        --nginx) ENABLE_NGINX=true ;;
        --iroh) ENABLE_IROH=true ;;
        -*) echo "Unknown option: $arg"; exit 1 ;;
        *) DOMAIN="$arg" ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    echo "Usage: ./deploy/setup.sh <domain> [--nginx] [--iroh]"
    echo ""
    echo "Options:"
    echo "  --nginx    Set up nginx reverse proxy with TLS (runs certbot)"
    echo "  --iroh     Enable iroh transport for S2S federation"
    exit 1
fi

FREEQ_USER="freeq"

echo "==> Setting up freeq for $DOMAIN"
echo "    Service user: $FREEQ_USER"
echo "    Path: $REPO_DIR"
echo "    nginx: $ENABLE_NGINX"
echo "    iroh: $ENABLE_IROH"

# Create dedicated service user (no login, no home, no sudo)
if ! id "$FREEQ_USER" &>/dev/null; then
    echo "==> Creating $FREEQ_USER system user..."
    sudo adduser --system --group --no-create-home "$FREEQ_USER"
fi

# Ensure freeq user can traverse to repo directory
REPO_PARENT="$(dirname "$REPO_DIR")"
sudo chmod o+x "$REPO_PARENT"

# Check dependencies
MISSING_PKGS=""
REQUIRED_PKGS="build-essential pkg-config libssl-dev curl git"
if [[ "$ENABLE_NGINX" == "true" ]]; then
    REQUIRED_PKGS="$REQUIRED_PKGS nginx certbot python3-certbot-nginx"
fi

for pkg in $REQUIRED_PKGS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        MISSING_PKGS="$MISSING_PKGS $pkg"
    fi
done

if [[ -n "$MISSING_PKGS" ]]; then
    echo "Missing apt packages:$MISSING_PKGS"
    read -p "Install these packages? [Y/n]: " INSTALL_PKGS
    if [[ "${INSTALL_PKGS,,}" != "n" ]]; then
        sudo apt-get update
        sudo apt-get install -y $MISSING_PKGS
    else
        echo "Please install manually: sudo apt-get install$MISSING_PKGS"
        exit 1
    fi
fi

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "Rust not found."
    read -p "Install Rust via rustup? [Y/n]: " INSTALL_RUST
    if [[ "${INSTALL_RUST,,}" != "n" ]]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    else
        echo "Please install Rust: https://rustup.rs"
        exit 1
    fi
fi

# Install Node.js if not present
if ! command -v node &> /dev/null; then
    echo "Node.js not found."
    read -p "Install Node.js 20 via nodesource? [Y/n]: " INSTALL_NODE
    if [[ "${INSTALL_NODE,,}" != "n" ]]; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs
    else
        echo "Please install Node.js 20+: https://nodejs.org"
        exit 1
    fi
fi

echo "==> Building server..."
cd "$REPO_DIR"
cargo build --release --bin freeq-server

echo "==> Building web app (auto-builds @freeq/sdk via prebuild hook)..."
cd "$REPO_DIR/freeq-app"
npm ci
npm run build
cd "$REPO_DIR"

# TLS setup (only with --nginx)
HAS_CERT=false
if [[ "$ENABLE_NGINX" == "true" ]]; then
    if [[ -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
        echo "==> TLS cert already exists for $DOMAIN"
        HAS_CERT=true
    else
        echo "==> Setting up TLS cert via certbot..."
        echo "    Make sure DNS for $DOMAIN points to this server!"
        read -p "Press enter when ready (or Ctrl+C to abort)..."

        # Create minimal nginx vhost for certbot
        NGINX_CONF="/etc/nginx/sites-available/freeq-$DOMAIN.conf"
        cat > /tmp/freeq-nginx-temp.conf << EOF
server {
    listen 80;
    server_name $DOMAIN;
    root /var/www/html;
}
EOF
        sudo mv /tmp/freeq-nginx-temp.conf "$NGINX_CONF"
        sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/
        sudo nginx -t && sudo systemctl reload nginx

        # Get cert
        if sudo certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email; then
            HAS_CERT=true
        else
            echo "ERROR: certbot failed. Fix the issue and re-run."
            exit 1
        fi
    fi

else
    # Check if cert exists anyway (for IRC TLS)
    if [[ -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
        HAS_CERT=true
    fi
fi

# Set up ssl-cert group for non-root cert access
if [[ "$HAS_CERT" == "true" ]]; then
    if ! getent group ssl-cert >/dev/null; then
        echo "==> Creating ssl-cert group..."
        sudo groupadd ssl-cert
    fi
    if ! id -nG "$FREEQ_USER" | grep -qw ssl-cert; then
        echo "==> Adding $FREEQ_USER to ssl-cert group..."
        sudo usermod -aG ssl-cert "$FREEQ_USER"
    fi
    # Make letsencrypt dirs traversable by ssl-cert, domain's privkey readable
    sudo chgrp ssl-cert /etc/letsencrypt/live /etc/letsencrypt/archive
    sudo chmod g+x /etc/letsencrypt/live /etc/letsencrypt/archive
    sudo chgrp -R ssl-cert /etc/letsencrypt/archive/"$DOMAIN"
    sudo chmod g+rx /etc/letsencrypt/archive/"$DOMAIN"
    sudo chmod g+r /etc/letsencrypt/archive/"$DOMAIN"/privkey*.pem
fi

# Generate systemd service file from template
echo "==> Generating systemd service..."
sed -e "s|{{USER}}|$FREEQ_USER|g" \
    -e "s|{{REPO_DIR}}|$REPO_DIR|g" \
    "$REPO_DIR/deploy/freeq-server.service.template" > /tmp/freeq-server.service

sudo mv /tmp/freeq-server.service /etc/systemd/system/freeq-server.service
sudo systemctl daemon-reload
sudo systemctl enable freeq-server

# Create /etc/freeq for secrets/config
sudo mkdir -p /etc/freeq
sudo chown root:"$FREEQ_USER" /etc/freeq
sudo chmod 750 /etc/freeq

# Write the server config the unit points at — but only if it doesn't exist.
# The file belongs to the operator once written: re-running setup with
# different options never silently clobbers hand edits.

# Web addr: bind to localhost if using nginx, otherwise 0.0.0.0
if [[ "$ENABLE_NGINX" == "true" ]]; then
    WEB_ADDR="127.0.0.1:8080"
else
    WEB_ADDR="0.0.0.0:8080"
fi

# `sudo test`, not `[[ -f ]]`: /etc/freeq is root:freeq 750, so the invoking
# user cannot see into it — a bare test reads "missing" for a file that
# exists, and the never-overwrite guarantee silently inverts.
if sudo test -f /etc/freeq/server.toml; then
    echo "==> /etc/freeq/server.toml exists — leaving it untouched."
    echo "    (This run wanted: web_addr=$WEB_ADDR, iroh=$ENABLE_IROH, tls=$HAS_CERT — verify if you changed options.)"
else
    echo "==> Writing /etc/freeq/server.toml..."
    {
        echo "## Generated by deploy/setup.sh for $DOMAIN — edit freely and restart."
        echo "## Every key mirrors a CLI flag; see server.toml.example in the repo."
        echo "listen_addr = \"0.0.0.0:6667\""
        if [[ "$HAS_CERT" == "true" ]]; then
            echo "tls_listen_addr = \"0.0.0.0:6697\""
            echo "tls_cert = \"/etc/letsencrypt/live/$DOMAIN/fullchain.pem\""
            echo "tls_key = \"/etc/letsencrypt/live/$DOMAIN/privkey.pem\""
        fi
        echo "db_path = \"/var/lib/freeq/freeq.db\""
        echo "web_addr = \"$WEB_ADDR\""
        echo "web_static_dir = \"$REPO_DIR/freeq-app/dist\""
        echo "server_name = \"$DOMAIN\""
        if [[ "$ENABLE_IROH" == "true" ]]; then
            echo "iroh = true"
        fi
        echo "motd = \"Welcome to freeq -- IRC with AT Protocol identity. https://freeq.at\""
    } | sudo tee /etc/freeq/server.toml > /dev/null
fi
# The config can legitimately hold secrets (oper_password, llm_api_key), so
# it gets the same treatment as /etc/freeq/secrets: root-owned, group-read
# for the service user, nothing for the world.
sudo chown root:"$FREEQ_USER" /etc/freeq/server.toml
sudo chmod 640 /etc/freeq/server.toml
if [[ ! -f /etc/freeq/secrets ]]; then
    echo "==> Creating /etc/freeq/secrets (add secrets here)..."
    sudo touch /etc/freeq/secrets
    sudo chown root:"$FREEQ_USER" /etc/freeq/secrets
    sudo chmod 640 /etc/freeq/secrets
fi
# Migrate old secrets file if present
if [[ -f "$REPO_DIR/.env.secrets" ]]; then
    sudo cat "$REPO_DIR/.env.secrets" | sudo tee -a /etc/freeq/secrets >/dev/null
    rm "$REPO_DIR/.env.secrets"
fi

# Create /var/lib/freeq for database (FHS standard)
sudo mkdir -p /var/lib/freeq
sudo chown "$FREEQ_USER:$FREEQ_USER" /var/lib/freeq
# Migrate existing db if present
if [[ -f "$REPO_DIR/freeq.db" ]]; then
    sudo mv "$REPO_DIR/freeq.db"* /var/lib/freeq/ 2>/dev/null || true
    sudo chown "$FREEQ_USER:$FREEQ_USER" /var/lib/freeq/freeq.db* 2>/dev/null || true
fi

# Nginx setup (install full config if we have cert)
if [[ "$ENABLE_NGINX" == "true" ]] && [[ "$HAS_CERT" == "true" ]]; then
    echo "==> Setting up nginx..."
    NGINX_CONF="/etc/nginx/sites-available/freeq-$DOMAIN.conf"

    sed -e "s|{{DOMAIN}}|$DOMAIN|g" \
        "$REPO_DIR/deploy/nginx.conf.template" > /tmp/freeq-nginx.conf

    sudo mv /tmp/freeq-nginx.conf "$NGINX_CONF"
    sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/
    sudo nginx -t && sudo systemctl reload nginx
fi

# Firewall (ufw allow is idempotent)
if command -v ufw &>/dev/null && sudo ufw status | grep -q "active"; then
    echo "==> Opening firewall ports (ufw)..."
    sudo ufw allow 6667/tcp
    if [[ "$HAS_CERT" == "true" ]]; then
        sudo ufw allow 6697/tcp
    fi
    if [[ "$ENABLE_NGINX" == "true" ]]; then
        sudo ufw allow 80/tcp
        sudo ufw allow 443/tcp
    else
        sudo ufw allow 8080/tcp
    fi
else
    echo "==> Note: Open firewall ports manually (6667, and 6697/443 if TLS, or 8080)"
fi

# A bad config fails here with the key named, not as a crash loop after the
# restart. Checked as the service user, so it reads the 640 file with exactly
# the permissions the service will have.
echo "==> Validating /etc/freeq/server.toml..."
sudo -u "$FREEQ_USER" "$REPO_DIR/target/release/freeq-server" --config /etc/freeq/server.toml --check-config

# Start or restart service
echo "==> Starting service..."
if systemctl is-active --quiet freeq-server; then
    sudo systemctl restart freeq-server
else
    sudo systemctl start freeq-server
fi
sudo systemctl status freeq-server --no-pager

echo ""
echo "Done! Server running at:"
echo "  IRC:       $DOMAIN:6667"
if [[ "$HAS_CERT" == "true" ]]; then
    echo "  IRC+TLS:   $DOMAIN:6697"
fi
if [[ "$ENABLE_NGINX" == "true" ]]; then
    echo "  Web:       https://$DOMAIN"
else
    echo "  Web:       http://$DOMAIN:8080"
fi
