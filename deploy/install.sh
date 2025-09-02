#!/bin/bash

# Industrial Internet Honeypot Installation Script for Ubuntu
# This script installs and configures the honeypot system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_error "This script should not be run as root for security reasons"
    print_status "Please run as a regular user with sudo privileges"
    exit 1
fi

# Check Ubuntu version
if ! grep -q "Ubuntu" /etc/os-release; then
    print_warning "This script is designed for Ubuntu. Other distributions may not work correctly."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

print_status "Starting Industrial Internet Honeypot installation..."

# Update system packages
print_status "Updating system packages..."
sudo apt update
sudo apt upgrade -y

# Install Python 3.11 and dependencies
print_status "Installing Python and dependencies..."
sudo apt install -y \
    python3.11 \
    python3.11-pip \
    python3.11-venv \
    python3.11-dev \
    build-essential \
    git \
    curl \
    wget \
    vim \
    htop \
    net-tools \
    docker.io \
    docker-compose

# Install Python packages
print_status "Installing Python packages..."
python3.11 -m pip install --user --upgrade pip
python3.11 -m pip install --user -r requirements.txt

# Create honeypot user
print_status "Creating honeypot user..."
if ! id -u honeypot >/dev/null 2>&1; then
    sudo useradd -m -s /bin/bash honeypot
    sudo usermod -aG docker honeypot
    print_success "Created honeypot user"
else
    print_warning "Honeypot user already exists"
fi

# Create directories
print_status "Creating directories..."
sudo mkdir -p /opt/honeypot
sudo mkdir -p /var/log/honeypot
sudo mkdir -p /etc/honeypot

# Copy files
print_status "Installing honeypot files..."
sudo cp -r . /opt/honeypot/
sudo chown -R honeypot:honeypot /opt/honeypot
sudo chown -R honeypot:honeypot /var/log/honeypot

# Create symbolic link for configuration
sudo ln -sf /opt/honeypot/config/honeypot.yaml /etc/honeypot/honeypot.yaml

# Set up systemd service
print_status "Creating systemd service..."
sudo tee /etc/systemd/system/industrial-honeypot.service > /dev/null <<EOF
[Unit]
Description=Industrial Internet Honeypot with LLM Response
After=network.target
Wants=network.target

[Service]
Type=simple
User=honeypot
Group=honeypot
WorkingDirectory=/opt/honeypot
ExecStart=/usr/bin/python3.11 /opt/honeypot/src/main.py -c /etc/honeypot/honeypot.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=honeypot

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/honeypot /opt/honeypot/logs

# Capability to bind to privileged ports
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# Set up logrotate
print_status "Configuring log rotation..."
sudo tee /etc/logrotate.d/industrial-honeypot > /dev/null <<EOF
/var/log/honeypot/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 honeypot honeypot
    postrotate
        systemctl reload industrial-honeypot || true
    endscript
}
EOF

# Configure firewall (if ufw is available)
if command -v ufw >/dev/null 2>&1; then
    print_status "Configuring firewall..."
    sudo ufw allow 22/tcp comment "SSH"
    sudo ufw allow 23/tcp comment "Telnet Honeypot"
    sudo ufw allow 80/tcp comment "HTTP Honeypot"
    sudo ufw allow 443/tcp comment "HTTPS Honeypot"
    sudo ufw allow 502/tcp comment "Modbus Honeypot"
    
    print_warning "Firewall rules added. Enable with: sudo ufw enable"
fi

# Create environment file template
print_status "Creating environment configuration..."
sudo tee /etc/honeypot/environment > /dev/null <<EOF
# OpenAI API Key for LLM responses
OPENAI_API_KEY=your_openai_api_key_here

# Other environment variables
HONEYPOT_LOG_LEVEL=INFO
HONEYPOT_BIND_IP=0.0.0.0
EOF

sudo chmod 600 /etc/honeypot/environment
sudo chown honeypot:honeypot /etc/honeypot/environment

# Enable and start service
print_status "Enabling systemd service..."
sudo systemctl daemon-reload
sudo systemctl enable industrial-honeypot.service

# Create start/stop scripts
print_status "Creating management scripts..."
sudo tee /usr/local/bin/honeypot-start > /dev/null <<'EOF'
#!/bin/bash
echo "Starting Industrial Honeypot..."
sudo systemctl start industrial-honeypot.service
sudo systemctl status industrial-honeypot.service --no-pager
EOF

sudo tee /usr/local/bin/honeypot-stop > /dev/null <<'EOF'
#!/bin/bash
echo "Stopping Industrial Honeypot..."
sudo systemctl stop industrial-honeypot.service
EOF

sudo tee /usr/local/bin/honeypot-status > /dev/null <<'EOF'
#!/bin/bash
echo "Industrial Honeypot Status:"
sudo systemctl status industrial-honeypot.service --no-pager
echo
echo "Recent logs:"
sudo journalctl -u industrial-honeypot.service --no-pager -n 20
EOF

sudo tee /usr/local/bin/honeypot-logs > /dev/null <<'EOF'
#!/bin/bash
echo "Following Industrial Honeypot logs..."
sudo journalctl -u industrial-honeypot.service -f
EOF

sudo chmod +x /usr/local/bin/honeypot-*

print_success "Installation completed successfully!"
print_status "Configuration steps:"
echo
print_status "1. Edit the configuration file:"
echo "   sudo vim /etc/honeypot/honeypot.yaml"
echo
print_status "2. Set your OpenAI API key (optional for LLM features):"
echo "   sudo vim /etc/honeypot/environment"
echo
print_status "3. Start the honeypot:"
echo "   honeypot-start"
echo
print_status "4. Monitor logs:"
echo "   honeypot-logs"
echo
print_status "5. Check status:"
echo "   honeypot-status"
echo
print_warning "Important Security Notes:"
print_warning "- The honeypot will bind to privileged ports (22, 80, etc.)"
print_warning "- Make sure to configure your firewall appropriately"
print_warning "- Monitor logs regularly for security events"
print_warning "- Keep the system updated"
echo
print_status "For Docker deployment, use:"
echo "   cd /opt/honeypot/deploy"
echo "   docker-compose up -d"