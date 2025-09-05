#!/bin/bash

# Industrial IoT Honeypot Deployment Script for Ubuntu
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
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
        exit 1
    fi
}

# Check Ubuntu version
check_ubuntu() {
    if ! grep -q "Ubuntu" /etc/os-release; then
        print_error "This script is designed for Ubuntu. Other distributions may not be supported."
        exit 1
    fi
    
    UBUNTU_VERSION=$(lsb_release -rs)
    print_status "Detected Ubuntu $UBUNTU_VERSION"
    
    if [[ $(echo "$UBUNTU_VERSION >= 18.04" | bc -l) -eq 0 ]]; then
        print_warning "Ubuntu 18.04 or later is recommended"
    fi
}

# Install system dependencies
install_system_deps() {
    print_status "Updating package list..."
    sudo apt-get update -qq
    
    print_status "Installing system dependencies..."
    sudo apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        git \
        curl \
        wget \
        build-essential \
        libssl-dev \
        libffi-dev \
        libpq-dev \
        postgresql \
        postgresql-contrib \
        redis-server \
        docker.io \
        docker-compose \
        nginx \
        ufw \
        htop \
        net-tools \
        tcpdump \
        nmap
    
    print_success "System dependencies installed"
}

# Setup Docker
setup_docker() {
    print_status "Setting up Docker..."
    
    # Add user to docker group
    sudo usermod -aG docker $USER
    
    # Enable and start Docker
    sudo systemctl enable docker
    sudo systemctl start docker
    
    print_success "Docker setup completed"
}

# Setup PostgreSQL
setup_postgresql() {
    print_status "Setting up PostgreSQL..."
    
    # Start PostgreSQL
    sudo systemctl enable postgresql
    sudo systemctl start postgresql
    
    # Create database and user
    sudo -u postgres psql -c "CREATE DATABASE honeypot_db;"
    sudo -u postgres psql -c "CREATE USER honeypot WITH ENCRYPTED PASSWORD 'honeypot123';"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE honeypot_db TO honeypot;"
    sudo -u postgres psql -c "ALTER USER honeypot CREATEDB;"
    
    print_success "PostgreSQL setup completed"
}

# Setup Redis
setup_redis() {
    print_status "Setting up Redis..."
    
    # Enable and start Redis
    sudo systemctl enable redis-server
    sudo systemctl start redis-server
    
    print_success "Redis setup completed"
}

# Create application directory
create_app_directory() {
    print_status "Creating application directory..."
    
    APP_DIR="/opt/honeypot"
    sudo mkdir -p $APP_DIR
    sudo chown $USER:$USER $APP_DIR
    
    # Copy application files
    if [ -d "src" ]; then
        cp -r . $APP_DIR/
        print_success "Application files copied to $APP_DIR"
    else
        print_error "Source files not found. Please run this script from the project directory."
        exit 1
    fi
}

# Setup Python virtual environment
setup_python_env() {
    print_status "Setting up Python virtual environment..."
    
    APP_DIR="/opt/honeypot"
    cd $APP_DIR
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install Python dependencies
    pip install --upgrade pip
    pip install -r requirements.txt
    
    print_success "Python environment setup completed"
}

# Configure firewall
configure_firewall() {
    print_status "Configuring firewall..."
    
    # Enable UFW
    sudo ufw --force enable
    
    # Allow SSH (important!)
    sudo ufw allow ssh
    
    # Allow honeypot ports
    sudo ufw allow 8000/tcp comment "Honeypot Web Interface"
    sudo ufw allow 2222/tcp comment "SSH Honeypot"
    sudo ufw allow 8080/tcp comment "HTTP Honeypot"
    sudo ufw allow 5020/tcp comment "Modbus Honeypot"
    sudo ufw allow 2121/tcp comment "FTP Honeypot"
    sudo ufw allow 2323/tcp comment "Telnet Honeypot"
    sudo ufw allow 9090/tcp comment "Prometheus Metrics"
    sudo ufw allow 5601/tcp comment "Kibana Dashboard"
    
    # Show firewall status
    sudo ufw status
    
    print_success "Firewall configured"
}

# Create systemd service
create_systemd_service() {
    print_status "Creating systemd service..."
    
    sudo tee /etc/systemd/system/honeypot.service > /dev/null <<EOF
[Unit]
Description=Industrial IoT Honeypot System
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=/opt/honeypot
Environment=PATH=/opt/honeypot/venv/bin
ExecStart=/opt/honeypot/venv/bin/python src/main.py
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/honeypot/logs /opt/honeypot/data

# Environment
Environment=DATABASE_URL=postgresql://honeypot:honeypot123@localhost:5432/honeypot_db
Environment=REDIS_URL=redis://localhost:6379/0

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable honeypot.service
    
    print_success "Systemd service created"
}

# Setup log rotation
setup_log_rotation() {
    print_status "Setting up log rotation..."
    
    sudo tee /etc/logrotate.d/honeypot > /dev/null <<EOF
/opt/honeypot/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $USER $USER
    postrotate
        systemctl reload honeypot.service
    endscript
}
EOF

    print_success "Log rotation configured"
}

# Setup monitoring
setup_monitoring() {
    print_status "Setting up monitoring..."
    
    # Create monitoring directory
    sudo mkdir -p /var/lib/honeypot/monitoring
    sudo chown $USER:$USER /var/lib/honeypot/monitoring
    
    # Create Grafana configuration (optional)
    # This would require additional setup for a full monitoring stack
    
    print_success "Basic monitoring setup completed"
}

# Create configuration file
create_config() {
    print_status "Creating configuration file..."
    
    # Create config directory if it doesn't exist
    mkdir -p /opt/honeypot/config
    
    # Create environment file
    cat > /opt/honeypot/.env <<EOF
# Database Configuration
DATABASE_URL=postgresql://honeypot:honeypot123@localhost:5432/honeypot_db

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# LLM Configuration (Optional - set if using OpenAI)
OPENAI_API_KEY=

# Application Configuration
APP_HOST=0.0.0.0
APP_PORT=8000
APP_DEBUG=false

# Security Configuration
SECRET_KEY=$(openssl rand -hex 32)
EOF

    print_success "Configuration created"
}

# Initialize database
init_database() {
    print_status "Initializing database..."
    
    cd /opt/honeypot
    source venv/bin/activate
    
    # The database tables will be created automatically when the application starts
    # for the first time, but we can test the connection here
    
    python3 -c "
from src.database.models import create_tables
try:
    create_tables()
    print('Database initialization successful')
except Exception as e:
    print(f'Database initialization failed: {e}')
    exit(1)
"
    
    print_success "Database initialized"
}

# Start services
start_services() {
    print_status "Starting services..."
    
    # Start the honeypot service
    sudo systemctl start honeypot.service
    
    # Check service status
    if sudo systemctl is-active --quiet honeypot.service; then
        print_success "Honeypot service started successfully"
    else
        print_error "Failed to start honeypot service"
        sudo systemctl status honeypot.service
        exit 1
    fi
}

# Display final information
show_final_info() {
    clear
    echo -e "${GREEN}======================================"
    echo -e " 🍯 Honeypot Installation Complete! "
    echo -e "======================================${NC}"
    echo
    echo -e "${BLUE}Access Information:${NC}"
    echo -e "  Web Dashboard: http://localhost:8000"
    echo -e "  Prometheus: http://localhost:9090"
    echo
    echo -e "${BLUE}Honeypot Services:${NC}"
    echo -e "  SSH:    localhost:2222"
    echo -e "  HTTP:   localhost:8080"
    echo -e "  Modbus: localhost:5020"
    echo -e "  FTP:    localhost:2121"
    echo -e "  Telnet: localhost:2323"
    echo
    echo -e "${BLUE}Management Commands:${NC}"
    echo -e "  Start:   sudo systemctl start honeypot"
    echo -e "  Stop:    sudo systemctl stop honeypot"
    echo -e "  Status:  sudo systemctl status honeypot"
    echo -e "  Logs:    sudo journalctl -u honeypot -f"
    echo
    echo -e "${BLUE}Configuration:${NC}"
    echo -e "  App Dir: /opt/honeypot"
    echo -e "  Config:  /opt/honeypot/config/config.yaml"
    echo -e "  Logs:    /opt/honeypot/logs/"
    echo
    echo -e "${YELLOW}Important Notes:${NC}"
    echo -e "  • The honeypot is now running and attracting attacks"
    echo -e "  • Monitor the dashboard for real-time activity"
    echo -e "  • Regular backups of the database are recommended"
    echo -e "  • Review firewall settings for your environment"
    echo -e "  • Set OPENAI_API_KEY in /opt/honeypot/.env for enhanced LLM features"
    echo
    echo -e "${GREEN}Happy hunting! 🛡️${NC}"
}

# Main installation process
main() {
    clear
    echo -e "${BLUE}======================================"
    echo -e " 🍯 Industrial IoT Honeypot Installer"
    echo -e "======================================${NC}"
    echo
    
    check_root
    check_ubuntu
    
    echo -e "${YELLOW}This script will install the Industrial IoT Honeypot system.${NC}"
    echo -e "${YELLOW}Please ensure you have sudo privileges.${NC}"
    echo
    read -p "Continue with installation? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 1
    fi
    
    echo
    print_status "Starting installation..."
    
    install_system_deps
    setup_docker
    setup_postgresql
    setup_redis
    create_app_directory
    setup_python_env
    configure_firewall
    create_systemd_service
    setup_log_rotation
    setup_monitoring
    create_config
    init_database
    start_services
    
    show_final_info
}

# Run main function
main "$@"