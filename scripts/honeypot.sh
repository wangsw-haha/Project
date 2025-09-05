#!/bin/bash

# Management script for the Industrial IoT Honeypot

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

APP_DIR="/opt/honeypot"
SERVICE_NAME="honeypot"

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

show_help() {
    echo "Industrial IoT Honeypot Management Script"
    echo
    echo "Usage: $0 [COMMAND]"
    echo
    echo "Commands:"
    echo "  start           Start the honeypot service"
    echo "  stop            Stop the honeypot service"
    echo "  restart         Restart the honeypot service"
    echo "  status          Show service status"
    echo "  logs            Show service logs"
    echo "  follow-logs     Follow service logs in real-time"
    echo "  stats           Show attack statistics"
    echo "  backup          Backup database and configuration"
    echo "  restore         Restore from backup"
    echo "  update          Update the honeypot system"
    echo "  test            Test honeypot services"
    echo "  docker-start    Start using Docker Compose"
    echo "  docker-stop     Stop Docker Compose services"
    echo "  docker-logs     Show Docker logs"
    echo "  help            Show this help message"
}

start_service() {
    print_status "Starting honeypot service..."
    sudo systemctl start $SERVICE_NAME
    sleep 2
    
    if sudo systemctl is-active --quiet $SERVICE_NAME; then
        print_success "Honeypot service started successfully"
        show_status
    else
        print_error "Failed to start honeypot service"
        sudo systemctl status $SERVICE_NAME
        exit 1
    fi
}

stop_service() {
    print_status "Stopping honeypot service..."
    sudo systemctl stop $SERVICE_NAME
    print_success "Honeypot service stopped"
}

restart_service() {
    print_status "Restarting honeypot service..."
    sudo systemctl restart $SERVICE_NAME
    sleep 2
    
    if sudo systemctl is-active --quiet $SERVICE_NAME; then
        print_success "Honeypot service restarted successfully"
        show_status
    else
        print_error "Failed to restart honeypot service"
        exit 1
    fi
}

show_status() {
    print_status "Service Status:"
    sudo systemctl status $SERVICE_NAME --no-pager -l
    
    echo
    print_status "Port Status:"
    sudo netstat -tlnp | grep -E "(8000|2222|8080|5020|2121|2323|9090)" || echo "No honeypot ports found"
    
    echo
    print_status "System Resources:"
    echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')%"
    echo "Memory: $(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')"
    echo "Disk: $(df -h / | awk 'NR==2{printf "%s", $5}')"
}

show_logs() {
    print_status "Recent service logs:"
    sudo journalctl -u $SERVICE_NAME --no-pager -n 50
}

follow_logs() {
    print_status "Following service logs (Ctrl+C to exit):"
    sudo journalctl -u $SERVICE_NAME -f
}

show_stats() {
    print_status "Attack Statistics:"
    
    if [ -f "$APP_DIR/venv/bin/python" ] && [ -d "$APP_DIR/src" ]; then
        cd $APP_DIR
        source venv/bin/activate
        
        python3 -c "
import sys
sys.path.insert(0, 'src')
from database.models import get_db_session, AttackLog
from datetime import datetime, timedelta

try:
    db = get_db_session()
    
    # Total attacks
    total = db.query(AttackLog).count()
    print(f'Total attacks: {total}')
    
    # Last 24 hours
    since = datetime.now() - timedelta(hours=24)
    recent = db.query(AttackLog).filter(AttackLog.timestamp >= since).count()
    print(f'Last 24 hours: {recent}')
    
    # By service
    print('\nBy service:')
    from sqlalchemy import func
    services = db.query(AttackLog.service, func.count(AttackLog.id)).group_by(AttackLog.service).all()
    for service, count in services:
        print(f'  {service}: {count}')
    
    # Top attackers
    print('\nTop attackers:')
    attackers = db.query(AttackLog.source_ip, func.count(AttackLog.id)).group_by(AttackLog.source_ip).order_by(func.count(AttackLog.id).desc()).limit(5).all()
    for ip, count in attackers:
        print(f'  {ip}: {count}')
    
    db.close()
    
except Exception as e:
    print(f'Error getting statistics: {e}')
"
    else
        print_error "Cannot access honeypot application"
    fi
}

backup_system() {
    print_status "Creating backup..."
    
    BACKUP_DIR="/tmp/honeypot_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p $BACKUP_DIR
    
    # Backup database
    print_status "Backing up database..."
    sudo -u postgres pg_dump honeypot_db > $BACKUP_DIR/database.sql
    
    # Backup configuration
    print_status "Backing up configuration..."
    if [ -d "$APP_DIR/config" ]; then
        cp -r $APP_DIR/config $BACKUP_DIR/
    fi
    
    # Backup logs (last 1000 lines)
    print_status "Backing up recent logs..."
    if [ -d "$APP_DIR/logs" ]; then
        mkdir -p $BACKUP_DIR/logs
        for logfile in $APP_DIR/logs/*.log; do
            if [ -f "$logfile" ]; then
                tail -n 1000 "$logfile" > $BACKUP_DIR/logs/$(basename "$logfile")
            fi
        done
    fi
    
    # Create archive
    cd /tmp
    tar -czf honeypot_backup_$(date +%Y%m%d_%H%M%S).tar.gz $(basename $BACKUP_DIR)
    rm -rf $BACKUP_DIR
    
    print_success "Backup created: /tmp/honeypot_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
}

test_services() {
    print_status "Testing honeypot services..."
    
    # Test web interface
    print_status "Testing web interface..."
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8000 | grep -q "200"; then
        print_success "Web interface: OK"
    else
        print_error "Web interface: Failed"
    fi
    
    # Test SSH honeypot
    print_status "Testing SSH honeypot..."
    if timeout 5 ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no user@localhost -p 2222 exit 2>/dev/null; then
        print_success "SSH honeypot: OK"
    else
        print_warning "SSH honeypot: Not responding (may be normal)"
    fi
    
    # Test HTTP honeypot
    print_status "Testing HTTP honeypot..."
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 | grep -q -E "(200|404)"; then
        print_success "HTTP honeypot: OK"
    else
        print_error "HTTP honeypot: Failed"
    fi
    
    # Test Modbus honeypot
    print_status "Testing Modbus honeypot..."
    if timeout 3 bash -c "</dev/tcp/localhost/5020" 2>/dev/null; then
        print_success "Modbus honeypot: OK"
    else
        print_warning "Modbus honeypot: Not responding"
    fi
    
    print_status "Service test completed"
}

docker_start() {
    print_status "Starting Docker Compose services..."
    docker-compose up -d
    print_success "Docker services started"
    
    sleep 5
    docker-compose ps
}

docker_stop() {
    print_status "Stopping Docker Compose services..."
    docker-compose down
    print_success "Docker services stopped"
}

docker_logs() {
    print_status "Docker Compose logs:"
    docker-compose logs -f
}

update_system() {
    print_status "Updating honeypot system..."
    
    # Stop service
    if sudo systemctl is-active --quiet $SERVICE_NAME; then
        print_status "Stopping service for update..."
        sudo systemctl stop $SERVICE_NAME
    fi
    
    # Update from git (if in git repo)
    if [ -d "$APP_DIR/.git" ]; then
        print_status "Pulling latest changes..."
        cd $APP_DIR
        git pull
    fi
    
    # Update Python dependencies
    if [ -f "$APP_DIR/venv/bin/pip" ]; then
        print_status "Updating Python dependencies..."
        cd $APP_DIR
        source venv/bin/activate
        pip install --upgrade -r requirements.txt
    fi
    
    # Restart service
    print_status "Starting service after update..."
    sudo systemctl start $SERVICE_NAME
    
    print_success "Update completed"
}

# Main command processing
case "${1:-help}" in
    "start")
        start_service
        ;;
    "stop")
        stop_service
        ;;
    "restart")
        restart_service
        ;;
    "status")
        show_status
        ;;
    "logs")
        show_logs
        ;;
    "follow-logs")
        follow_logs
        ;;
    "stats")
        show_stats
        ;;
    "backup")
        backup_system
        ;;
    "test")
        test_services
        ;;
    "docker-start")
        docker_start
        ;;
    "docker-stop")
        docker_stop
        ;;
    "docker-logs")
        docker_logs
        ;;
    "update")
        update_system
        ;;
    "help"|*)
        show_help
        ;;
esac