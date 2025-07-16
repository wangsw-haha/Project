# Industrial IoT Honeypot System

🍯 A comprehensive industrial internet honeypot system with AI-powered attack analysis and real-time monitoring capabilities.

## Overview

This honeypot system simulates various industrial protocols and services to attract, detect, and analyze cyber attacks targeting industrial control systems (ICS), SCADA systems, and IoT devices. It features Large Language Model (LLM) integration for intelligent response generation and attack analysis.

## Features

### 🛡️ **Multi-Protocol Honeypots**
- **SSH Honeypot**: Simulates Linux servers with fake filesystem and command execution
- **HTTP Honeypot**: Mimics web applications with vulnerable endpoints
- **Modbus TCP Honeypot**: Industrial protocol simulation for PLC attacks
- **FTP Honeypot**: File transfer protocol with fake file systems
- **Telnet Honeypot**: Legacy terminal access simulation

### 🤖 **AI-Powered Analysis**
- **LLM Integration**: OpenAI GPT and Hugging Face model support
- **Intelligent Responses**: Context-aware command responses
- **Attack Classification**: Automated threat categorization
- **Behavioral Analysis**: Pattern recognition and anomaly detection

### 📊 **Real-time Monitoring**
- **Web Dashboard**: Comprehensive attack visualization
- **Prometheus Metrics**: System and attack metrics
- **Elasticsearch Integration**: Advanced log analysis
- **Geographic Tracking**: Attack source mapping
- **Real-time Alerts**: Configurable notification system

### 🔧 **Enterprise Ready**
- **Docker Containerization**: Easy deployment and scaling
- **Database Persistence**: PostgreSQL for attack data storage
- **Redis Caching**: High-performance session management
- **Load Balancing**: Multi-instance deployment support
- **Security Hardened**: Following security best practices

## Quick Start

### Prerequisites
- Ubuntu 18.04+ (recommended: 20.04 LTS)
- 4GB RAM minimum (8GB recommended)
- 20GB disk space
- Internet connection for dependencies

### Installation

#### Method 1: Automated Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/wangsw-haha/Project.git
cd Project

# Run the installation script
sudo bash scripts/install.sh
```

#### Method 2: Docker Deployment

```bash
# Clone the repository
git clone https://github.com/wangsw-haha/Project.git
cd Project

# Set environment variables (optional)
export OPENAI_API_KEY="your-openai-api-key"

# Start with Docker Compose
docker-compose up -d
```

#### Method 3: Manual Installation

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip postgresql redis-server

# Clone and setup
git clone https://github.com/wangsw-haha/Project.git
cd Project

# Install Python dependencies
pip3 install -r requirements.txt

# Setup database
sudo -u postgres createdb honeypot_db
sudo -u postgres createuser honeypot

# Run the application
python3 src/main.py
```

## Configuration

### Environment Variables

```bash
# Database Configuration
DATABASE_URL=postgresql://honeypot:honeypot123@localhost:5432/honeypot_db

# Redis Configuration  
REDIS_URL=redis://localhost:6379/0

# LLM Configuration
OPENAI_API_KEY=your-openai-api-key
LLM_PROVIDER=openai  # or huggingface

# Application Configuration
APP_HOST=0.0.0.0
APP_PORT=8000
```

### Configuration File

Edit `config/config.yaml` to customize honeypot behavior:

```yaml
honeypots:
  ssh:
    enabled: true
    port: 2222
    banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    
  http:
    enabled: true
    port: 8080
    server_header: "Apache/2.4.41 (Ubuntu)"
    
  modbus:
    enabled: true
    port: 5020
    device_name: "Industrial PLC Controller"
```

## Access Points

After installation, access the system through:

- **Web Dashboard**: http://localhost:8000
- **Prometheus Metrics**: http://localhost:9090
- **Kibana (if enabled)**: http://localhost:5601

### Honeypot Services

- **SSH**: `ssh user@localhost -p 2222`
- **HTTP**: http://localhost:8080
- **Modbus**: TCP port 5020
- **FTP**: `ftp localhost 2121`
- **Telnet**: `telnet localhost 2323`

## Usage

### Monitoring Attacks

1. **Real-time Dashboard**: Visit the web interface to see live attack data
2. **Attack Analysis**: View detailed attack information with LLM analysis
3. **Geographic Distribution**: See attack sources on a world map
4. **Metrics**: Monitor system performance and attack rates

### Managing Services

```bash
# Service management
sudo systemctl start honeypot
sudo systemctl stop honeypot
sudo systemctl status honeypot

# View logs
sudo journalctl -u honeypot -f

# Docker management
docker-compose up -d    # Start
docker-compose down     # Stop
docker-compose logs -f  # View logs
```

### Database Access

```sql
-- Connect to database
psql -h localhost -U honeypot -d honeypot_db

-- View attack logs
SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT 10;

-- Attack statistics
SELECT service, COUNT(*) as attacks 
FROM attack_logs 
GROUP BY service;
```

## API Reference

### REST API Endpoints

```http
GET /api/status                    # System status
GET /api/attacks/summary          # Attack summary
GET /api/attacks/recent           # Recent attacks
GET /api/attacks/{id}             # Attack details
GET /api/metrics/system           # System metrics
GET /api/sessions/active          # Active sessions
```

### Example API Usage

```bash
# Get system status
curl http://localhost:8000/api/status

# Get recent attacks
curl http://localhost:8000/api/attacks/recent?limit=5

# Get attack summary for last 24 hours
curl http://localhost:8000/api/attacks/summary?hours=24
```

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Attackers     │────│   Honeypots     │────│   Analysis      │
│                 │    │                 │    │                 │
│ • SSH Clients   │    │ • SSH Service   │    │ • LLM Analysis  │
│ • Web Crawlers  │    │ • HTTP Server   │    │ • Pattern Det.  │
│ • Modbus Tools  │    │ • Modbus TCP    │    │ • Threat Intel  │
│ • FTP Clients   │    │ • FTP Server    │    │ • Geolocation   │
│ • Telnet Bots   │    │ • Telnet Server │    │ • Classification │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                        ┌───────▼────────┐
                        │   Data Store   │
                        │                │
                        │ • PostgreSQL   │
                        │ • Redis Cache  │
                        │ • Elasticsearch│
                        └────────────────┘
                                │
                        ┌───────▼────────┐
                        │  Monitoring    │
                        │                │
                        │ • Web Dashboard│
                        │ • Prometheus   │
                        │ • Grafana      │
                        │ • Alerts       │
                        └────────────────┘
```

## Security Considerations

### Deployment Security

1. **Network Isolation**: Deploy in a segmented network
2. **Firewall Rules**: Restrict access to management interfaces
3. **Regular Updates**: Keep system and dependencies updated
4. **Backup Strategy**: Regular database and configuration backups
5. **Monitoring**: Set up alerts for unusual activity

### Legal and Ethical Notes

- **Authorization**: Only deploy on networks you own or have permission to monitor
- **Data Privacy**: Ensure compliance with local privacy regulations
- **Responsible Disclosure**: Share threat intelligence responsibly
- **Log Retention**: Implement appropriate data retention policies

## Development

### Project Structure

```
Project/
├── src/
│   ├── core/           # Core framework
│   ├── honeypots/      # Honeypot implementations
│   ├── llm/           # LLM integration
│   ├── database/      # Database models
│   ├── monitoring/    # Metrics and monitoring
│   └── web/           # Web interface
├── config/            # Configuration files
├── scripts/           # Deployment scripts
├── tests/             # Test suite
├── docs/              # Documentation
└── docker-compose.yml # Container orchestration
```

### Adding New Honeypots

1. Create a new honeypot class inheriting from `BaseHoneypot`
2. Implement the required methods (`start`, `stop`, `handle_client`)
3. Register the honeypot in `src/main.py`
4. Add configuration in `config/config.yaml`

Example:

```python
from src.core.honeypot import BaseHoneypot

class MyHoneypot(BaseHoneypot):
    def __init__(self, config):
        super().__init__("my_service", config.get("port", 1234), config)
    
    async def start(self):
        # Implementation here
        pass
    
    async def stop(self):
        # Implementation here
        pass
```

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=src

# Run specific test
python -m pytest tests/test_honeypots.py
```

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Check what's using the port
   sudo netstat -tlnp | grep :8000
   
   # Change port in config or stop conflicting service
   ```

2. **Database Connection Failed**
   ```bash
   # Check PostgreSQL status
   sudo systemctl status postgresql
   
   # Verify credentials
   psql -h localhost -U honeypot -d honeypot_db
   ```

3. **Permission Denied**
   ```bash
   # Fix file permissions
   sudo chown -R $USER:$USER /opt/honeypot
   
   # Check service user
   sudo systemctl status honeypot
   ```

### Logs and Debugging

```bash
# Application logs
tail -f /opt/honeypot/logs/honeypot.log

# System service logs
sudo journalctl -u honeypot -f

# Database logs
sudo tail -f /var/log/postgresql/postgresql-*.log

# Enable debug mode
export APP_DEBUG=true
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Commit your changes: `git commit -am 'Add feature'`
5. Push to the branch: `git push origin feature-name`
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- OpenAI for GPT API integration
- Hugging Face for transformer models
- The cybersecurity community for threat intelligence
- Industrial security researchers for protocol insights

## Support

- **Documentation**: Check the `/docs` directory for detailed guides
- **Issues**: Report bugs and feature requests on GitHub
- **Community**: Join discussions in GitHub Discussions
- **Security**: Report security issues privately to maintainers

---

**⚠️ Warning**: This is a honeypot system designed to attract malicious activity. Only deploy in controlled environments with proper security measures.

**🛡️ Remember**: The goal is to learn about threats and improve security, not to cause harm or violate laws.