# Industrial Internet Honeypot with LLM-based Dynamic Response

A sophisticated honeypot system designed for industrial Internet environments with intelligent response capabilities powered by Large Language Models (LLM). This system can detect various cyber attacks and provide dynamic, contextual responses to engage attackers while gathering intelligence.

## 🚀 Features

### Core Capabilities
- **Multi-Protocol Support**: HTTP/HTTPS, SSH, Telnet, Modbus TCP
- **LLM-Powered Responses**: Dynamic, intelligent responses using OpenAI GPT models
- **Attack Detection**: Pattern-based detection for SQL injection, XSS, command injection, brute force, and more
- **Industrial Simulation**: Realistic SCADA/HMI interfaces and industrial protocol responses
- **Comprehensive Logging**: Detailed attack logs with JSON formatting
- **Real-time Monitoring**: Live attack statistics and pattern analysis

### Attack Detection
- SQL Injection attempts
- Cross-Site Scripting (XSS)
- Command injection
- Directory traversal
- Brute force authentication
- Port scanning
- Suspicious payload analysis

### Protocol Handlers
- **HTTP/HTTPS**: Simulated industrial web interfaces (HMI, SCADA dashboards)
- **SSH**: Interactive shell sessions with realistic industrial system commands
- **Telnet**: SCADA terminal interface with industrial control menus
- **Modbus TCP**: Full Modbus protocol implementation with simulated PLC data

## 📋 Requirements

- **Operating System**: Ubuntu 18.04+ (recommended 20.04 or 22.04)
- **Python**: 3.8+ (3.11 recommended)
- **Memory**: 2GB RAM minimum, 4GB recommended
- **Network**: Root privileges for binding to privileged ports (22, 80, etc.)
- **Optional**: OpenAI API key for LLM features

## 🔧 Installation

### Method 1: Automated Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-username/industrial-honeypot.git
cd industrial-honeypot

# Run the installation script
chmod +x deploy/install.sh
./deploy/install.sh
```

### Method 2: Docker Deployment

```bash
# Clone and build
git clone https://github.com/your-username/industrial-honeypot.git
cd industrial-honeypot

# Set your OpenAI API key (optional)
echo "OPENAI_API_KEY=your_api_key_here" > .env

# Deploy with Docker Compose
cd deploy
docker-compose up -d

# Check status
docker-compose ps
docker-compose logs -f honeypot
```

### Method 3: Manual Installation

```bash
# Install dependencies
sudo apt update
sudo apt install python3.11 python3.11-pip python3.11-venv build-essential

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install Python packages
pip install -r requirements.txt

# Configure
cp config/honeypot.yaml.example config/honeypot.yaml
# Edit configuration as needed

# Run
python src/main.py
```

## ⚙️ Configuration

### Main Configuration File: `config/honeypot.yaml`

```yaml
honeypot:
  name: "Industrial-Honeypot-LLM"
  
  network:
    bind_ip: "0.0.0.0"
    ports:
      http: 80
      ssh: 22
      telnet: 23
      modbus: 502
      
  llm:
    provider: "openai"
    model: "gpt-3.5-turbo"
    api_key_env: "OPENAI_API_KEY"
    
  detection:
    enabled: true
    sensitivity: "medium"
    
  response:
    mode: "dynamic"  # static, dynamic
    fake_vulnerability_rate: 0.3
    
  logging:
    level: "INFO"
    file: "logs/honeypot.log"
```

### Environment Variables

Create `/etc/honeypot/environment` or `.env` file:

```bash
# Required for LLM features
OPENAI_API_KEY=your_openai_api_key_here

# Optional configurations
HONEYPOT_LOG_LEVEL=INFO
HONEYPOT_BIND_IP=0.0.0.0
```

## 🎯 Usage

### Starting the Honeypot

```bash
# Using systemd service (after installation)
honeypot-start

# Or manually
python src/main.py -c config/honeypot.yaml

# With Docker
docker-compose up -d
```

### Monitoring

```bash
# View real-time logs
honeypot-logs

# Check status
honeypot-status

# View attack statistics
tail -f logs/honeypot.log | grep "ATTACK DETECTED"
```

### Stopping

```bash
# Using systemd
honeypot-stop

# With Docker
docker-compose down
```

## 📊 Log Analysis

The honeypot generates detailed JSON logs for each attack:

```json
{
  "timestamp": "2024-01-15T14:30:25.123456",
  "event_type": "attack_detected",
  "attack_type": "sql_injection",
  "source_ip": "192.168.1.100",
  "target_port": 80,
  "protocol": "HTTP",
  "payload": "' OR 1=1--",
  "severity": "high",
  "response_sent": true,
  "llm_generated": true
}
```

## 🛡️ Security Considerations

### Production Deployment
- Run on isolated network segments
- Monitor logs continuously
- Update regularly
- Use strong firewall rules
- Limit outbound connections

### Legal and Ethical Use
- Only deploy on networks you own or have explicit permission to monitor
- Comply with local laws and regulations
- Consider privacy implications
- Document and report findings appropriately

## 🔍 Attack Scenarios

### Web Application Attacks
The HTTP handler simulates industrial web interfaces and can detect:
- SQL injection in search forms
- XSS attempts in user input
- Directory traversal attacks
- Command injection in web parameters

### Industrial Protocol Attacks
The Modbus handler can detect:
- Unauthorized read/write operations
- Function code abuse
- Large data requests (potential DoS)
- Unusual communication patterns

### Remote Access Attacks
SSH and Telnet handlers detect:
- Brute force authentication attempts
- Command injection in shell sessions
- Privilege escalation attempts
- Suspicious command patterns

## 📈 Extending the Honeypot

### Adding New Protocols

1. Create a new handler in `src/protocols/`
2. Implement the protocol logic
3. Add attack detection patterns
4. Register in `src/core/honeypot.py`

### Custom Attack Detection

1. Add patterns to `src/core/attack_detector.py`
2. Define response templates in `config/responses.yaml`
3. Create LLM prompts for dynamic responses

### Integration with SIEM

The honeypot outputs structured JSON logs that can be easily integrated with:
- Splunk
- Elastic Stack (ELK)
- IBM QRadar
- ArcSight
- Chronicle

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This honeypot is designed for research, education, and authorized security testing only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this software.

## 📞 Support

- **Documentation**: Check the `docs/` directory for detailed guides
- **Issues**: Report bugs and feature requests on GitHub
- **Security**: Report security issues privately to the maintainers

## 🙏 Acknowledgments

- OpenAI for GPT models
- Industrial protocol specifications and standards bodies
- The cybersecurity research community
- Contributors and testers

---

**Warning**: This is a honeypot system designed to attract and log malicious activity. Only deploy in controlled environments with proper security measures in place.