# Docker Deployment Guide

This guide covers deploying the Industrial IoT Honeypot using Docker and Docker Compose.

## Prerequisites

- Docker 20.10+
- Docker Compose 1.29+
- 4GB RAM minimum
- 20GB disk space

## Quick Start

1. **Clone the repository**:
```bash
git clone https://github.com/wangsw-haha/Project.git
cd Project
```

2. **Set environment variables** (optional):
```bash
export OPENAI_API_KEY="your-openai-api-key"
```

3. **Start the system**:
```bash
docker-compose up -d
```

4. **Access the dashboard**:
- Web Interface: http://localhost:8000
- Kibana Dashboard: http://localhost:5601

## Environment Configuration

Create a `.env` file in the project root:

```env
# LLM Configuration
OPENAI_API_KEY=your-openai-api-key-here

# Database Configuration
POSTGRES_DB=honeypot_db
POSTGRES_USER=honeypot
POSTGRES_PASSWORD=honeypot123

# Security
SECRET_KEY=your-secret-key-here
```

## Service Ports

| Service | Internal Port | External Port | Description |
|---------|---------------|---------------|-------------|
| Web UI | 8000 | 8000 | Management Dashboard |
| SSH Honeypot | 22 | 2222 | SSH Service |
| HTTP Honeypot | 80 | 8080 | Web Service |
| Modbus Honeypot | 502 | 5020 | Industrial Protocol |
| FTP Honeypot | 21 | 2121 | File Transfer |
| Telnet Honeypot | 23 | 2323 | Terminal Access |
| Prometheus | 9090 | 9090 | Metrics |
| Kibana | 5601 | 5601 | Log Analysis |

## Management Commands

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f

# Restart specific service
docker-compose restart honeypot

# Scale honeypot instances
docker-compose up -d --scale honeypot=3

# Update images
docker-compose pull
docker-compose up -d
```

## Persistence

Data is persisted in Docker volumes:
- `postgres_data`: Database files
- `redis_data`: Redis cache
- `elasticsearch_data`: Search index

## Backup and Restore

### Backup
```bash
# Create backup directory
mkdir -p ./backups

# Backup database
docker-compose exec db pg_dump -U honeypot honeypot_db > ./backups/database_$(date +%Y%m%d_%H%M%S).sql

# Backup configuration
docker-compose exec honeypot tar -czf /tmp/config_backup.tar.gz /app/config
docker cp $(docker-compose ps -q honeypot):/tmp/config_backup.tar.gz ./backups/
```

### Restore
```bash
# Restore database
docker-compose exec -T db psql -U honeypot honeypot_db < ./backups/database_20241201_120000.sql

# Restore configuration
docker cp ./backups/config_backup.tar.gz $(docker-compose ps -q honeypot):/tmp/
docker-compose exec honeypot tar -xzf /tmp/config_backup.tar.gz -C /
```

## Monitoring

### Health Checks
```bash
# Check service health
docker-compose ps

# Check resource usage
docker stats

# Check logs for errors
docker-compose logs --tail=100 honeypot | grep ERROR
```

### Metrics Access
- Prometheus: http://localhost:9090
- Grafana (if configured): http://localhost:3000

## Security Considerations

1. **Network Isolation**: Run in isolated Docker network
2. **Firewall**: Only expose necessary ports
3. **Updates**: Regularly update base images
4. **Secrets**: Use Docker secrets for sensitive data
5. **Logging**: Monitor container logs

## Troubleshooting

### Common Issues

1. **Port conflicts**:
```bash
# Check which ports are in use
netstat -tlnp | grep -E "(8000|2222|8080)"

# Modify docker-compose.yml ports if needed
```

2. **Permission errors**:
```bash
# Fix file permissions
sudo chown -R $USER:$USER ./logs ./data

# Check container user
docker-compose exec honeypot id
```

3. **Database connection issues**:
```bash
# Check database status
docker-compose logs db

# Test connection
docker-compose exec honeypot psql postgresql://honeypot:honeypot123@db:5432/honeypot_db -c "SELECT 1;"
```

4. **Memory issues**:
```bash
# Monitor memory usage
docker stats --no-stream

# Adjust memory limits in docker-compose.yml
```

### Debug Mode

Enable debug logging:
```bash
# Set environment variable
echo "APP_DEBUG=true" >> .env

# Restart services
docker-compose restart honeypot
```

## Production Deployment

For production deployment:

1. **Use external database**: Replace PostgreSQL service with external instance
2. **Load balancer**: Add nginx or HAProxy for multiple instances
3. **SSL/TLS**: Configure HTTPS with proper certificates
4. **Monitoring**: Add comprehensive monitoring stack
5. **Backup strategy**: Implement automated backups
6. **Security hardening**: Follow container security best practices

### Production docker-compose.yml example:
```yaml
version: '3.8'

services:
  honeypot:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@external-db:5432/honeypot_db
      - REDIS_URL=redis://external-redis:6379/0
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 1G
        reservations:
          memory: 512M
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl
    depends_on:
      - honeypot
```

## Support

For Docker-specific issues:
- Check the Docker documentation
- Review container logs
- Verify resource allocation
- Test network connectivity between containers