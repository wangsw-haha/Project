import psutil
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List
from collections import defaultdict, deque
from prometheus_client import Counter, Histogram, Gauge, start_http_server
from loguru import logger
from src.database.models import AttackLog, SystemMetrics, get_db_session


class MetricsCollector:
    """Collect and expose metrics for monitoring"""
    
    def __init__(self):
        # Prometheus metrics
        self.attack_counter = Counter(
            'honeypot_attacks_total',
            'Total number of attacks',
            ['service', 'attack_type']
        )
        
        self.connection_counter = Counter(
            'honeypot_connections_total',
            'Total number of connections',
            ['service']
        )
        
        self.session_duration = Histogram(
            'honeypot_session_duration_seconds',
            'Session duration in seconds',
            ['service']
        )
        
        self.system_cpu = Gauge('honeypot_system_cpu_percent', 'CPU usage percentage')
        self.system_memory = Gauge('honeypot_system_memory_percent', 'Memory usage percentage')
        self.system_disk = Gauge('honeypot_system_disk_percent', 'Disk usage percentage')
        self.active_connections = Gauge('honeypot_active_connections', 'Active connections', ['service'])
        
        # Internal metrics storage
        self.attack_history = deque(maxlen=1000)
        self.connection_history = deque(maxlen=1000)
        self.service_stats = defaultdict(lambda: {
            'attacks': 0,
            'connections': 0,
            'last_attack': None
        })
        
        # Start Prometheus metrics server
        self.prometheus_port = 9090
        self._start_prometheus_server()
        
        # Start system metrics collection
        self._start_system_metrics_collection()
    
    def _start_prometheus_server(self):
        """Start Prometheus metrics HTTP server"""
        try:
            start_http_server(self.prometheus_port)
            logger.info(f"Prometheus metrics server started on port {self.prometheus_port}")
        except Exception as e:
            logger.error(f"Failed to start Prometheus server: {e}")
    
    def _start_system_metrics_collection(self):
        """Start collecting system metrics"""
        import threading
        
        def collect_system_metrics():
            while True:
                try:
                    # Collect system metrics
                    cpu_percent = psutil.cpu_percent(interval=1)
                    memory_percent = psutil.virtual_memory().percent
                    disk_percent = psutil.disk_usage('/').percent
                    
                    # Update Prometheus metrics
                    self.system_cpu.set(cpu_percent)
                    self.system_memory.set(memory_percent)
                    self.system_disk.set(disk_percent)
                    
                    # Store in database
                    self._store_system_metrics(cpu_percent, memory_percent, disk_percent)
                    
                    time.sleep(60)  # Collect every minute
                    
                except Exception as e:
                    logger.error(f"Error collecting system metrics: {e}")
                    time.sleep(60)
        
        thread = threading.Thread(target=collect_system_metrics, daemon=True)
        thread.start()
    
    def _store_system_metrics(self, cpu_percent: float, memory_percent: float, disk_percent: float):
        """Store system metrics in database"""
        try:
            db = get_db_session()
            
            # Calculate network stats
            network_stats = psutil.net_io_counters()
            
            # Calculate attack rate (attacks per minute)
            now = datetime.now()
            recent_attacks = [
                attack for attack in self.attack_history
                if (now - attack['timestamp']).total_seconds() < 60
            ]
            attack_rate = len(recent_attacks)
            
            # Calculate active connections
            total_connections = sum(
                stats['connections'] for stats in self.service_stats.values()
            )
            
            metrics = SystemMetrics(
                cpu_usage=cpu_percent,
                memory_usage=memory_percent,
                disk_usage=disk_percent,
                network_in=network_stats.bytes_recv,
                network_out=network_stats.bytes_sent,
                active_connections=total_connections,
                attack_rate=attack_rate
            )
            
            db.add(metrics)
            db.commit()
            db.close()
            
        except Exception as e:
            logger.error(f"Error storing system metrics: {e}")
    
    def increment_attack_counter(self, service: str, attack_type: str):
        """Increment attack counter"""
        self.attack_counter.labels(service=service, attack_type=attack_type).inc()
        
        # Store in internal history
        self.attack_history.append({
            'service': service,
            'attack_type': attack_type,
            'timestamp': datetime.now()
        })
        
        # Update service stats
        self.service_stats[service]['attacks'] += 1
        self.service_stats[service]['last_attack'] = datetime.now()
    
    def increment_connection_counter(self, service: str):
        """Increment connection counter"""
        self.connection_counter.labels(service=service).inc()
        
        # Store in internal history
        self.connection_history.append({
            'service': service,
            'timestamp': datetime.now()
        })
        
        # Update service stats
        self.service_stats[service]['connections'] += 1
    
    def record_session_duration(self, service: str, duration: float):
        """Record session duration"""
        self.session_duration.labels(service=service).observe(duration)
    
    def update_active_connections(self, service: str, count: int):
        """Update active connections gauge"""
        self.active_connections.labels(service=service).set(count)
    
    def get_attack_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get attack summary for the last N hours"""
        try:
            db = get_db_session()
            
            # Calculate time window
            since = datetime.now() - timedelta(hours=hours)
            
            # Query attacks
            attacks = db.query(AttackLog).filter(
                AttackLog.timestamp >= since
            ).all()
            
            # Aggregate data
            summary = {
                'total_attacks': len(attacks),
                'unique_ips': len(set(attack.source_ip for attack in attacks)),
                'services': defaultdict(int),
                'attack_types': defaultdict(int),
                'top_attackers': defaultdict(int),
                'hourly_distribution': defaultdict(int)
            }
            
            for attack in attacks:
                summary['services'][attack.service] += 1
                summary['attack_types'][attack.attack_type] += 1
                summary['top_attackers'][attack.source_ip] += 1
                hour = attack.timestamp.hour
                summary['hourly_distribution'][hour] += 1
            
            # Convert to regular dicts and sort
            summary['services'] = dict(summary['services'])
            summary['attack_types'] = dict(summary['attack_types'])
            summary['top_attackers'] = dict(
                sorted(summary['top_attackers'].items(), 
                      key=lambda x: x[1], reverse=True)[:10]
            )
            summary['hourly_distribution'] = dict(summary['hourly_distribution'])
            
            db.close()
            return summary
            
        except Exception as e:
            logger.error(f"Error getting attack summary: {e}")
            return {
                'total_attacks': 0,
                'unique_ips': 0,
                'services': {},
                'attack_types': {},
                'top_attackers': {},
                'hourly_distribution': {}
            }
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get current service status"""
        return {
            'services': dict(self.service_stats),
            'total_attacks': sum(stats['attacks'] for stats in self.service_stats.values()),
            'total_connections': sum(stats['connections'] for stats in self.service_stats.values())
        }
    
    def get_recent_attacks(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent attacks"""
        try:
            db = get_db_session()
            
            attacks = db.query(AttackLog).order_by(
                AttackLog.timestamp.desc()
            ).limit(limit).all()
            
            result = []
            for attack in attacks:
                result.append({
                    'id': attack.id,
                    'timestamp': attack.timestamp.isoformat(),
                    'source_ip': attack.source_ip,
                    'service': attack.service,
                    'attack_type': attack.attack_type,
                    'payload': attack.payload[:200] if attack.payload else '',
                    'country': attack.country,
                    'severity': attack.severity
                })
            
            db.close()
            return result
            
        except Exception as e:
            logger.error(f"Error getting recent attacks: {e}")
            return []
    
    def get_geographic_distribution(self) -> Dict[str, int]:
        """Get geographic distribution of attacks"""
        try:
            db = get_db_session()
            
            # Get attacks from the last 24 hours
            since = datetime.now() - timedelta(hours=24)
            attacks = db.query(AttackLog).filter(
                AttackLog.timestamp >= since,
                AttackLog.country.isnot(None)
            ).all()
            
            country_counts = defaultdict(int)
            for attack in attacks:
                if attack.country:
                    country_counts[attack.country] += 1
            
            db.close()
            return dict(country_counts)
            
        except Exception as e:
            logger.error(f"Error getting geographic distribution: {e}")
            return {}


# Global metrics collector instance
metrics_collector = MetricsCollector()