"""
Attack detection engine for identifying and classifying attacks.
"""

import re
import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque


class AttackDetector:
    """Engine for detecting and classifying cyber attacks."""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('honeypot.detector')
        
        # Attack tracking
        self.connection_history = defaultdict(deque)
        self.failed_attempts = defaultdict(int)
        self.attack_patterns = []
        
        # Detection patterns
        self.sql_patterns = [
            r"'.*OR.*'.*'",
            r"UNION.*SELECT",
            r"DROP.*TABLE",
            r"INSERT.*INTO",
            r"DELETE.*FROM",
            r"--.*",
            r"/\*.*\*/",
            r"EXEC.*\(",
            r"CAST.*\(",
            r"CONVERT.*\("
        ]
        
        self.xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe.*?>",
            r"<object.*?>",
            r"<embed.*?>",
            r"<link.*?>",
            r"<meta.*?>"
        ]
        
        self.command_injection_patterns = [
            r";.*\w+",
            r"\|.*\w+",
            r"&&.*\w+",
            r"\$\(.*\)",
            r"`.*`",
            r"../",
            r"\\.\\.\\",
            r"cat\s+/etc/passwd",
            r"whoami",
            r"id\s*$",
            r"uname\s*-a"
        ]
        
        self.common_payloads = [
            "admin", "administrator", "root", "test", "guest",
            "password", "123456", "admin123", "password123",
            "/../../../etc/passwd", "..\\..\\..\\windows\\system32\\",
            "SELECT * FROM users", "<script>alert('xss')</script>"
        ]
        
    async def analyze_request(self, request_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze incoming request for attack patterns."""
        source_ip = request_data.get('source_ip', '')
        target_port = request_data.get('target_port', 0)
        protocol = request_data.get('protocol', '')
        payload = str(request_data.get('payload', ''))
        
        # Track connection
        self._track_connection(source_ip, target_port)
        
        # Detect attack types
        attack_types = []
        
        # SQL Injection detection
        if self._detect_sql_injection(payload):
            attack_types.append('sql_injection')
            
        # XSS detection
        if self._detect_xss(payload):
            attack_types.append('xss')
            
        # Command injection detection
        if self._detect_command_injection(payload):
            attack_types.append('command_injection')
            
        # Brute force detection
        if self._detect_brute_force(source_ip, payload):
            attack_types.append('brute_force')
            
        # Port scan detection
        if self._detect_port_scan(source_ip):
            attack_types.append('port_scan')
            
        # Directory traversal
        if self._detect_directory_traversal(payload):
            attack_types.append('directory_traversal')
            
        if not attack_types:
            # Check for suspicious patterns
            if self._is_suspicious_payload(payload):
                attack_types.append('suspicious_activity')
                
        if attack_types:
            attack_info = {
                'type': attack_types[0],  # Primary attack type
                'all_types': attack_types,
                'source_ip': source_ip,
                'target_port': target_port,
                'protocol': protocol,
                'payload': payload,
                'timestamp': datetime.utcnow().isoformat(),
                'severity': self._calculate_severity(attack_types),
                'detection_method': 'pattern_matching',
                'confidence': self._calculate_confidence(payload, attack_types)
            }
            
            self.attack_patterns.append(attack_info)
            return attack_info
            
        return None
        
    def _detect_sql_injection(self, payload: str) -> bool:
        """Detect SQL injection attempts."""
        payload_lower = payload.lower()
        return any(re.search(pattern, payload_lower, re.IGNORECASE) 
                  for pattern in self.sql_patterns)
                  
    def _detect_xss(self, payload: str) -> bool:
        """Detect XSS attempts."""
        return any(re.search(pattern, payload, re.IGNORECASE) 
                  for pattern in self.xss_patterns)
                  
    def _detect_command_injection(self, payload: str) -> bool:
        """Detect command injection attempts."""
        return any(re.search(pattern, payload) 
                  for pattern in self.command_injection_patterns)
                  
    def _detect_brute_force(self, source_ip: str, payload: str) -> bool:
        """Detect brute force attempts."""
        # Check for common credentials
        payload_lower = payload.lower()
        has_common_creds = any(cred in payload_lower for cred in self.common_payloads[:10])
        
        if has_common_creds:
            self.failed_attempts[source_ip] += 1
            
        # Brute force threshold
        return self.failed_attempts[source_ip] > 3
        
    def _detect_port_scan(self, source_ip: str) -> bool:
        """Detect port scanning attempts."""
        connections = self.connection_history[source_ip]
        
        # Check if same IP connected to multiple ports recently
        recent_connections = [
            conn for conn in connections 
            if datetime.fromisoformat(conn['timestamp']) > datetime.utcnow() - timedelta(minutes=5)
        ]
        
        unique_ports = set(conn['port'] for conn in recent_connections)
        return len(unique_ports) > 5
        
    def _detect_directory_traversal(self, payload: str) -> bool:
        """Detect directory traversal attempts."""
        traversal_patterns = ['../', '..\\', '%2e%2e%2f', '%2e%2e%5c']
        return any(pattern in payload.lower() for pattern in traversal_patterns)
        
    def _is_suspicious_payload(self, payload: str) -> bool:
        """Check for generally suspicious patterns."""
        suspicious_keywords = [
            'passwd', 'shadow', 'hosts', 'config', 'admin',
            'system', 'bin', 'etc', 'var', 'proc',
            'shell', 'bash', 'cmd', 'powershell'
        ]
        
        payload_lower = payload.lower()
        return any(keyword in payload_lower for keyword in suspicious_keywords)
        
    def _track_connection(self, source_ip: str, target_port: int) -> None:
        """Track connection attempts."""
        connection_info = {
            'timestamp': datetime.utcnow().isoformat(),
            'port': target_port
        }
        
        connections = self.connection_history[source_ip]
        connections.append(connection_info)
        
        # Keep only last 100 connections per IP
        if len(connections) > 100:
            connections.popleft()
            
    def _calculate_severity(self, attack_types: List[str]) -> str:
        """Calculate attack severity."""
        high_severity_attacks = ['command_injection', 'sql_injection']
        medium_severity_attacks = ['xss', 'brute_force', 'directory_traversal']
        
        if any(attack in high_severity_attacks for attack in attack_types):
            return 'high'
        elif any(attack in medium_severity_attacks for attack in attack_types):
            return 'medium'
        else:
            return 'low'
            
    def _calculate_confidence(self, payload: str, attack_types: List[str]) -> float:
        """Calculate detection confidence."""
        base_confidence = 0.7
        
        # Increase confidence for multiple attack types
        if len(attack_types) > 1:
            base_confidence += 0.1
            
        # Increase confidence for longer, more complex payloads
        if len(payload) > 100:
            base_confidence += 0.1
            
        # Decrease confidence for very short payloads
        if len(payload) < 10:
            base_confidence -= 0.2
            
        return min(1.0, max(0.1, base_confidence))
        
    def get_recent_attacks(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Get recent attacks within specified time window."""
        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        
        return [
            attack for attack in self.attack_patterns
            if datetime.fromisoformat(attack['timestamp']) > cutoff_time
        ]
        
    def get_attack_stats(self) -> Dict[str, Any]:
        """Get attack statistics."""
        if not self.attack_patterns:
            return {'total_attacks': 0}
            
        attack_types = [attack['type'] for attack in self.attack_patterns]
        type_counts = defaultdict(int)
        for attack_type in attack_types:
            type_counts[attack_type] += 1
            
        recent_attacks = self.get_recent_attacks(60)
        
        return {
            'total_attacks': len(self.attack_patterns),
            'recent_attacks': len(recent_attacks),
            'attack_types': dict(type_counts),
            'unique_ips': len(set(attack['source_ip'] for attack in self.attack_patterns)),
            'most_targeted_port': max(
                (attack['target_port'] for attack in self.attack_patterns),
                key=lambda port: sum(1 for a in self.attack_patterns if a['target_port'] == port),
                default=0
            )
        }