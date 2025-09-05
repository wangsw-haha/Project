"""
Attack Classification System for Industrial IoT Honeypot
Classifies incoming traffic into 10 attack types and generates appropriate responses
"""

import re
import time
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass
from loguru import logger


class AttackType(Enum):
    """Enumeration of attack types"""
    NORMAL_TRAFFIC = "normal_traffic"  # 正常流量
    MODBUS_FLOOD = "modbus_flood"  # Modbus洪水攻击
    REGISTER_MANIPULATION = "register_manipulation"  # 寄存器操控
    PROTOCOL_ANOMALY = "protocol_anomaly"  # 协议异常
    DOS_ATTACK = "dos_attack"  # 拒绝服务攻击
    MITM_ATTACK = "mitm_attack"  # 中间人攻击
    SCAN_ATTACK = "scan_attack"  # 扫描攻击
    BRUTE_FORCE = "brute_force"  # 暴力破解
    MALFORMED_PACKET = "malformed_packet"  # 畸形数据包
    UNKNOWN_ATTACK = "unknown_attack"  # 未知攻击


@dataclass
class AttackClassification:
    """Attack classification result"""
    attack_type: AttackType
    confidence: float
    severity: str  # low, medium, high, critical
    description: str
    indicators: List[str]
    response_strategy: str


class AttackClassifier:
    """Main attack classification engine"""
    
    def __init__(self):
        self.connection_tracker = {}  # Track connection patterns
        self.request_history = {}  # Track request history per IP
        self.time_window = 60  # Time window for pattern analysis (seconds)
        
        # Attack patterns and signatures
        self.modbus_functions = {
            0x01: "Read Coils",
            0x02: "Read Discrete Inputs", 
            0x03: "Read Holding Registers",
            0x04: "Read Input Registers",
            0x05: "Write Single Coil",
            0x06: "Write Single Register",
            0x0F: "Write Multiple Coils",
            0x10: "Write Multiple Registers"
        }
        
        # Suspicious command patterns
        self.malicious_patterns = {
            'sql_injection': [r'union\s+select', r'drop\s+table', r'insert\s+into'],
            'command_injection': [r'rm\s+-rf', r'wget\s+http', r'curl\s+http', r'nc\s+-'],
            'path_traversal': [r'\.\./', r'%2e%2e%2f', r'\.\.\\'],
            'xss': [r'<script>', r'javascript:', r'onerror='],
            'directory_listing': [r'ls\s+-la', r'dir\s+/s', r'find\s+/']
        }
        
        # Brute force indicators
        self.common_passwords = ['admin', 'password', '123456', 'root', 'test']
        self.common_usernames = ['admin', 'root', 'user', 'test', 'guest']
        
    def classify_attack(self, source_ip: str, service: str, payload: str = "", 
                       connection_info: Dict[str, Any] = None) -> AttackClassification:
        """
        Classify an attack based on multiple indicators
        """
        try:
            # Initialize connection info if not provided
            if connection_info is None:
                connection_info = {}
            
            # Track connection patterns
            self._update_connection_tracker(source_ip, service)
            
            # Analyze different aspects
            dos_score = self._analyze_dos_patterns(source_ip)
            scan_score = self._analyze_scan_patterns(source_ip, service)
            brute_force_score = self._analyze_brute_force_patterns(source_ip, payload)
            protocol_score = self._analyze_protocol_patterns(service, payload, connection_info)
            malware_score = self._analyze_malicious_payload(payload)
            
            # Service-specific analysis
            if service == "modbus":
                modbus_analysis = self._analyze_modbus_specific(payload, connection_info)
                return self._determine_modbus_attack_type(
                    dos_score, scan_score, protocol_score, modbus_analysis, 
                    source_ip, payload
                )
            
            # General attack type determination
            return self._determine_general_attack_type(
                dos_score, scan_score, brute_force_score, protocol_score, 
                malware_score, source_ip, service, payload
            )
            
        except Exception as e:
            logger.error(f"Error in attack classification: {e}")
            return AttackClassification(
                attack_type=AttackType.UNKNOWN_ATTACK,
                confidence=0.5,
                severity="medium",
                description="Classification failed due to error",
                indicators=["classification_error"],
                response_strategy="default"
            )
    
    def _update_connection_tracker(self, source_ip: str, service: str):
        """Update connection tracking data"""
        current_time = time.time()
        
        if source_ip not in self.connection_tracker:
            self.connection_tracker[source_ip] = {
                'first_seen': current_time,
                'last_seen': current_time,
                'connection_count': 0,
                'services': set(),
                'requests_per_minute': []
            }
        
        tracker = self.connection_tracker[source_ip]
        tracker['last_seen'] = current_time
        tracker['connection_count'] += 1
        tracker['services'].add(service)
        
        # Clean old request data
        tracker['requests_per_minute'] = [
            req_time for req_time in tracker['requests_per_minute']
            if current_time - req_time < self.time_window
        ]
        tracker['requests_per_minute'].append(current_time)
    
    def _analyze_dos_patterns(self, source_ip: str) -> float:
        """Analyze for DoS attack patterns"""
        if source_ip not in self.connection_tracker:
            return 0.0
        
        tracker = self.connection_tracker[source_ip]
        requests_per_minute = len(tracker['requests_per_minute'])
        
        # High request rate indicates potential DoS
        if requests_per_minute > 100:
            return 0.9
        elif requests_per_minute > 50:
            return 0.7
        elif requests_per_minute > 20:
            return 0.4
        else:
            return 0.1
    
    def _analyze_scan_patterns(self, source_ip: str, service: str) -> float:
        """Analyze for scanning attack patterns"""
        if source_ip not in self.connection_tracker:
            return 0.0
        
        tracker = self.connection_tracker[source_ip]
        service_count = len(tracker['services'])
        
        # Multiple services accessed indicates scanning
        if service_count > 5:
            return 0.9
        elif service_count > 3:
            return 0.6
        elif service_count > 1:
            return 0.3
        else:
            return 0.1
    
    def _analyze_brute_force_patterns(self, source_ip: str, payload: str) -> float:
        """Analyze for brute force attack patterns"""
        score = 0.0
        
        # Check for common passwords/usernames in payload
        payload_lower = payload.lower()
        for password in self.common_passwords:
            if password in payload_lower:
                score += 0.2
        for username in self.common_usernames:
            if username in payload_lower:
                score += 0.1
        
        # Check connection frequency (high frequency suggests brute force)
        if source_ip in self.connection_tracker:
            requests_count = len(self.connection_tracker[source_ip]['requests_per_minute'])
            if requests_count > 10:  # More than 10 attempts per minute
                score += 0.4
        
        return min(score, 1.0)
    
    def _analyze_protocol_patterns(self, service: str, payload: str, connection_info: Dict[str, Any]) -> float:
        """Analyze for protocol anomalies"""
        score = 0.0
        
        # Check for malformed protocol structures
        if service == "modbus":
            score += self._check_modbus_protocol_anomalies(payload)
        elif service == "http":
            score += self._check_http_protocol_anomalies(payload)
        elif service == "ssh":
            score += self._check_ssh_protocol_anomalies(payload)
        
        # Check for unusual connection patterns
        if connection_info.get('unexpected_disconnection'):
            score += 0.3
        if connection_info.get('invalid_handshake'):
            score += 0.5
            
        return min(score, 1.0)
    
    def _analyze_malicious_payload(self, payload: str) -> float:
        """Analyze payload for malicious content"""
        score = 0.0
        payload_lower = payload.lower()
        
        for pattern_type, patterns in self.malicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, payload_lower):
                    score += 0.3
                    break  # Only count once per pattern type
        
        return min(score, 1.0)
    
    def _analyze_modbus_specific(self, payload: str, connection_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Modbus-specific attack patterns"""
        analysis = {
            'flood_score': 0.0,
            'register_manipulation_score': 0.0,
            'function_codes': [],
            'register_access_pattern': 'normal'
        }
        
        # Analyze Modbus payload if available
        if payload:
            # Check for rapid-fire requests (flood attack)
            if connection_info.get('requests_per_second', 0) > 10:
                analysis['flood_score'] = 0.8
            
            # Check for register manipulation patterns
            if any(func in payload for func in ['05', '06', '0F', '10']):  # Write functions
                analysis['register_manipulation_score'] = 0.6
                analysis['register_access_pattern'] = 'write_heavy'
            
            # Extract function codes if possible
            analysis['function_codes'] = self._extract_modbus_functions(payload)
        
        return analysis
    
    def _extract_modbus_functions(self, payload: str) -> List[int]:
        """Extract Modbus function codes from payload"""
        functions = []
        try:
            # This is a simplified extraction - in reality, would need proper Modbus parsing
            for func_code in self.modbus_functions.keys():
                if f"{func_code:02X}" in payload.upper():
                    functions.append(func_code)
        except Exception:
            pass
        return functions
    
    def _check_modbus_protocol_anomalies(self, payload: str) -> float:
        """Check for Modbus protocol anomalies"""
        score = 0.0
        
        # Check for invalid function codes
        if payload and len(payload) > 2:
            try:
                # Simplified check - real implementation would parse MBAP header
                if any(invalid in payload.upper() for invalid in ['FF', '00']):
                    score += 0.3
            except Exception:
                pass
        
        return score
    
    def _check_http_protocol_anomalies(self, payload: str) -> float:
        """Check for HTTP protocol anomalies"""
        score = 0.0
        
        # Check for malformed HTTP requests
        if payload:
            if not re.match(r'^[A-Z]+ /', payload):
                score += 0.4
            if 'Content-Length: -' in payload:
                score += 0.5
        
        return score
    
    def _check_ssh_protocol_anomalies(self, payload: str) -> float:
        """Check for SSH protocol anomalies"""
        score = 0.0
        
        # Check for SSH-specific anomalies
        if payload:
            if not payload.startswith('SSH-'):
                score += 0.3
            if 'SSH-0.' in payload:  # Very old version
                score += 0.2
        
        return score
    
    def _determine_modbus_attack_type(self, dos_score: float, scan_score: float, 
                                    protocol_score: float, modbus_analysis: Dict[str, Any],
                                    source_ip: str, payload: str) -> AttackClassification:
        """Determine Modbus-specific attack type"""
        
        # Modbus flood attack
        if modbus_analysis['flood_score'] > 0.7 or dos_score > 0.7:
            return AttackClassification(
                attack_type=AttackType.MODBUS_FLOOD,
                confidence=max(modbus_analysis['flood_score'], dos_score),
                severity="high",
                description="Modbus flood attack detected - high frequency requests",
                indicators=[f"requests_per_second: {modbus_analysis.get('flood_score', 0)}", "rapid_requests"],
                response_strategy="rate_limit_and_delay"
            )
        
        # Register manipulation
        if modbus_analysis['register_manipulation_score'] > 0.5:
            return AttackClassification(
                attack_type=AttackType.REGISTER_MANIPULATION,
                confidence=modbus_analysis['register_manipulation_score'],
                severity="critical",
                description="Register manipulation attempt detected",
                indicators=["write_function_codes", modbus_analysis['register_access_pattern']],
                response_strategy="fake_success_with_monitoring"
            )
        
        # Protocol anomaly
        if protocol_score > 0.5:
            return AttackClassification(
                attack_type=AttackType.PROTOCOL_ANOMALY,
                confidence=protocol_score,
                severity="medium",
                description="Modbus protocol anomaly detected",
                indicators=["malformed_modbus_packet", "invalid_function_code"],
                response_strategy="error_response"
            )
        
        # Scanning
        if scan_score > 0.5:
            return AttackClassification(
                attack_type=AttackType.SCAN_ATTACK,
                confidence=scan_score,
                severity="low",
                description="Modbus service scanning detected",
                indicators=["multiple_service_probes", "port_scanning"],
                response_strategy="minimal_response"
            )
        
        # Normal traffic (default for Modbus)
        return AttackClassification(
            attack_type=AttackType.NORMAL_TRAFFIC,
            confidence=0.8,
            severity="info",
            description="Normal Modbus traffic",
            indicators=["valid_modbus_request"],
            response_strategy="normal_response"
        )
    
    def _determine_general_attack_type(self, dos_score: float, scan_score: float,
                                     brute_force_score: float, protocol_score: float,
                                     malware_score: float, source_ip: str, service: str,
                                     payload: str) -> AttackClassification:
        """Determine general attack type for non-Modbus services"""
        
        # DoS attack
        if dos_score > 0.7:
            return AttackClassification(
                attack_type=AttackType.DOS_ATTACK,
                confidence=dos_score,
                severity="high",
                description="Denial of Service attack detected",
                indicators=["high_request_rate", "resource_exhaustion"],
                response_strategy="rate_limit_and_block"
            )
        
        # Brute force attack
        if brute_force_score > 0.6:
            return AttackClassification(
                attack_type=AttackType.BRUTE_FORCE,
                confidence=brute_force_score,
                severity="medium",
                description="Brute force attack detected",
                indicators=["common_passwords", "repeated_login_attempts"],
                response_strategy="delay_and_fake_auth"
            )
        
        # Scanning attack
        if scan_score > 0.6:
            return AttackClassification(
                attack_type=AttackType.SCAN_ATTACK,
                confidence=scan_score,
                severity="low",
                description="Service scanning detected",
                indicators=["multiple_service_probes"],
                response_strategy="minimal_response"
            )
        
        # Protocol anomaly
        if protocol_score > 0.5:
            return AttackClassification(
                attack_type=AttackType.PROTOCOL_ANOMALY,
                confidence=protocol_score,
                severity="medium",
                description="Protocol anomaly detected",
                indicators=["malformed_packets", "invalid_protocol"],
                response_strategy="error_response"
            )
        
        # Malformed packet
        if malware_score > 0.5:
            return AttackClassification(
                attack_type=AttackType.MALFORMED_PACKET,
                confidence=malware_score,
                severity="medium",
                description="Malicious payload detected",
                indicators=["injection_attempts", "malicious_patterns"],
                response_strategy="sanitized_error_response"
            )
        
        # Unknown attack (suspicious but not clearly categorized)
        if any(score > 0.3 for score in [dos_score, scan_score, brute_force_score, protocol_score, malware_score]):
            return AttackClassification(
                attack_type=AttackType.UNKNOWN_ATTACK,
                confidence=0.4,
                severity="medium",
                description="Suspicious activity detected",
                indicators=["anomalous_behavior"],
                response_strategy="cautious_response"
            )
        
        # Normal traffic
        return AttackClassification(
            attack_type=AttackType.NORMAL_TRAFFIC,
            confidence=0.9,
            severity="info",
            description="Normal traffic",
            indicators=["benign_patterns"],
            response_strategy="normal_response"
        )
    
    def get_attack_statistics(self) -> Dict[str, Any]:
        """Get attack statistics"""
        stats = {
            'total_ips_tracked': len(self.connection_tracker),
            'active_connections': 0,
            'top_attackers': [],
            'attack_types_seen': {}
        }
        
        current_time = time.time()
        for ip, tracker in self.connection_tracker.items():
            if current_time - tracker['last_seen'] < 300:  # Active in last 5 minutes
                stats['active_connections'] += 1
        
        return stats


# Global classifier instance
attack_classifier = AttackClassifier()