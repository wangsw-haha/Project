"""
Simulated Attack Dataset Generator
Creates realistic attack data for testing the classification system
"""

import random
import time
import json
from typing import Dict, Any, List
from datetime import datetime, timedelta

from .attack_classifier import AttackType


class AttackDatasetGenerator:
    """Generates simulated attack datasets for testing"""
    
    def __init__(self):
        self.attack_patterns = {
            AttackType.NORMAL_TRAFFIC: self._generate_normal_traffic,
            AttackType.MODBUS_FLOOD: self._generate_modbus_flood,
            AttackType.REGISTER_MANIPULATION: self._generate_register_manipulation,
            AttackType.PROTOCOL_ANOMALY: self._generate_protocol_anomaly,
            AttackType.DOS_ATTACK: self._generate_dos_attack,
            AttackType.MITM_ATTACK: self._generate_mitm_attack,
            AttackType.SCAN_ATTACK: self._generate_scan_attack,
            AttackType.BRUTE_FORCE: self._generate_brute_force,
            AttackType.MALFORMED_PACKET: self._generate_malformed_packet,
            AttackType.UNKNOWN_ATTACK: self._generate_unknown_attack
        }
        
        # Common IP ranges for attackers
        self.attacker_ips = [
            "192.168.1.100", "10.0.0.50", "172.16.0.200",
            "203.0.113.15", "198.51.100.25", "45.32.123.45",
            "185.199.108.153", "104.16.249.249", "8.8.8.8"
        ]
        
        # Legitimate IP ranges  
        self.legitimate_ips = [
            "192.168.1.10", "192.168.1.20", "10.0.0.5",
            "172.16.0.10", "192.168.0.100"
        ]
        
        # Common usernames and passwords for brute force
        self.common_usernames = ['admin', 'root', 'user', 'test', 'guest', 'operator', 'supervisor']
        self.common_passwords = ['admin', 'password', '123456', 'root', 'test', 'qwerty', 'admin123']
        
        # Modbus function codes
        self.modbus_functions = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10]
        
        # Services
        self.services = ['modbus', 'ssh', 'http', 'ftp', 'telnet']
    
    def generate_dataset(self, num_samples: int = 1000) -> List[Dict[str, Any]]:
        """Generate a complete dataset with all attack types"""
        dataset = []
        
        # Distribution of attack types (percentages)
        attack_distribution = {
            AttackType.NORMAL_TRAFFIC: 0.4,  # 40% normal traffic
            AttackType.SCAN_ATTACK: 0.15,    # 15% scanning
            AttackType.BRUTE_FORCE: 0.12,    # 12% brute force
            AttackType.MODBUS_FLOOD: 0.08,   # 8% modbus flood
            AttackType.DOS_ATTACK: 0.06,     # 6% dos
            AttackType.PROTOCOL_ANOMALY: 0.05, # 5% protocol anomaly
            AttackType.REGISTER_MANIPULATION: 0.04, # 4% register manipulation
            AttackType.MALFORMED_PACKET: 0.04, # 4% malformed packets
            AttackType.MITM_ATTACK: 0.03,    # 3% mitm
            AttackType.UNKNOWN_ATTACK: 0.03  # 3% unknown
        }
        
        for attack_type, percentage in attack_distribution.items():
            count = int(num_samples * percentage)
            for _ in range(count):
                sample = self.attack_patterns[attack_type]()
                sample['true_label'] = attack_type.value
                sample['timestamp'] = self._generate_timestamp()
                dataset.append(sample)
        
        # Shuffle dataset
        random.shuffle(dataset)
        return dataset
    
    def save_dataset(self, dataset: List[Dict[str, Any]], filename: str):
        """Save dataset to JSON file"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(dataset, f, indent=2, default=str, ensure_ascii=False)
    
    def _generate_timestamp(self) -> str:
        """Generate realistic timestamp"""
        base_time = datetime.now()
        random_offset = timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        return (base_time - random_offset).isoformat()
    
    # Attack pattern generators
    def _generate_normal_traffic(self) -> Dict[str, Any]:
        """Generate normal traffic patterns"""
        service = random.choice(self.services)
        source_ip = random.choice(self.legitimate_ips)
        
        patterns = {
            'modbus': {
                'source_ip': source_ip,
                'service': 'modbus',
                'payload': f"Function: {random.choice([0x01, 0x03, 0x04])}, Address: {random.randint(0, 100)}",
                'connection_info': {
                    'requests_per_second': random.uniform(0.1, 2.0),
                    'valid_handshake': True
                }
            },
            'ssh': {
                'source_ip': source_ip,
                'service': 'ssh',
                'payload': random.choice(['ls', 'pwd', 'whoami', 'ps aux']),
                'connection_info': {
                    'authenticated': True,
                    'session_duration': random.randint(300, 3600)
                }
            },
            'http': {
                'source_ip': source_ip,
                'service': 'http',
                'payload': f"GET / HTTP/1.1\r\nHost: {source_ip}\r\nUser-Agent: Mozilla/5.0",
                'connection_info': {
                    'method': 'GET',
                    'status_code': 200
                }
            }
        }
        
        return patterns.get(service, patterns['modbus'])
    
    def _generate_modbus_flood(self) -> Dict[str, Any]:
        """Generate Modbus flood attack patterns"""
        return {
            'source_ip': random.choice(self.attacker_ips),
            'service': 'modbus',
            'payload': f"Function: {random.choice(self.modbus_functions)}, Rapid requests",
            'connection_info': {
                'requests_per_second': random.uniform(20, 100),
                'burst_pattern': True,
                'connection_count': random.randint(50, 200)
            }
        }
    
    def _generate_register_manipulation(self) -> Dict[str, Any]:
        """Generate register manipulation patterns"""
        write_functions = [0x05, 0x06, 0x0F, 0x10]
        return {
            'source_ip': random.choice(self.attacker_ips),
            'service': 'modbus',
            'payload': f"Write Function: {random.choice(write_functions)}, Address: {random.randint(0, 100)}, Value: {random.randint(0, 65535)}",
            'connection_info': {
                'function_code': random.choice(write_functions),
                'write_attempts': random.randint(5, 50),
                'suspicious_values': True
            }
        }
    
    def _generate_protocol_anomaly(self) -> Dict[str, Any]:
        """Generate protocol anomaly patterns"""
        service = random.choice(['modbus', 'ssh', 'http'])
        
        patterns = {
            'modbus': {
                'source_ip': random.choice(self.attacker_ips),
                'service': 'modbus',
                'payload': f"Invalid Function: 0xFF, Malformed Header",
                'connection_info': {
                    'invalid_mbap': True,
                    'malformed_pdu': True
                }
            },
            'ssh': {
                'source_ip': random.choice(self.attacker_ips),
                'service': 'ssh',
                'payload': "SSH-0.5-InvalidVersion",
                'connection_info': {
                    'invalid_version': True,
                    'protocol_error': True
                }
            },
            'http': {
                'source_ip': random.choice(self.attacker_ips),
                'service': 'http',
                'payload': "INVALID_METHOD /test HTTP/1.1\r\nContent-Length: -1",
                'connection_info': {
                    'invalid_method': True,
                    'malformed_headers': True
                }
            }
        }
        
        return patterns[service]
    
    def _generate_dos_attack(self) -> Dict[str, Any]:
        """Generate DoS attack patterns"""
        service = random.choice(self.services)
        return {
            'source_ip': random.choice(self.attacker_ips),
            'service': service,
            'payload': f"High frequency requests to {service}",
            'connection_info': {
                'requests_per_minute': random.randint(200, 1000),
                'connection_flooding': True,
                'resource_exhaustion': True
            }
        }
    
    def _generate_mitm_attack(self) -> Dict[str, Any]:
        """Generate MITM attack patterns"""
        return {
            'source_ip': random.choice(self.attacker_ips),
            'service': random.choice(['ssh', 'http']),
            'payload': "Certificate mismatch or invalid SSL handshake",
            'connection_info': {
                'certificate_mismatch': True,
                'ssl_anomaly': True,
                'proxy_detected': True
            }
        }
    
    def _generate_scan_attack(self) -> Dict[str, Any]:
        """Generate scanning attack patterns"""
        return {
            'source_ip': random.choice(self.attacker_ips),
            'service': random.choice(self.services),
            'payload': f"Port scan probe",
            'connection_info': {
                'multiple_services': True,
                'service_count': random.randint(5, 20),
                'rapid_connections': True,
                'port_scanning': True
            }
        }
    
    def _generate_brute_force(self) -> Dict[str, Any]:
        """Generate brute force attack patterns"""
        service = random.choice(['ssh', 'ftp', 'telnet'])
        username = random.choice(self.common_usernames)
        password = random.choice(self.common_passwords)
        
        return {
            'source_ip': random.choice(self.attacker_ips),
            'service': service,
            'payload': f"Login attempt: {username}:{password}",
            'connection_info': {
                'username': username,
                'password': password,
                'auth_attempts': random.randint(10, 100),
                'dictionary_attack': True
            }
        }
    
    def _generate_malformed_packet(self) -> Dict[str, Any]:
        """Generate malformed packet patterns"""
        service = random.choice(self.services)
        malformed_payloads = [
            "Buffer overflow attempt: " + "A" * 1000,
            "SQL injection: ' OR 1=1 --",
            "Command injection: ; rm -rf /",
            "XSS attempt: <script>alert('xss')</script>",
            "Path traversal: ../../etc/passwd"
        ]
        
        return {
            'source_ip': random.choice(self.attacker_ips),
            'service': service,
            'payload': random.choice(malformed_payloads),
            'connection_info': {
                'malicious_payload': True,
                'injection_attempt': True,
                'payload_size_anomaly': True
            }
        }
    
    def _generate_unknown_attack(self) -> Dict[str, Any]:
        """Generate unknown/novel attack patterns"""
        return {
            'source_ip': random.choice(self.attacker_ips),
            'service': random.choice(self.services),
            'payload': f"Unknown pattern: {random.randint(1000, 9999)}",
            'connection_info': {
                'anomalous_behavior': True,
                'unknown_signature': True,
                'suspicious_timing': True,
                'novel_attack_vector': True
            }
        }


# Example usage and dataset generation
if __name__ == "__main__":
    generator = AttackDatasetGenerator()
    
    # Generate training dataset
    training_data = generator.generate_dataset(2000)
    generator.save_dataset(training_data, '/tmp/attack_dataset_training.json')
    
    # Generate testing dataset
    testing_data = generator.generate_dataset(500)
    generator.save_dataset(testing_data, '/tmp/attack_dataset_testing.json')
    
    print(f"Generated {len(training_data)} training samples")
    print(f"Generated {len(testing_data)} testing samples")
    
    # Show sample distribution
    from collections import Counter
    labels = [sample['true_label'] for sample in training_data]
    distribution = Counter(labels)
    
    print("\nTraining dataset distribution:")
    for label, count in distribution.items():
        percentage = (count / len(training_data)) * 100
        print(f"  {label}: {count} samples ({percentage:.1f}%)")