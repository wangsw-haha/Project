"""
Advanced Feature Extraction for Industrial IoT Honeypot Attack Classification
Extracts comprehensive features from network traffic and protocol data for ML training
"""

import re
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime
from collections import Counter
from loguru import logger
import hashlib


class FeatureExtractor:
    """Advanced feature extraction for attack classification"""
    
    def __init__(self):
        """Initialize feature extractor with protocol-specific patterns"""
        
        # Modbus function codes mapping
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
        
        # Suspicious patterns for different protocols
        self.malicious_patterns = {
            'sql_injection': [
                r'union\s+select', r'drop\s+table', r'insert\s+into',
                r'delete\s+from', r'update\s+set', r'exec\s*\('
            ],
            'command_injection': [
                r';\s*rm\s+', r';\s*cat\s+', r';\s*ls\s+',
                r'`[^`]*`', r'\$\([^)]*\)', r'&&\s*rm'
            ],
            'xss_patterns': [
                r'<script[^>]*>', r'javascript:', r'on\w+\s*=',
                r'<iframe[^>]*>', r'eval\s*\(', r'alert\s*\('
            ],
            'directory_traversal': [
                r'\.\./', r'\.\.\\', r'%2e%2e%2f',
                r'%2e%2e\\', r'\.\.%2f', r'\.\.%5c'
            ]
        }
        
        # Protocol-specific suspicious commands
        self.suspicious_commands = {
            'ssh': [
                'whoami', 'id', 'uname', 'ps', 'netstat', 'ifconfig',
                'cat /etc/passwd', 'cat /etc/shadow', 'sudo su',
                'chmod 777', 'wget', 'curl', 'nc', 'python'
            ],
            'http': [
                'admin', 'wp-admin', 'phpmyadmin', 'config.php',
                'shell.php', 'cmd.php', '.htaccess', 'robots.txt'
            ]
        }
        
        # Common attack signatures
        self.attack_signatures = {
            'brute_force': ['failed', 'invalid', 'incorrect', 'denied'],
            'scan': ['404', '403', '500', 'not found', 'forbidden'],
            'dos': ['timeout', 'connection refused', 'resource exhausted']
        }
    
    def extract_features(self, dataset: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Extract comprehensive features from attack dataset
        
        Args:
            dataset: List of attack samples with metadata
            
        Returns:
            Tuple of (features, labels, feature_names)
        """
        logger.info(f"Extracting features from {len(dataset)} samples")
        
        features = []
        labels = []
        
        for sample in dataset:
            feature_vector = self._extract_sample_features(sample)
            features.append(feature_vector)
            labels.append(sample['true_label'])
        
        feature_names = self._get_feature_names()
        
        # Convert to numpy arrays with proper shape handling
        if features:
            # Ensure all feature vectors have the same length
            max_length = max(len(f) for f in features)
            padded_features = []
            for f in features:
                if len(f) < max_length:
                    # Pad with zeros if feature vector is shorter
                    padded_f = f + [0.0] * (max_length - len(f))
                else:
                    padded_f = f[:max_length]  # Truncate if longer
                padded_features.append(padded_f)
            
            features_array = np.array(padded_features, dtype=np.float32)
        else:
            features_array = np.array([])
        
        labels_array = np.array(labels)
        
        logger.info(f"Extracted {features_array.shape[1] if len(features_array.shape) > 1 else 0} features from {len(features_array)} samples")
        logger.info(f"Feature dimensions: {features_array.shape}")
        
        return features_array, labels_array, feature_names
    
    def _extract_sample_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract features from a single sample"""
        
        features = []
        
        # Basic metadata features
        features.extend(self._extract_basic_features(sample))
        
        # Protocol-specific features
        features.extend(self._extract_protocol_features(sample))
        
        # Payload analysis features
        features.extend(self._extract_payload_features(sample))
        
        # Connection pattern features
        features.extend(self._extract_connection_features(sample))
        
        # Temporal features
        features.extend(self._extract_temporal_features(sample))
        
        # Statistical features
        features.extend(self._extract_statistical_features(sample))
        
        return features
    
    def _extract_basic_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract basic metadata features"""
        features = []
        
        # IP address features
        source_ip = sample.get('source_ip', '')
        features.extend(self._extract_ip_features(source_ip))
        
        # Service type (one-hot encoded)
        service = sample.get('service', 'unknown')
        services = ['ssh', 'http', 'modbus', 'ftp', 'telnet']
        for s in services:
            features.append(1.0 if service == s else 0.0)
        
        # Payload length
        payload = sample.get('payload', '')
        features.append(float(len(payload)))
        
        return features
    
    def _extract_ip_features(self, ip: str) -> List[float]:
        """Extract features from IP address"""
        features = []
        
        # IP class features
        if ip:
            octets = ip.split('.')
            if len(octets) == 4:
                try:
                    first_octet = int(octets[0])
                    # Class A (1-126)
                    features.append(1.0 if 1 <= first_octet <= 126 else 0.0)
                    # Class B (128-191)  
                    features.append(1.0 if 128 <= first_octet <= 191 else 0.0)
                    # Class C (192-223)
                    features.append(1.0 if 192 <= first_octet <= 223 else 0.0)
                    # Private ranges
                    features.append(1.0 if first_octet in [10, 172, 192] else 0.0)
                except ValueError:
                    features.extend([0.0, 0.0, 0.0, 0.0])
            else:
                features.extend([0.0, 0.0, 0.0, 0.0])
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])
        
        return features
    
    def _extract_protocol_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract protocol-specific features"""
        features = []
        service = sample.get('service', '')
        payload = sample.get('payload', '')
        
        if service == 'modbus':
            features.extend(self._extract_modbus_features(payload))
        elif service == 'ssh':
            features.extend(self._extract_ssh_features(payload))
        elif service == 'http':
            features.extend(self._extract_http_features(payload))
        else:
            # Generic protocol features
            features.extend(self._extract_generic_protocol_features(payload))
        
        return features
    
    def _extract_modbus_features(self, payload: str) -> List[float]:
        """Extract Modbus-specific features"""
        features = []
        
        # Function code detection
        for func_code in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10]:
            features.append(1.0 if f"Function: {func_code}" in payload else 0.0)
        
        # Write operation detection
        write_functions = [0x05, 0x06, 0x0F, 0x10]
        has_write = any(f"Function: {func}" in payload for func in write_functions)
        features.append(1.0 if has_write else 0.0)
        
        # Address range analysis
        address_match = re.search(r'Address: (\d+)', payload)
        if address_match:
            address = int(address_match.group(1))
            # Suspicious address ranges
            features.append(1.0 if address > 10000 else 0.0)  # High addresses
            features.append(1.0 if address == 0 else 0.0)      # Zero address
        else:
            features.extend([0.0, 0.0])
        
        # Value analysis for write operations
        value_match = re.search(r'Value: (\d+)', payload)
        if value_match:
            value = int(value_match.group(1))
            # Suspicious values
            features.append(1.0 if value > 65535 else 0.0)  # Out of range
            features.append(1.0 if value == 0xFFFF else 0.0)  # Max value
        else:
            features.extend([0.0, 0.0])
        
        return features
    
    def _extract_ssh_features(self, payload: str) -> List[float]:
        """Extract SSH-specific features"""
        features = []
        
        # Command pattern analysis
        for cmd in self.suspicious_commands['ssh']:
            features.append(1.0 if cmd.lower() in payload.lower() else 0.0)
        
        # Pad to consistent length (12 features)
        while len(features) < 12:
            features.append(0.0)
        
        return features[:12]
    
    def _extract_http_features(self, payload: str) -> List[float]:
        """Extract HTTP-specific features"""
        features = []
        
        # HTTP method detection
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        for method in methods:
            features.append(1.0 if method in payload else 0.0)
        
        # Suspicious URL patterns
        for pattern in self.suspicious_commands['http']:
            features.append(1.0 if pattern.lower() in payload.lower() else 0.0)
        
        # Pad to consistent length (12 features)
        while len(features) < 12:
            features.append(0.0)
        
        return features[:12]
    
    def _extract_generic_protocol_features(self, payload: str) -> List[float]:
        """Extract generic protocol features for unknown services"""
        return [0.0] * 12  # Consistent with other protocol features
    
    def _extract_payload_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract features from payload content"""
        features = []
        payload = sample.get('payload', '')
        
        # String analysis
        features.append(float(len(payload)))  # Payload length
        features.append(float(payload.count(' ')) / max(len(payload), 1))  # Space ratio
        features.append(float(len(set(payload))) / max(len(payload), 1))  # Character diversity
        
        # Malicious pattern detection
        pattern_matches = 0
        for category, patterns in self.malicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    pattern_matches += 1
        features.append(float(pattern_matches))
        
        # Entropy calculation
        features.append(self._calculate_entropy(payload))
        
        # Binary/ASCII ratio
        ascii_chars = sum(1 for c in payload if 32 <= ord(c) <= 126)
        features.append(ascii_chars / max(len(payload), 1))
        
        return features
    
    def _extract_connection_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract connection pattern features"""
        features = []
        connection_info = sample.get('connection_info', {})
        
        # Request frequency
        rpm = connection_info.get('requests_per_minute', 0)
        features.append(float(rpm))
        features.append(1.0 if rpm > 100 else 0.0)  # High frequency indicator
        
        # Connection flags
        features.append(1.0 if connection_info.get('connection_flooding', False) else 0.0)
        features.append(1.0 if connection_info.get('resource_exhaustion', False) else 0.0)
        features.append(1.0 if connection_info.get('certificate_mismatch', False) else 0.0)
        features.append(1.0 if connection_info.get('ssl_anomaly', False) else 0.0)
        features.append(1.0 if connection_info.get('proxy_detected', False) else 0.0)
        
        return features
    
    def _extract_temporal_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract temporal features"""
        features = []
        
        timestamp_str = sample.get('timestamp', '')
        if timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                
                # Hour of day (0-23)
                features.append(float(timestamp.hour))
                # Day of week (0-6)
                features.append(float(timestamp.weekday()))
                # Weekend indicator
                features.append(1.0 if timestamp.weekday() >= 5 else 0.0)
                # Night time indicator (22:00 - 06:00)
                features.append(1.0 if timestamp.hour >= 22 or timestamp.hour <= 6 else 0.0)
                
            except ValueError:
                features.extend([0.0, 0.0, 0.0, 0.0])
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])
        
        return features
    
    def _extract_statistical_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract statistical features"""
        features = []
        payload = sample.get('payload', '')
        
        # Character frequency analysis
        if payload:
            char_counts = Counter(payload.lower())
            most_common = char_counts.most_common(3)
            
            # Top 3 character frequencies
            for i in range(3):
                if i < len(most_common):
                    features.append(float(most_common[i][1]) / len(payload))
                else:
                    features.append(0.0)
            
            # Digit ratio
            digit_count = sum(1 for c in payload if c.isdigit())
            features.append(digit_count / max(len(payload), 1))
            
            # Uppercase ratio
            upper_count = sum(1 for c in payload if c.isupper())
            features.append(upper_count / max(len(payload), 1))
            
        else:
            features.extend([0.0, 0.0, 0.0, 0.0, 0.0])
        
        return features
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string"""
        if not data:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _get_feature_names(self) -> List[str]:
        """Get names of all extracted features"""
        names = []
        
        # Basic features
        names.extend(['ip_class_a', 'ip_class_b', 'ip_class_c', 'ip_private'])
        names.extend(['service_ssh', 'service_http', 'service_modbus', 'service_ftp', 'service_telnet'])
        names.append('payload_length')
        
        # Protocol features (12 features for each)
        names.extend([f'protocol_feature_{i}' for i in range(12)])
        
        # Payload features
        names.extend(['payload_len', 'space_ratio', 'char_diversity', 'pattern_matches', 'entropy', 'ascii_ratio'])
        
        # Connection features
        names.extend(['requests_per_minute', 'high_frequency', 'flooding', 'resource_exhaustion', 
                     'cert_mismatch', 'ssl_anomaly', 'proxy_detected'])
        
        # Temporal features
        names.extend(['hour_of_day', 'day_of_week', 'is_weekend', 'is_night'])
        
        # Statistical features
        names.extend(['top_char_freq_1', 'top_char_freq_2', 'top_char_freq_3', 'digit_ratio', 'upper_ratio'])
        
        return names
    
    def extract_single_sample_features(self, sample: Dict[str, Any]) -> np.ndarray:
        """Extract features from a single sample for real-time classification"""
        feature_vector = self._extract_sample_features(sample)
        return np.array(feature_vector).reshape(1, -1)
    
    def get_feature_importance_names(self) -> Dict[str, str]:
        """Get feature names with descriptions for interpretability"""
        return {
            'payload_length': 'Length of attack payload',
            'requests_per_minute': 'Request frequency (attacks/minute)',
            'entropy': 'Shannon entropy of payload',
            'pattern_matches': 'Number of malicious patterns detected',
            'high_frequency': 'High frequency attack indicator',
            'char_diversity': 'Character diversity in payload',
            'protocol_feature_0': 'Protocol-specific feature 1',
            'is_night': 'Night time attack indicator',
            'flooding': 'Connection flooding indicator',
            'ascii_ratio': 'ASCII character ratio in payload'
        }