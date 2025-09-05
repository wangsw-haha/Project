"""
Dynamic Response Generator
Generates contextual responses based on attack classification
"""

import random
import time
import asyncio
from typing import Dict, Any, List, Optional
from loguru import logger

from .attack_classifier import AttackType, AttackClassification


class DynamicResponseGenerator:
    """Generates dynamic responses based on attack classification"""
    
    def __init__(self):
        # Response templates for different attack types
        self.response_templates = {
            AttackType.NORMAL_TRAFFIC: {
                'modbus': self._normal_modbus_responses,
                'ssh': self._normal_ssh_responses,
                'http': self._normal_http_responses,
                'default': self._normal_default_responses
            },
            AttackType.MODBUS_FLOOD: {
                'modbus': self._modbus_flood_responses,
                'default': self._dos_responses
            },
            AttackType.REGISTER_MANIPULATION: {
                'modbus': self._register_manipulation_responses,
                'default': self._malicious_responses
            },
            AttackType.PROTOCOL_ANOMALY: {
                'modbus': self._protocol_anomaly_responses,
                'ssh': self._protocol_error_responses,
                'http': self._http_error_responses,
                'default': self._protocol_error_responses
            },
            AttackType.DOS_ATTACK: {
                'default': self._dos_responses
            },
            AttackType.MITM_ATTACK: {
                'default': self._mitm_responses
            },
            AttackType.SCAN_ATTACK: {
                'default': self._scan_responses
            },
            AttackType.BRUTE_FORCE: {
                'ssh': self._brute_force_ssh_responses,
                'default': self._brute_force_responses
            },
            AttackType.MALFORMED_PACKET: {
                'default': self._malformed_packet_responses
            },
            AttackType.UNKNOWN_ATTACK: {
                'default': self._unknown_attack_responses
            }
        }
        
        # Response delays for different strategies
        self.response_delays = {
            'immediate': 0,
            'short_delay': random.uniform(0.5, 2.0),
            'medium_delay': random.uniform(2.0, 5.0),
            'long_delay': random.uniform(5.0, 10.0),
            'progressive_delay': 1.0  # Will be multiplied by attempt number
        }
        
        # Track attack patterns for progressive responses
        self.attack_history = {}
    
    async def generate_response(self, classification: AttackClassification, 
                              service: str, payload: str = "", 
                              source_ip: str = "", **context) -> Dict[str, Any]:
        """
        Generate a dynamic response based on attack classification
        """
        try:
            # Get appropriate response template
            attack_templates = self.response_templates.get(classification.attack_type, {})
            response_func = attack_templates.get(service, attack_templates.get('default', self._default_response))
            
            # Update attack history for progressive responses
            self._update_attack_history(source_ip, classification.attack_type)
            
            # Generate base response
            response = response_func(classification, payload, source_ip, **context)
            
            # Apply response strategy modifications
            response = await self._apply_response_strategy(response, classification, source_ip)
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating dynamic response: {e}")
            return self._default_response(classification, payload, source_ip, **context)
    
    def _update_attack_history(self, source_ip: str, attack_type: AttackType):
        """Update attack history for progressive responses"""
        if source_ip not in self.attack_history:
            self.attack_history[source_ip] = {}
        
        if attack_type.value not in self.attack_history[source_ip]:
            self.attack_history[source_ip][attack_type.value] = {
                'count': 0,
                'first_seen': time.time(),
                'last_seen': time.time()
            }
        
        history = self.attack_history[source_ip][attack_type.value]
        history['count'] += 1
        history['last_seen'] = time.time()
    
    async def _apply_response_strategy(self, response: Dict[str, Any], 
                                     classification: AttackClassification,
                                     source_ip: str) -> Dict[str, Any]:
        """Apply response strategy modifications"""
        strategy = classification.response_strategy
        
        if strategy == "rate_limit_and_delay":
            # Progressive delay based on attack frequency
            attack_count = self._get_attack_count(source_ip, classification.attack_type)
            delay = min(attack_count * 2, 30)  # Max 30 seconds delay
            await asyncio.sleep(delay)
            response['delay_applied'] = delay
            
        elif strategy == "rate_limit_and_block":
            # Simulate temporary blocking
            response['blocked'] = True
            response['message'] = "Connection temporarily blocked due to suspicious activity"
            await asyncio.sleep(10)
            
        elif strategy == "delay_and_fake_auth":
            # Progressive authentication delay
            attempt_count = self._get_attack_count(source_ip, classification.attack_type)
            delay = min(attempt_count ** 2, 60)  # Exponential backoff, max 60 seconds
            await asyncio.sleep(delay)
            response['auth_delay'] = delay
            
        elif strategy == "minimal_response":
            # Provide minimal information
            response['content'] = response.get('content', '')[:50] + "..." if len(response.get('content', '')) > 50 else response.get('content', '')
            
        elif strategy == "fake_success_with_monitoring":
            # Pretend success but log extensively
            response['success'] = True
            response['monitored'] = True
            logger.warning(f"Fake success response sent to {source_ip} for {classification.attack_type.value}")
        
        return response
    
    def _get_attack_count(self, source_ip: str, attack_type: AttackType) -> int:
        """Get attack count for progressive responses"""
        if source_ip in self.attack_history and attack_type.value in self.attack_history[source_ip]:
            return self.attack_history[source_ip][attack_type.value]['count']
        return 0
    
    # Normal traffic responses
    def _normal_modbus_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Normal Modbus responses"""
        responses = [
            {
                'type': 'modbus_response',
                'function_code': 0x03,  # Read Holding Registers
                'data': [100, 200, 150, 75],  # Fake sensor data
                'unit_id': 1,
                'content': 'Successfully read 4 registers',
                'status': 'success'
            },
            {
                'type': 'modbus_response', 
                'function_code': 0x01,  # Read Coils
                'data': [True, False, True, False],
                'unit_id': 1,
                'content': 'Coil status retrieved',
                'status': 'success'
            }
        ]
        return random.choice(responses)
    
    def _normal_ssh_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Normal SSH responses"""
        commands = {
            'ls': 'documents\ndownloads\npictures\nmusic\n',
            'pwd': '/home/user\n',
            'whoami': 'user\n',
            'uname': 'Linux ubuntu 5.4.0-74-generic #83-Ubuntu x86_64\n',
            'ps': 'PID TTY          TIME CMD\n 1234 pts/0    00:00:01 bash\n'
        }
        
        command = payload.strip().lower()
        content = commands.get(command, f"{command}: command not found\n")
        
        return {
            'type': 'ssh_response',
            'content': content,
            'status': 'success',
            'exit_code': 0 if command in commands else 127
        }
    
    def _normal_http_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Normal HTTP responses"""
        responses = [
            {
                'type': 'http_response',
                'status_code': 200,
                'headers': {'Content-Type': 'text/html', 'Server': 'Apache/2.4.41'},
                'content': '<html><body><h1>Industrial Control Panel</h1><p>System Status: Online</p></body></html>',
                'status': 'success'
            },
            {
                'type': 'http_response',
                'status_code': 404,
                'headers': {'Content-Type': 'text/html', 'Server': 'Apache/2.4.41'},
                'content': '<html><body><h1>404 Not Found</h1></body></html>',
                'status': 'not_found'
            }
        ]
        return random.choice(responses)
    
    def _normal_default_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Normal default responses"""
        return {
            'type': 'generic_response',
            'content': 'Service ready',
            'status': 'success'
        }
    
    # Attack-specific responses
    def _modbus_flood_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Responses for Modbus flood attacks"""
        responses = [
            {
                'type': 'modbus_error',
                'error_code': 0x06,  # Server Device Busy
                'content': 'Device busy, please retry later',
                'delay': True,
                'status': 'rate_limited'
            },
            {
                'type': 'modbus_error',
                'error_code': 0x0A,  # Gateway Target Device Failed to Respond
                'content': 'Gateway timeout',
                'status': 'timeout'
            }
        ]
        return random.choice(responses)
    
    def _register_manipulation_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Responses for register manipulation attempts"""
        # Fake successful write but log extensively
        return {
            'type': 'modbus_response',
            'function_code': 0x06,  # Write Single Register
            'register_address': random.randint(0, 100),
            'value': random.randint(0, 1000),
            'content': 'Register write successful',
            'status': 'fake_success',
            'monitored': True
        }
    
    def _protocol_anomaly_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Responses for protocol anomalies"""
        return {
            'type': 'modbus_error',
            'error_code': 0x01,  # Illegal Function
            'content': 'Illegal function code',
            'status': 'protocol_error'
        }
    
    def _dos_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Responses for DoS attacks"""
        return {
            'type': 'rate_limit_response',
            'content': 'Rate limit exceeded',
            'retry_after': 60,
            'status': 'rate_limited'
        }
    
    def _mitm_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Responses for MITM attacks"""
        return {
            'type': 'security_response',
            'content': 'Certificate validation failed',
            'status': 'security_error'
        }
    
    def _scan_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Responses for scanning attacks"""
        # Provide minimal information
        return {
            'type': 'minimal_response',
            'content': 'Service available',
            'status': 'minimal'
        }
    
    def _brute_force_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Responses for brute force attacks"""
        return {
            'type': 'auth_response',
            'content': 'Authentication failed',
            'attempts_remaining': max(0, 3 - self._get_attack_count(source_ip, classification.attack_type)),
            'status': 'auth_failed'
        }
    
    def _brute_force_ssh_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """SSH-specific brute force responses"""
        return {
            'type': 'ssh_auth_response',
            'content': 'Permission denied (publickey,password)',
            'banner': 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
            'status': 'auth_failed'
        }
    
    def _malformed_packet_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Responses for malformed packets"""
        return {
            'type': 'protocol_error',
            'content': 'Bad request format',
            'status': 'malformed'
        }
    
    def _unknown_attack_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Responses for unknown attacks"""
        return {
            'type': 'cautious_response',
            'content': 'Request processed',
            'status': 'monitored'
        }
    
    def _protocol_error_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Generic protocol error responses"""
        return {
            'type': 'protocol_error',
            'content': 'Protocol error',
            'status': 'error'
        }
    
    def _http_error_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """HTTP protocol error responses"""
        return {
            'type': 'http_response',
            'status_code': 400,
            'headers': {'Content-Type': 'text/html'},
            'content': '<html><body><h1>400 Bad Request</h1></body></html>',
            'status': 'bad_request'
        }
    
    def _malicious_responses(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Responses for malicious activity"""
        return {
            'type': 'security_response',
            'content': 'Access denied',
            'status': 'blocked'
        }
    
    def _default_response(self, classification: AttackClassification, payload: str, source_ip: str, **context) -> Dict[str, Any]:
        """Default fallback response"""
        return {
            'type': 'default_response',
            'content': 'Service unavailable',
            'status': 'default'
        }
    
    def get_response_statistics(self) -> Dict[str, Any]:
        """Get response generation statistics"""
        return {
            'total_ips_tracked': len(self.attack_history),
            'attack_types_seen': list(set(
                attack_type for ip_attacks in self.attack_history.values() 
                for attack_type in ip_attacks.keys()
            )),
            'total_attacks_handled': sum(
                sum(attack_data['count'] for attack_data in ip_attacks.values())
                for ip_attacks in self.attack_history.values()
            )
        }


# Global response generator instance
response_generator = DynamicResponseGenerator()