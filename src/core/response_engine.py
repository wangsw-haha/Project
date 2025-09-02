"""
Dynamic response engine for generating intelligent responses to attacks.
"""

import asyncio
import random
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime


class ResponseEngine:
    """Engine for generating dynamic responses to attacks."""
    
    def __init__(self, config, llm_client=None):
        self.config = config
        self.llm_client = llm_client
        self.logger = logging.getLogger('honeypot.response')
        
        # Response cache to avoid repetitive LLM calls
        self.response_cache = {}
        self.cache_timeout = 3600  # 1 hour
        
    async def generate_response(self, attack_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a response based on attack information."""
        attack_type = attack_info.get('type', 'unknown')
        response_mode = self.config.get('honeypot.response.mode', 'dynamic')
        
        try:
            if response_mode == 'dynamic' and self.llm_client:
                response = await self._generate_llm_response(attack_info)
            else:
                response = self._generate_static_response(attack_info)
                
            # Add response metadata
            response.update({
                'timestamp': datetime.utcnow().isoformat(),
                'attack_type': attack_type,
                'source_ip': attack_info.get('source_ip'),
                'llm_generated': response_mode == 'dynamic' and self.llm_client is not None
            })
            
            # Apply configured delay
            await self._apply_response_delay(attack_type)
            
            return response
            
        except Exception as e:
            self.logger.error(f"Failed to generate response: {e}")
            return self._get_fallback_response(attack_info)
            
    async def _generate_llm_response(self, attack_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate response using LLM."""
        attack_type = attack_info.get('type', 'unknown')
        cache_key = f"{attack_type}_{hash(str(attack_info.get('payload', '')))}"
        
        # Check cache first
        if cache_key in self.response_cache:
            cached_response, timestamp = self.response_cache[cache_key]
            if (datetime.utcnow() - timestamp).seconds < self.cache_timeout:
                self.logger.debug(f"Using cached response for {attack_type}")
                return cached_response
                
        # Generate new response with LLM
        llm_content = await self.llm_client.generate_response(attack_info)
        
        if llm_content:
            response = {
                'type': 'llm_generated',
                'content': llm_content,
                'delay': random.uniform(1.0, 3.0)
            }
            
            # Cache the response
            self.response_cache[cache_key] = (response, datetime.utcnow())
            
            return response
        else:
            # Fallback to static response
            return self._generate_static_response(attack_info)
            
    def _generate_static_response(self, attack_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate static response from templates."""
        attack_type = attack_info.get('type', 'unknown')
        responses = self.config.get_responses(attack_type)
        
        if not responses:
            responses = self.config.get_responses('default')
            
        # Choose response based on vulnerability rate
        fake_vuln_rate = self.config.get('honeypot.response.fake_vulnerability_rate', 0.3)
        
        if random.random() < fake_vuln_rate:
            # Show apparent vulnerability
            vulnerable_responses = [r for r in responses if r.get('type') in ['fake_success', 'honeypot_data', 'fake_execution']]
            if vulnerable_responses:
                responses = vulnerable_responses
                
        # Select random response
        if responses:
            selected_response = random.choice(responses)
            
            # Process response content
            content = selected_response.get('content', '')
            content = self._process_response_content(content, attack_info)
            
            return {
                'type': selected_response.get('type', 'static'),
                'content': content,
                'delay': selected_response.get('delay', 1.0)
            }
        else:
            return self._get_fallback_response(attack_info)
            
    def _process_response_content(self, content: str, attack_info: Dict[str, Any]) -> str:
        """Process response content with dynamic values."""
        # Replace common placeholders
        payload = attack_info.get('payload', '')
        
        content = content.replace('{payload}', payload[:100])  # Limit payload length
        content = content.replace('{source_ip}', attack_info.get('source_ip', 'unknown'))
        content = content.replace('{timestamp}', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
        
        # Add some randomization for more realistic responses
        if 'admin' in content and random.random() < 0.3:
            content = content.replace('admin', random.choice(['administrator', 'root', 'system']))
            
        return content
        
    def _get_fallback_response(self, attack_info: Dict[str, Any]) -> Dict[str, Any]:
        """Get basic fallback response."""
        fallback_responses = [
            "Connection established. Please wait...",
            "System ready. Enter command:",
            "Login: ",
            "Password: ",
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>System Status: Online</body></html>",
            "500 Internal Server Error",
            "Access denied. Contact administrator."
        ]
        
        return {
            'type': 'fallback',
            'content': random.choice(fallback_responses),
            'delay': 1.0
        }
        
    async def _apply_response_delay(self, attack_type: str) -> None:
        """Apply configured delay before response."""
        delay_min = self.config.get('honeypot.response.delay_min', 1.0)
        delay_max = self.config.get('honeypot.response.delay_max', 3.0)
        
        # Different delays for different attack types
        delay_multipliers = {
            'sql_injection': 1.5,  # Database queries take time
            'command_injection': 2.0,  # System commands take time
            'brute_force': 0.5,  # Quick login attempts
            'port_scan': 0.2,  # Fast port responses
            'xss': 1.0  # Normal web response
        }
        
        multiplier = delay_multipliers.get(attack_type, 1.0)
        delay = random.uniform(delay_min, delay_max) * multiplier
        
        await asyncio.sleep(delay)
        
    def generate_honeypot_banner(self, protocol: str, port: int) -> str:
        """Generate realistic banner for different services."""
        banners = {
            22: [
                "SSH-2.0-OpenSSH_7.4",
                "SSH-2.0-OpenSSH_8.0",
                "SSH-2.0-libssh_0.6.3"
            ],
            23: [
                "Welcome to Industrial Control System v2.1",
                "SCADA Terminal Server Ready",
                "HMI Access Point - Please Login"
            ],
            80: [
                "Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips",
                "Server: nginx/1.16.1",
                "Server: Microsoft-IIS/10.0"
            ],
            21: [
                "220 Industrial FTP Server Ready",
                "220 Microsoft FTP Service",
                "220 ProFTPD 1.3.5 Server"
            ],
            502: [
                "Modbus/TCP Server Ready",
                "Industrial Gateway v1.2",
                "PLC Communication Interface"
            ]
        }
        
        port_banners = banners.get(port, ["Service Ready"])
        return random.choice(port_banners)
        
    def customize_response_for_system_type(self, response: str, system_type: str) -> str:
        """Customize response based on simulated system type."""
        system_customizations = {
            'scada': {
                'keywords': ['pump', 'valve', 'pressure', 'flow', 'alarm', 'HMI'],
                'errors': ['Sensor malfunction', 'Control loop error', 'Safety interlock active']
            },
            'plc': {
                'keywords': ['ladder logic', 'I/O module', 'timer', 'counter', 'register'],
                'errors': ['Memory fault', 'Communication timeout', 'Input/Output error']
            },
            'hmi': {
                'keywords': ['operator', 'display', 'touchscreen', 'alarm list', 'trend'],
                'errors': ['Display timeout', 'Touch calibration error', 'Graphics failure']
            }
        }
        
        if system_type in system_customizations:
            customization = system_customizations[system_type]
            
            # Add relevant keywords
            if random.random() < 0.3:
                keyword = random.choice(customization['keywords'])
                response += f"\n[{keyword.upper()}] Status: OK"
                
            # Occasionally add system-specific errors
            if random.random() < 0.1:
                error = random.choice(customization['errors'])
                response += f"\nWARNING: {error}"
                
        return response