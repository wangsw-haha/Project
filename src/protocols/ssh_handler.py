"""
SSH protocol handler for the honeypot.
"""

import asyncio
import logging
import random
from typing import Dict, Any, Optional


class SSHHandler:
    """SSH protocol handler."""
    
    def __init__(self, config, attack_detector, response_engine, logger_manager):
        self.config = config
        self.attack_detector = attack_detector
        self.response_engine = response_engine
        self.logger_manager = logger_manager
        self.logger = logging.getLogger('honeypot.ssh')
        
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming SSH connection."""
        client_info = writer.get_extra_info('peername')
        source_ip = client_info[0] if client_info else 'unknown'
        
        try:
            # Log connection
            self.logger_manager.log_connection({
                'source_ip': source_ip,
                'target_port': 22,
                'protocol': 'SSH',
                'status': 'established'
            })
            
            # Send SSH banner
            banner = self.response_engine.generate_honeypot_banner('ssh', 22)
            await self._send_data(writer, f"{banner}\r\n")
            
            # Handle SSH protocol simulation
            await self._handle_ssh_protocol(reader, writer, source_ip)
            
        except Exception as e:
            self.logger.error(f"Error handling SSH connection from {source_ip}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
                
    async def _handle_ssh_protocol(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, source_ip: str) -> None:
        """Handle SSH protocol simulation."""
        try:
            # Read client identification
            client_version = await reader.readline()
            if not client_version:
                return
                
            client_version = client_version.decode('utf-8', errors='ignore').strip()
            
            # Analyze for attacks
            attack_info = await self._analyze_ssh_data(client_version, source_ip)
            
            # Simulate key exchange (simplified)
            await self._simulate_key_exchange(reader, writer)
            
            # Handle authentication attempts
            await self._handle_authentication(reader, writer, source_ip)
            
        except Exception as e:
            self.logger.error(f"Error in SSH protocol handling: {e}")
            
    async def _simulate_key_exchange(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Simulate SSH key exchange."""
        # Send server key exchange
        kex_data = b'\x00\x00\x00\x0c\x0a\x14' + b'fake_kex_data' * 10
        await self._send_data(writer, kex_data)
        
        # Read client key exchange
        try:
            client_kex = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        except asyncio.TimeoutError:
            pass
            
    async def _handle_authentication(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, source_ip: str) -> None:
        """Handle SSH authentication attempts."""
        attempts = 0
        max_attempts = 3
        
        while attempts < max_attempts:
            try:
                # Send authentication request
                auth_prompt = b'\x00\x00\x00\x10\x32password: '
                await self._send_data(writer, auth_prompt)
                
                # Read authentication attempt
                auth_data = await asyncio.wait_for(reader.read(1024), timeout=30.0)
                if not auth_data:
                    break
                    
                # Analyze authentication attempt
                auth_string = auth_data.decode('utf-8', errors='ignore')
                attack_info = await self._analyze_ssh_auth(auth_string, source_ip, attempts)
                
                if attack_info:
                    # Handle brute force attack
                    response = await self.response_engine.generate_response(attack_info)
                    
                    if 'fake_success' in response.get('type', ''):
                        # Simulate successful login
                        await self._simulate_shell_session(reader, writer, source_ip)
                        break
                    else:
                        # Authentication failed
                        await self._send_data(writer, b'Authentication failed\r\n')
                        
                attempts += 1
                
            except asyncio.TimeoutError:
                break
            except Exception as e:
                self.logger.error(f"Error in SSH authentication: {e}")
                break
                
    async def _simulate_shell_session(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, source_ip: str) -> None:
        """Simulate SSH shell session."""
        try:
            # Send welcome message
            welcome = "Welcome to Industrial Control System\r\nLast login: Tue Jan 15 14:30:22 2024\r\n"
            await self._send_data(writer, welcome.encode())
            
            # Send prompt
            await self._send_data(writer, b'scada@industrial:~$ ')
            
            # Handle commands
            while True:
                try:
                    command = await asyncio.wait_for(reader.readline(), timeout=60.0)
                    if not command:
                        break
                        
                    command = command.decode('utf-8', errors='ignore').strip()
                    if not command:
                        continue
                        
                    # Analyze command for attacks
                    attack_info = await self._analyze_ssh_command(command, source_ip)
                    
                    if attack_info:
                        # Generate response for attack
                        response = await self.response_engine.generate_response(attack_info)
                        output = response.get('content', 'Command not found')
                    else:
                        # Generate normal command output
                        output = self._generate_command_output(command)
                        
                    await self._send_data(writer, f"{output}\r\n".encode())
                    await self._send_data(writer, b'scada@industrial:~$ ')
                    
                except asyncio.TimeoutError:
                    break
                    
        except Exception as e:
            self.logger.error(f"Error in SSH shell session: {e}")
            
    async def _analyze_ssh_data(self, data: str, source_ip: str) -> Optional[Dict[str, Any]]:
        """Analyze SSH data for attacks."""
        analysis_data = {
            'source_ip': source_ip,
            'target_port': 22,
            'protocol': 'SSH',
            'payload': data,
            'context': 'SSH connection',
            'system_type': 'Linux server'
        }
        
        return await self.attack_detector.analyze_request(analysis_data)
        
    async def _analyze_ssh_auth(self, auth_data: str, source_ip: str, attempt: int) -> Optional[Dict[str, Any]]:
        """Analyze SSH authentication attempt."""
        # Extract username/password from auth data (simplified)
        credentials = auth_data.lower()
        
        analysis_data = {
            'source_ip': source_ip,
            'target_port': 22,
            'protocol': 'SSH',
            'payload': f"auth_attempt_{attempt}: {credentials}",
            'context': 'SSH authentication',
            'system_type': 'Linux server'
        }
        
        return await self.attack_detector.analyze_request(analysis_data)
        
    async def _analyze_ssh_command(self, command: str, source_ip: str) -> Optional[Dict[str, Any]]:
        """Analyze SSH command for attacks."""
        analysis_data = {
            'source_ip': source_ip,
            'target_port': 22,
            'protocol': 'SSH',
            'payload': command,
            'context': 'SSH shell command',
            'system_type': 'Linux server'
        }
        
        return await self.attack_detector.analyze_request(analysis_data)
        
    def _generate_command_output(self, command: str) -> str:
        """Generate realistic command output."""
        command = command.strip().lower()
        
        if command == 'ls':
            return "config  data  logs  scripts  temp"
        elif command == 'pwd':
            return "/home/scada"
        elif command == 'whoami':
            return "scada"
        elif command == 'id':
            return "uid=1001(scada) gid=1001(scada) groups=1001(scada),100(users)"
        elif command.startswith('cat'):
            if 'passwd' in command:
                return "root:x:0:0:root:/root:/bin/bash\nscada:x:1001:1001:SCADA User:/home/scada:/bin/bash"
            else:
                return "Permission denied"
        elif command == 'ps aux':
            return '''USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1  19356  1560 ?        Ss   Jan15   0:01 /sbin/init
scada      123  0.5  2.1  45678  8901 ?        S    14:30   0:05 /usr/bin/scada-server
scada      124  0.1  0.8  12345  3456 ?        S    14:30   0:01 /usr/bin/hmi-client'''
        elif command == 'netstat -an':
            return '''Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:502             0.0.0.0:*               LISTEN'''
        elif command == 'uname -a':
            return "Linux industrial 4.15.0-123-generic #126-Ubuntu SMP Wed Dec 9 16:32:23 UTC 2020 x86_64 GNU/Linux"
        elif command.startswith('cd'):
            return ""
        elif command == 'history':
            return '''  1  ls
  2  cd /var/log
  3  tail -f scada.log
  4  systemctl status scada-server
  5  netstat -an'''
        elif command == 'exit':
            return "logout"
        else:
            return f"{command}: command not found"
            
    async def _send_data(self, writer: asyncio.StreamWriter, data) -> None:
        """Send data to SSH client."""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            writer.write(data)
            await writer.drain()
        except Exception as e:
            self.logger.error(f"Error sending SSH data: {e}")