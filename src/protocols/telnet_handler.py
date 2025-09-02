"""
Telnet protocol handler for the honeypot.
"""

import asyncio
import logging
from typing import Dict, Any, Optional


class TelnetHandler:
    """Telnet protocol handler."""
    
    def __init__(self, config, attack_detector, response_engine, logger_manager):
        self.config = config
        self.attack_detector = attack_detector
        self.response_engine = response_engine
        self.logger_manager = logger_manager
        self.logger = logging.getLogger('honeypot.telnet')
        
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming Telnet connection."""
        client_info = writer.get_extra_info('peername')
        source_ip = client_info[0] if client_info else 'unknown'
        
        try:
            # Log connection
            self.logger_manager.log_connection({
                'source_ip': source_ip,
                'target_port': 23,
                'protocol': 'Telnet',
                'status': 'established'
            })
            
            # Send banner
            banner = self.response_engine.generate_honeypot_banner('telnet', 23)
            await self._send_data(writer, f"{banner}\r\n")
            
            # Handle telnet session
            await self._handle_telnet_session(reader, writer, source_ip)
            
        except Exception as e:
            self.logger.error(f"Error handling Telnet connection from {source_ip}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
                
    async def _handle_telnet_session(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, source_ip: str) -> None:
        """Handle Telnet session."""
        try:
            # Authentication
            authenticated = await self._handle_authentication(reader, writer, source_ip)
            
            if authenticated:
                # Main menu/shell
                await self._handle_main_interface(reader, writer, source_ip)
            else:
                await self._send_data(writer, "Authentication failed. Connection closed.\r\n")
                
        except Exception as e:
            self.logger.error(f"Error in Telnet session: {e}")
            
    async def _handle_authentication(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, source_ip: str) -> bool:
        """Handle Telnet authentication."""
        max_attempts = 3
        attempts = 0
        
        while attempts < max_attempts:
            try:
                # Username prompt
                await self._send_data(writer, "Username: ")
                username = await asyncio.wait_for(reader.readline(), timeout=30.0)
                if not username:
                    break
                    
                username = username.decode('utf-8', errors='ignore').strip()
                
                # Password prompt
                await self._send_data(writer, "Password: ")
                password = await asyncio.wait_for(reader.readline(), timeout=30.0)
                if not password:
                    break
                    
                password = password.decode('utf-8', errors='ignore').strip()
                
                # Analyze credentials
                credentials = f"{username}:{password}"
                attack_info = await self._analyze_telnet_auth(credentials, source_ip, attempts)
                
                if attack_info:
                    response = await self.response_engine.generate_response(attack_info)
                    
                    if 'fake_success' in response.get('type', ''):
                        await self._send_data(writer, "Login successful.\r\n\r\n")
                        return True
                    else:
                        await self._send_data(writer, "Invalid credentials.\r\n")
                else:
                    # Check for valid credentials (honeypot accepts some common ones)
                    if self._check_honeypot_credentials(username, password):
                        await self._send_data(writer, "Login successful.\r\n\r\n")
                        return True
                    else:
                        await self._send_data(writer, "Invalid credentials.\r\n")
                        
                attempts += 1
                
            except asyncio.TimeoutError:
                await self._send_data(writer, "Timeout. Connection closed.\r\n")
                break
            except Exception as e:
                self.logger.error(f"Error in Telnet authentication: {e}")
                break
                
        return False
        
    def _check_honeypot_credentials(self, username: str, password: str) -> bool:
        """Check if credentials should be accepted by honeypot."""
        # Accept some common credentials to attract attackers
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', 'admin123'),
            ('operator', 'operator'),
            ('guest', 'guest'),
            ('user', 'user'),
            ('scada', 'scada'),
            ('engineer', 'engineer')
        ]
        
        return (username.lower(), password.lower()) in common_creds
        
    async def _handle_main_interface(self, reader: asyncio.StreamWriter, writer: asyncio.StreamWriter, source_ip: str) -> None:
        """Handle main telnet interface."""
        try:
            # Show welcome message and menu
            await self._show_main_menu(writer)
            
            while True:
                await self._send_data(writer, "SCADA> ")
                
                try:
                    command = await asyncio.wait_for(reader.readline(), timeout=60.0)
                    if not command:
                        break
                        
                    command = command.decode('utf-8', errors='ignore').strip()
                    if not command:
                        continue
                        
                    # Handle exit commands
                    if command.lower() in ['exit', 'quit', 'logout']:
                        await self._send_data(writer, "Goodbye.\r\n")
                        break
                        
                    # Analyze command for attacks
                    attack_info = await self._analyze_telnet_command(command, source_ip)
                    
                    if attack_info:
                        # Generate response for attack
                        response = await self.response_engine.generate_response(attack_info)
                        output = response.get('content', 'Command not recognized')
                    else:
                        # Generate normal command output
                        output = self._process_command(command)
                        
                    await self._send_data(writer, f"{output}\r\n")
                    
                except asyncio.TimeoutError:
                    await self._send_data(writer, "Session timeout.\r\n")
                    break
                    
        except Exception as e:
            self.logger.error(f"Error in Telnet main interface: {e}")
            
    async def _show_main_menu(self, writer: asyncio.StreamWriter) -> None:
        """Show main menu."""
        menu = '''
====================================
  Industrial Control System v2.1
  SCADA Terminal Interface
====================================

Available Commands:
  status     - Show system status
  sensors    - Display sensor readings
  pumps      - Show pump status
  valves     - Display valve positions
  alarms     - View active alarms
  config     - Configuration menu
  logs       - View system logs
  help       - Show this menu
  exit       - Logout

====================================
'''
        await self._send_data(writer, menu)
        
    def _process_command(self, command: str) -> str:
        """Process telnet command."""
        command = command.strip().lower()
        
        if command == 'status':
            return '''System Status: ONLINE
Uptime: 15 days, 4 hours, 23 minutes
CPU Usage: 23%
Memory Usage: 67%
Network: Connected
Last Update: 2024-01-15 14:30:25'''
            
        elif command == 'sensors':
            return '''Sensor Readings:
Temperature Sensor 01: 23.5°C (Normal)
Pressure Sensor 01: 101.3 kPa (Normal)
Flow Sensor 01: 125.7 L/min (Normal)
Level Sensor 01: 78% (Normal)
pH Sensor 01: 7.2 (Normal)'''
            
        elif command == 'pumps':
            return '''Pump Status:
Pump 01: RUNNING (85% capacity)
Pump 02: RUNNING (67% capacity)
Pump 03: STOPPED (Maintenance mode)
Pump 04: RUNNING (92% capacity)'''
            
        elif command == 'valves':
            return '''Valve Positions:
Inlet Valve 01: OPEN (45°)
Outlet Valve 01: OPEN (67°)
Control Valve 01: PARTIAL (23°)
Safety Valve 01: CLOSED'''
            
        elif command == 'alarms':
            return '''Active Alarms:
[INFO] 14:25:12 - Pump 03 scheduled maintenance
[WARN] 14:20:45 - High temperature trend detected
[INFO] 14:15:30 - Operator login: admin

No critical alarms'''
            
        elif command == 'config':
            return '''Configuration Menu:
1. Network Settings
2. Alarm Thresholds
3. User Management
4. System Parameters
5. Back to Main Menu

Enter selection (1-5):'''
            
        elif command == 'logs':
            return '''Recent System Logs:
2024-01-15 14:30:25 [INFO] System status check completed
2024-01-15 14:29:12 [INFO] Sensor calibration successful
2024-01-15 14:28:45 [WARN] Network latency spike detected
2024-01-15 14:27:33 [INFO] Pump 01 performance optimal
2024-01-15 14:26:18 [INFO] User 'admin' logged in'''
            
        elif command == 'help':
            return '''Available Commands:
status, sensors, pumps, valves, alarms, config, logs, help, exit'''
            
        elif command.startswith('config ') or command.isdigit():
            # Handle config submenu
            return self._handle_config_submenu(command)
            
        else:
            return f"Unknown command: {command}. Type 'help' for available commands."
            
    def _handle_config_submenu(self, selection: str) -> str:
        """Handle configuration submenu."""
        if selection == '1' or 'network' in selection:
            return '''Network Configuration:
IP Address: 192.168.1.100
Subnet Mask: 255.255.255.0
Gateway: 192.168.1.1
DNS: 192.168.1.10
Status: Connected'''
            
        elif selection == '2' or 'alarm' in selection:
            return '''Alarm Thresholds:
Temperature High: 35.0°C
Temperature Low: 5.0°C
Pressure High: 150.0 kPa
Pressure Low: 50.0 kPa
Flow High: 200.0 L/min
Flow Low: 10.0 L/min'''
            
        elif selection == '3' or 'user' in selection:
            return '''User Management:
Current Users:
- admin (Administrator)
- operator (Operator)
- guest (Read-only)

Last Login Times:
admin: 2024-01-15 14:30:25
operator: 2024-01-15 12:15:10'''
            
        elif selection == '4' or 'system' in selection:
            return '''System Parameters:
Scan Rate: 1000 ms
Data Retention: 30 days
Auto Backup: Enabled
Debug Mode: Disabled
Communication Timeout: 5000 ms'''
            
        else:
            return "Invalid selection. Enter 1-5 or type command."
            
    async def _analyze_telnet_auth(self, credentials: str, source_ip: str, attempt: int) -> Optional[Dict[str, Any]]:
        """Analyze telnet authentication attempt."""
        analysis_data = {
            'source_ip': source_ip,
            'target_port': 23,
            'protocol': 'Telnet',
            'payload': f"auth_attempt_{attempt}: {credentials}",
            'context': 'Telnet authentication',
            'system_type': 'SCADA'
        }
        
        return await self.attack_detector.analyze_request(analysis_data)
        
    async def _analyze_telnet_command(self, command: str, source_ip: str) -> Optional[Dict[str, Any]]:
        """Analyze telnet command for attacks."""
        analysis_data = {
            'source_ip': source_ip,
            'target_port': 23,
            'protocol': 'Telnet',
            'payload': command,
            'context': 'Telnet command',
            'system_type': 'SCADA'
        }
        
        return await self.attack_detector.analyze_request(analysis_data)
        
    async def _send_data(self, writer: asyncio.StreamWriter, data: str) -> None:
        """Send data to telnet client."""
        try:
            writer.write(data.encode('utf-8'))
            await writer.drain()
        except Exception as e:
            self.logger.error(f"Error sending Telnet data: {e}")