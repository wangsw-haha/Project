"""
HTTP protocol handler for the honeypot.
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from urllib.parse import unquote
import re


class HTTPHandler:
    """HTTP protocol handler."""
    
    def __init__(self, config, attack_detector, response_engine, logger_manager):
        self.config = config
        self.attack_detector = attack_detector
        self.response_engine = response_engine
        self.logger_manager = logger_manager
        self.logger = logging.getLogger('honeypot.http')
        
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming HTTP connection."""
        client_info = writer.get_extra_info('peername')
        source_ip = client_info[0] if client_info else 'unknown'
        
        try:
            # Log connection
            self.logger_manager.log_connection({
                'source_ip': source_ip,
                'target_port': 80,
                'protocol': 'HTTP',
                'status': 'established'
            })
            
            # Read HTTP request
            request_data = await self._read_http_request(reader)
            if not request_data:
                return
                
            # Analyze for attacks
            attack_info = await self._analyze_http_request(request_data, source_ip)
            
            # Generate and send response
            if attack_info:
                # Handle attack
                response = await self._handle_attack_response(attack_info)
            else:
                # Normal response
                response = await self._handle_normal_response(request_data)
                
            await self._send_http_response(writer, response)
            
        except Exception as e:
            self.logger.error(f"Error handling HTTP connection from {source_ip}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
                
    async def _read_http_request(self, reader: asyncio.StreamReader) -> Optional[Dict[str, Any]]:
        """Read and parse HTTP request."""
        try:
            # Read request line
            request_line = await reader.readline()
            if not request_line:
                return None
                
            request_line = request_line.decode('utf-8', errors='ignore').strip()
            
            # Parse request line
            parts = request_line.split(' ')
            if len(parts) < 3:
                return None
                
            method, path, version = parts[0], parts[1], parts[2]
            
            # Read headers
            headers = {}
            while True:
                line = await reader.readline()
                if not line or line == b'\r\n':
                    break
                    
                line = line.decode('utf-8', errors='ignore').strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                    
            # Read body if present
            body = b''
            content_length = headers.get('content-length')
            if content_length:
                try:
                    length = int(content_length)
                    body = await reader.read(length)
                except ValueError:
                    pass
                    
            return {
                'method': method,
                'path': path,
                'version': version,
                'headers': headers,
                'body': body.decode('utf-8', errors='ignore'),
                'raw_request': request_line
            }
            
        except Exception as e:
            self.logger.error(f"Error reading HTTP request: {e}")
            return None
            
    async def _analyze_http_request(self, request_data: Dict[str, Any], source_ip: str) -> Optional[Dict[str, Any]]:
        """Analyze HTTP request for attacks."""
        # Build analysis payload
        path = unquote(request_data.get('path', ''))
        body = request_data.get('body', '')
        headers = request_data.get('headers', {})
        
        # Combine all potential attack vectors
        payload = f"{path} {body}"
        
        # Add suspicious headers
        for header_name, header_value in headers.items():
            if header_name in ['user-agent', 'referer', 'x-forwarded-for']:
                payload += f" {header_value}"
                
        analysis_data = {
            'source_ip': source_ip,
            'target_port': 80,
            'protocol': 'HTTP',
            'payload': payload,
            'method': request_data.get('method'),
            'path': path,
            'user_agent': headers.get('user-agent', ''),
            'context': 'Web application',
            'system_type': 'HMI'
        }
        
        return await self.attack_detector.analyze_request(analysis_data)
        
    async def _handle_attack_response(self, attack_info: Dict[str, Any]) -> Dict[str, Any]:
        """Handle attack and generate response."""
        from core.honeypot import IndustrialHoneypot
        
        # Get response from main honeypot handler
        response = await self.response_engine.generate_response(attack_info)
        
        attack_type = attack_info.get('type')
        
        # Customize HTTP response based on attack type
        if attack_type == 'sql_injection':
            return self._create_sql_response(response)
        elif attack_type == 'xss':
            return self._create_xss_response(response, attack_info)
        elif attack_type == 'command_injection':
            return self._create_command_response(response)
        elif attack_type == 'directory_traversal':
            return self._create_file_response(response)
        else:
            return self._create_generic_response(response)
            
    async def _handle_normal_response(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle normal HTTP request."""
        path = request_data.get('path', '/')
        method = request_data.get('method', 'GET')
        
        # Simulate industrial web interface
        if path == '/' or path == '/index.html':
            content = self._generate_industrial_homepage()
        elif path.startswith('/admin'):
            content = self._generate_admin_interface()
        elif path.startswith('/api/'):
            content = self._generate_api_response(path)
        elif path.startswith('/scada/'):
            content = self._generate_scada_interface()
        else:
            content = self._generate_404_page()
            
        return {
            'status_code': 200 if '404' not in content else 404,
            'headers': {
                'Content-Type': 'text/html',
                'Server': 'Industrial-Web-Server/2.1',
                'X-Powered-By': 'SCADA-Framework'
            },
            'content': content
        }
        
    def _create_sql_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Create SQL injection response."""
        content = response.get('content', 'Database error')
        
        if 'fake_error' in response.get('type', ''):
            return {
                'status_code': 500,
                'headers': {'Content-Type': 'text/html'},
                'content': f'<html><body><h1>Database Error</h1><p>{content}</p></body></html>'
            }
        else:
            return {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'content': f'{{"result": "{content}", "status": "success"}}'
            }
            
    def _create_xss_response(self, response: Dict[str, Any], attack_info: Dict[str, Any]) -> Dict[str, Any]:
        """Create XSS response."""
        content = response.get('content', 'Request processed')
        payload = attack_info.get('payload', '')
        
        # Reflect the payload back (simulating vulnerability)
        if 'reflected' in response.get('type', ''):
            content = content.format(payload=payload)
            
        return {
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'content': f'<html><body><h1>Search Results</h1><p>{content}</p></body></html>'
        }
        
    def _create_command_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Create command injection response."""
        content = response.get('content', 'Command executed')
        
        return {
            'status_code': 200,
            'headers': {'Content-Type': 'text/plain'},
            'content': content
        }
        
    def _create_file_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Create file access response."""
        content = response.get('content', 'File not found')
        
        return {
            'status_code': 200,
            'headers': {'Content-Type': 'text/plain'},
            'content': content
        }
        
    def _create_generic_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Create generic response."""
        content = response.get('content', 'Request processed')
        
        return {
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'content': f'<html><body>{content}</body></html>'
        }
        
    def _generate_industrial_homepage(self) -> str:
        """Generate industrial system homepage."""
        return '''<!DOCTYPE html>
<html>
<head>
    <title>Industrial Control System - HMI Interface</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; }
        .header { background: #003366; color: white; padding: 20px; }
        .content { padding: 20px; }
        .status { background: #e6ffe6; border: 1px solid #00cc00; padding: 10px; margin: 10px 0; }
        .alarm { background: #ffe6e6; border: 1px solid #cc0000; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Industrial Control System v2.1</h1>
        <p>SCADA/HMI Management Interface</p>
    </div>
    <div class="content">
        <div class="status">
            <h3>System Status: ONLINE</h3>
            <p>All systems operational. Last update: 2024-01-15 14:30:25</p>
        </div>
        <h3>Quick Access</h3>
        <ul>
            <li><a href="/admin">Administration Panel</a></li>
            <li><a href="/scada/overview">SCADA Overview</a></li>
            <li><a href="/api/status">System API</a></li>
            <li><a href="/reports">Historical Reports</a></li>
        </ul>
        <div class="alarm">
            <strong>WARNING:</strong> Maintenance scheduled for 2024-01-20 02:00 UTC
        </div>
    </div>
</body>
</html>'''
        
    def _generate_admin_interface(self) -> str:
        """Generate admin interface."""
        return '''<!DOCTYPE html>
<html>
<head><title>Administration Panel</title></head>
<body>
    <h1>System Administration</h1>
    <form action="/admin/login" method="post">
        <p>Username: <input type="text" name="username" value="admin"></p>
        <p>Password: <input type="password" name="password"></p>
        <p><input type="submit" value="Login"></p>
    </form>
    <p><small>Default credentials: admin/admin123</small></p>
</body>
</html>'''
        
    def _generate_api_response(self, path: str) -> str:
        """Generate API response."""
        if 'status' in path:
            return '{"status": "online", "version": "2.1.0", "uptime": 86400, "processes": 23}'
        elif 'sensors' in path:
            return '{"temperature": 23.5, "pressure": 101.3, "flow_rate": 45.2, "status": "normal"}'
        else:
            return '{"error": "Unknown endpoint", "available": ["/api/status", "/api/sensors"]}'
            
    def _generate_scada_interface(self) -> str:
        """Generate SCADA interface."""
        return '''<!DOCTYPE html>
<html>
<head><title>SCADA Overview</title></head>
<body>
    <h1>SCADA System Overview</h1>
    <table border="1">
        <tr><th>Device</th><th>Status</th><th>Value</th></tr>
        <tr><td>Pump 01</td><td>Running</td><td>85%</td></tr>
        <tr><td>Valve 01</td><td>Open</td><td>45°</td></tr>
        <tr><td>Sensor 01</td><td>Normal</td><td>23.5°C</td></tr>
        <tr><td>Flow Meter</td><td>Active</td><td>125 L/min</td></tr>
    </table>
    <p><a href="/scada/control">Device Control</a></p>
</body>
</html>'''
        
    def _generate_404_page(self) -> str:
        """Generate 404 error page."""
        return '''<!DOCTYPE html>
<html>
<head><title>404 - Page Not Found</title></head>
<body>
    <h1>404 - Page Not Found</h1>
    <p>The requested resource was not found on this server.</p>
    <p><a href="/">Return to Homepage</a></p>
</body>
</html>'''
        
    async def _send_http_response(self, writer: asyncio.StreamWriter, response: Dict[str, Any]) -> None:
        """Send HTTP response."""
        try:
            status_code = response.get('status_code', 200)
            headers = response.get('headers', {})
            content = response.get('content', '')
            
            # Build response
            response_line = f"HTTP/1.1 {status_code} OK\r\n"
            
            # Add headers
            headers['Content-Length'] = str(len(content.encode('utf-8')))
            headers['Connection'] = 'close'
            
            for key, value in headers.items():
                response_line += f"{key}: {value}\r\n"
                
            response_line += "\r\n"
            response_line += content
            
            # Send response
            writer.write(response_line.encode('utf-8'))
            await writer.drain()
            
        except Exception as e:
            self.logger.error(f"Error sending HTTP response: {e}")