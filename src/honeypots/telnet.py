import asyncio
import socket
import threading
from typing import Dict, Any
from loguru import logger
from src.core.honeypot import BaseHoneypot
from src.llm.service import llm_service


class TelnetHoneypot(BaseHoneypot):
    """Telnet Honeypot implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("telnet", config.get("port", 23), config)
        self.server_socket = None
        
        # Fake system info
        self.system_banner = config.get("banner", "Ubuntu 20.04.3 LTS")
        self.hostname = "industrial-gateway"
        self.current_user = "admin"
        
        # Command history per session
        self.session_commands = {}
    
    async def start(self):
        """Start Telnet honeypot"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(10)
            
            logger.info(f"Telnet Honeypot listening on port {self.port}")
            
            while True:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    ).start()
                except Exception as e:
                    if self.server_socket:
                        logger.error(f"Error accepting Telnet connection: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Error starting Telnet honeypot: {e}")
    
    async def stop(self):
        """Stop Telnet honeypot"""
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        logger.info("Telnet Honeypot stopped")
    
    def _handle_client(self, client_socket, client_address):
        """Handle Telnet client connection"""
        session_id = None
        
        try:
            # Create session
            session_id = self.create_session(client_address[0])
            self.session_commands[session_id] = []
            
            # Log connection
            asyncio.run(self.log_attack(
                client_address[0],
                client_address[1],
                attack_type="telnet_connection",
                session_id=session_id
            ))
            
            # Send welcome banner
            client_socket.send(f"{self.system_banner}\r\n".encode())
            client_socket.send(f"{self.hostname} login: ".encode())
            
            # Handle login
            username = self._receive_line(client_socket).strip()
            if username:
                client_socket.send(b"Password: ")
                password = self._receive_line(client_socket).strip()
                
                # Log login attempt
                asyncio.run(self.log_attack(
                    client_address[0],
                    0,
                    payload=f"username: {username}, password: {password}",
                    attack_type="telnet_login",
                    session_id=session_id
                ))
                
                # Always "accept" login for honeypot purposes
                client_socket.send(f"\r\nWelcome to {self.hostname}\r\n".encode())
                client_socket.send(f"Last login: Mon Jan  1 12:00:00 2024 from {client_address[0]}\r\n".encode())
                
                # Start shell session
                self._handle_shell(client_socket, session_id, client_address[0], username)
        
        except Exception as e:
            logger.error(f"Error handling Telnet client {client_address[0]}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            
            if session_id:
                self.end_session(session_id)
                if session_id in self.session_commands:
                    del self.session_commands[session_id]
    
    def _receive_line(self, client_socket) -> str:
        """Receive a line from the client"""
        try:
            data = b""
            while True:
                char = client_socket.recv(1)
                if not char:
                    break
                if char in [b'\r', b'\n']:
                    if data:
                        break
                else:
                    data += char
            return data.decode('utf-8', errors='ignore')
        except:
            return ""
    
    def _handle_shell(self, client_socket, session_id: str, source_ip: str, username: str):
        """Handle Telnet shell session"""
        try:
            while True:
                # Send prompt
                prompt = f"{username}@{self.hostname}:~$ "
                client_socket.send(prompt.encode())
                
                # Receive command
                command = self._receive_line(client_socket)
                if not command:
                    break
                
                command = command.strip()
                if not command:
                    continue
                
                # Process command
                response = asyncio.run(self._process_command(command, session_id, source_ip, username))
                
                # Send response
                if response:
                    client_socket.send(f"{response}\r\n".encode())
                
                # Check for exit commands
                if command.lower() in ["exit", "logout", "quit"]:
                    client_socket.send(b"logout\r\n")
                    break
        
        except Exception as e:
            logger.error(f"Error in Telnet shell for {source_ip}: {e}")
    
    async def _process_command(self, command: str, session_id: str, source_ip: str, username: str) -> str:
        """Process Telnet command"""
        try:
            # Update session data
            if session_id in self.active_sessions:
                self.active_sessions[session_id]["commands_count"] += 1
                self.active_sessions[session_id]["commands_executed"].append(command)
            
            if session_id in self.session_commands:
                self.session_commands[session_id].append(command)
            
            # Log command
            await self.log_attack(
                source_ip,
                0,
                payload=command,
                attack_type="telnet_command",
                session_id=session_id
            )
            
            # Process common commands
            cmd_parts = command.split()
            if not cmd_parts:
                return ""
            
            cmd = cmd_parts[0].lower()
            
            if cmd == "help":
                return self._get_help_text()
            elif cmd == "ls":
                return "file1.txt  file2.log  directory1/"
            elif cmd == "pwd":
                return f"/home/{username}"
            elif cmd == "whoami":
                return username
            elif cmd == "id":
                return f"uid=1000({username}) gid=1000({username}) groups=1000({username}),4(adm),24(cdrom),27(sudo)"
            elif cmd == "ps":
                return "PID TTY          TIME CMD\n 1234 pts/0    00:00:01 bash\n 5678 pts/0    00:00:00 ps"
            elif cmd == "netstat":
                return """Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 192.168.1.100:502       192.168.1.10:3456       ESTABLISHED
tcp        0      0 192.168.1.100:80        192.168.1.20:4567       ESTABLISHED"""
            elif cmd == "uname":
                if len(cmd_parts) > 1 and cmd_parts[1] == "-a":
                    return "Linux industrial-gateway 5.4.0-91-generic #102-Ubuntu SMP Wed Jan 20 02:56:02 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux"
                else:
                    return "Linux"
            elif cmd == "ifconfig":
                return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)"""
            elif cmd == "cat":
                if len(cmd_parts) > 1:
                    filename = cmd_parts[1]
                    if filename == "/etc/passwd":
                        return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
admin:x:1000:1000:Admin:/home/admin:/bin/bash"""
                    elif filename == "/proc/version":
                        return "Linux version 5.4.0-91-generic (buildd@lgw01-amd64-039) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #102-Ubuntu SMP Wed Jan 20 02:56:02 UTC 2021"
                    else:
                        return f"cat: {filename}: No such file or directory"
                else:
                    return "cat: missing operand"
            elif cmd == "df":
                return """Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/sda1       20641404 3456789  16053547  18% /
tmpfs            1024000       0   1024000   0% /dev/shm"""
            elif cmd == "free":
                return """              total        used        free      shared  buff/cache   available
Mem:        2048000      456789     1234567        1234       356789     1456789
Swap:       1024000           0     1024000"""
            elif cmd == "date":
                from datetime import datetime
                return datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
            elif cmd == "history":
                if session_id in self.session_commands:
                    history = self.session_commands[session_id]
                    return "\n".join(f"  {i+1}  {cmd}" for i, cmd in enumerate(history))
                else:
                    return "1  help"
            elif cmd in ["exit", "logout", "quit"]:
                return ""
            else:
                # Use LLM for unknown commands
                context = {
                    "service": "telnet",
                    "username": username,
                    "hostname": self.hostname,
                    "session_id": session_id
                }
                
                # Check for potentially malicious commands
                malicious_indicators = ["rm -rf", "wget", "curl", "nc", "netcat", "/etc/shadow", "sudo"]
                if any(indicator in command.lower() for indicator in malicious_indicators):
                    await self.log_attack(
                        source_ip,
                        0,
                        payload=command,
                        attack_type="telnet_malicious_command",
                        session_id=session_id
                    )
                
                return await llm_service.generate_response(command, context)
        
        except Exception as e:
            logger.error(f"Error processing Telnet command '{command}': {e}")
            return f"bash: {cmd}: command not found"
    
    def _get_help_text(self) -> str:
        """Get help text for available commands"""
        return """Available commands:
ls      - list directory contents
pwd     - print working directory
whoami  - print current user
ps      - display running processes
netstat - display network connections
uname   - system information
ifconfig- network interface configuration
cat     - display file contents
df      - display filesystem usage
free    - display memory usage
date    - display current date and time
history - command history
help    - this help message
exit    - logout"""