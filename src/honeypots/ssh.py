import asyncio
import paramiko
import threading
import socket
from io import StringIO
from typing import Dict, Any
from loguru import logger
from src.core.honeypot import BaseHoneypot
from src.llm.service import llm_service


class SSHHoneypot(BaseHoneypot):
    """SSH Honeypot implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("ssh", config.get("port", 22), config)
        self.host_key = None
        self.server_socket = None
        self._setup_host_key()
        
        # Fake filesystem structure
        self.fake_filesystem = {
            "/": ["home", "etc", "var", "usr", "tmp"],
            "/home": ["user", "admin"],
            "/home/user": ["documents", "downloads", "file1.txt", "script.sh"],
            "/home/admin": ["config.conf", "backup.tar.gz"],
            "/etc": ["passwd", "shadow", "hosts", "ssh"],
            "/var": ["log", "www", "tmp"],
            "/var/log": ["auth.log", "syslog", "apache2"],
            "/usr": ["bin", "lib", "share"],
            "/tmp": []
        }
        
        # Current directory per session
        self.session_dirs = {}
    
    def _setup_host_key(self):
        """Setup SSH host key"""
        try:
            self.host_key = paramiko.RSAKey.generate(2048)
        except Exception as e:
            logger.error(f"Error generating host key: {e}")
    
    async def start(self):
        """Start SSH honeypot"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(100)
            
            logger.info(f"SSH Honeypot listening on port {self.port}")
            
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
                        logger.error(f"Error accepting SSH connection: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Error starting SSH honeypot: {e}")
    
    async def stop(self):
        """Stop SSH honeypot"""
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        logger.info("SSH Honeypot stopped")
    
    def _handle_client(self, client_socket, client_address):
        """Handle SSH client connection"""
        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            server = SSHServer(self, client_address[0])
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer)
            
            try:
                transport.start_server(server=server)
            except paramiko.SSHException:
                logger.info(f"SSH negotiation failed with {client_address[0]}")
                return
            
            chan = transport.accept(20)
            if chan is None:
                logger.info(f"No SSH channel from {client_address[0]}")
                return
            
            # Create session
            session_id = self.create_session(client_address[0])
            self.session_dirs[session_id] = "/home/user"
            
            # Log connection attempt
            asyncio.run(self.log_attack(
                client_address[0], 
                client_address[1],
                attack_type="ssh_connection",
                session_id=session_id
            ))
            
            # Send welcome message
            chan.send(f"Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)\r\n\r\n")
            chan.send("user@ubuntu:~$ ")
            
            # Handle commands
            self._handle_shell(chan, session_id, client_address[0])
            
        except Exception as e:
            logger.error(f"Error handling SSH client {client_address[0]}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _handle_shell(self, chan, session_id, source_ip):
        """Handle SSH shell session"""
        command_buffer = ""
        
        try:
            while True:
                data = chan.recv(1024)
                if not data:
                    break
                
                command_buffer += data.decode('utf-8', errors='ignore')
                
                # Check for complete command (ended with newline)
                if '\r' in command_buffer or '\n' in command_buffer:
                    # Extract command
                    lines = command_buffer.replace('\r', '\n').split('\n')
                    for line in lines[:-1]:  # Process all complete lines
                        command = line.strip()
                        if command:
                            response = asyncio.run(self._process_command(command, session_id, source_ip))
                            chan.send(f"{response}\r\n")
                            chan.send("user@ubuntu:~$ ")
                    
                    # Keep the last incomplete line
                    command_buffer = lines[-1]
                
        except Exception as e:
            logger.error(f"Error in SSH shell for {source_ip}: {e}")
        finally:
            chan.close()
            self.end_session(session_id)
            if session_id in self.session_dirs:
                del self.session_dirs[session_id]
    
    async def _process_command(self, command: str, session_id: str, source_ip: str) -> str:
        """Process SSH command"""
        try:
            # Update session data
            if session_id in self.active_sessions:
                self.active_sessions[session_id]["commands_count"] += 1
                self.active_sessions[session_id]["commands_executed"].append(command)
            
            # Log command
            await self.log_attack(
                source_ip, 
                0,
                payload=command,
                attack_type="ssh_command",
                session_id=session_id
            )
            
            # Get current directory
            current_dir = self.session_dirs.get(session_id, "/home/user")
            
            # Process common commands
            cmd_parts = command.split()
            if not cmd_parts:
                return ""
            
            cmd = cmd_parts[0].lower()
            
            if cmd == "ls":
                return self._handle_ls(current_dir, cmd_parts[1:] if len(cmd_parts) > 1 else [])
            elif cmd == "pwd":
                return current_dir
            elif cmd == "cd":
                target = cmd_parts[1] if len(cmd_parts) > 1 else "/home/user"
                return self._handle_cd(session_id, current_dir, target)
            elif cmd == "cat":
                if len(cmd_parts) > 1:
                    return self._handle_cat(current_dir, cmd_parts[1])
                return "cat: missing operand"
            elif cmd == "whoami":
                return "user"
            elif cmd == "ps":
                return "PID TTY          TIME CMD\n 1234 pts/0    00:00:01 bash\n 5678 pts/0    00:00:00 ps"
            elif cmd == "uname":
                return "Linux ubuntu 5.4.0-91-generic #102-Ubuntu SMP Wed Jan 20 02:56:02 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux"
            elif cmd in ["exit", "logout"]:
                return "logout"
            else:
                # Use LLM for unknown commands
                context = {
                    "service": "ssh",
                    "current_directory": current_dir,
                    "session_id": session_id
                }
                return await llm_service.generate_response(command, context)
        
        except Exception as e:
            logger.error(f"Error processing SSH command '{command}': {e}")
            return "bash: command not found"
    
    def _handle_ls(self, current_dir: str, args: list) -> str:
        """Handle ls command"""
        target_dir = current_dir
        
        if args and not args[0].startswith('-'):
            target_dir = args[0]
            if not target_dir.startswith('/'):
                target_dir = f"{current_dir.rstrip('/')}/{target_dir}"
        
        # Normalize path
        target_dir = target_dir.replace('//', '/')
        
        if target_dir in self.fake_filesystem:
            files = self.fake_filesystem[target_dir]
            return "  ".join(files)
        else:
            return f"ls: cannot access '{target_dir}': No such file or directory"
    
    def _handle_cd(self, session_id: str, current_dir: str, target: str) -> str:
        """Handle cd command"""
        if target == "..":
            if current_dir == "/":
                return ""
            new_dir = "/".join(current_dir.rstrip('/').split('/')[:-1]) or "/"
        elif target.startswith('/'):
            new_dir = target
        else:
            new_dir = f"{current_dir.rstrip('/')}/{target}"
        
        # Normalize path
        new_dir = new_dir.replace('//', '/')
        
        if new_dir in self.fake_filesystem:
            self.session_dirs[session_id] = new_dir
            return ""
        else:
            return f"bash: cd: {target}: No such file or directory"
    
    def _handle_cat(self, current_dir: str, filename: str) -> str:
        """Handle cat command"""
        if filename == "/etc/passwd":
            return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
user:x:1000:1000:User:/home/user:/bin/bash"""
        elif filename == "file1.txt":
            return "This is a sample file content."
        else:
            return f"cat: {filename}: No such file or directory"


class SSHServer(paramiko.ServerInterface):
    """SSH Server interface"""
    
    def __init__(self, honeypot, source_ip):
        self.honeypot = honeypot
        self.source_ip = source_ip
    
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_password(self, username, password):
        # Log authentication attempt
        asyncio.run(self.honeypot.log_attack(
            self.source_ip,
            0,
            payload=f"username: {username}, password: {password}",
            attack_type="ssh_auth_attempt",
            user_agent=f"SSH client - {username}"
        ))
        
        # Always allow authentication for honeypot purposes
        return paramiko.AUTH_SUCCESSFUL
    
    def check_auth_publickey(self, username, key):
        # Log public key auth attempt
        asyncio.run(self.honeypot.log_attack(
            self.source_ip,
            0,
            payload=f"username: {username}, key_type: {key.get_name()}",
            attack_type="ssh_pubkey_attempt",
            user_agent=f"SSH client - {username}"
        ))
        
        return paramiko.AUTH_SUCCESSFUL
    
    def get_allowed_auths(self, username):
        return 'password,publickey'
    
    def check_channel_shell_request(self, channel):
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True