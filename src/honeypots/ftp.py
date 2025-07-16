import asyncio
import socket
import threading
from typing import Dict, Any
from twisted.protocols.ftp import FTPFactory, FTPRealm
from twisted.internet import reactor, endpoints
from twisted.cred.portal import Portal
from twisted.cred.checkers import AllowAnonymousAccess
from loguru import logger
from src.core.honeypot import BaseHoneypot


class FTPHoneypot(BaseHoneypot):
    """FTP Honeypot implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("ftp", config.get("port", 21), config)
        self.factory = None
        self.server_thread = None
        
        # Fake filesystem
        self.fake_files = {
            "readme.txt": b"Welcome to the Industrial FTP Server\n",
            "config.ini": b"[settings]\nhost=192.168.1.100\nport=502\n",
            "backup.sql": b"-- Database backup\nCREATE TABLE users...\n",
            "data.csv": b"timestamp,temperature,pressure\n2024-01-01,25.5,1013\n"
        }
    
    async def start(self):
        """Start FTP honeypot"""
        try:
            def run_ftp_server():
                try:
                    # Create FTP factory with custom realm
                    realm = FTPRealm("/tmp", [])  # Anonymous access to /tmp
                    portal = Portal(realm, [AllowAnonymousAccess()])
                    factory = FTPFactory(portal)
                    
                    # Customize banner
                    factory.welcomeMessage = self.config.get("banner", "220 (vsFTPd 3.0.3)")
                    
                    # Listen on the configured port
                    endpoint = endpoints.TCP4ServerEndpoint(reactor, self.port)
                    endpoint.listen(factory)
                    
                    logger.info(f"FTP Honeypot listening on port {self.port}")
                    
                    # Override the factory's protocol to log connections
                    original_buildProtocol = factory.buildProtocol
                    
                    def logged_buildProtocol(addr):
                        # Log connection attempt
                        asyncio.run(self.log_attack(
                            addr.host,
                            addr.port,
                            attack_type="ftp_connection"
                        ))
                        return original_buildProtocol(addr)
                    
                    factory.buildProtocol = logged_buildProtocol
                    
                    reactor.run(installSignalHandlers=False)
                    
                except Exception as e:
                    logger.error(f"Error in FTP server: {e}")
            
            self.server_thread = threading.Thread(target=run_ftp_server, daemon=True)
            self.server_thread.start()
            
            # Wait a moment to ensure the server starts
            await asyncio.sleep(1)
            
        except Exception as e:
            logger.error(f"Error starting FTP honeypot: {e}")
    
    async def stop(self):
        """Stop FTP honeypot"""
        try:
            if reactor.running:
                reactor.callFromThread(reactor.stop)
        except Exception as e:
            logger.error(f"Error stopping FTP honeypot: {e}")
        
        logger.info("FTP Honeypot stopped")