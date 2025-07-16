#!/usr/bin/env python3
"""
Industrial IoT Honeypot System
Main entry point for the honeypot application
"""

import asyncio
import signal
import sys
import os
import threading
import uvicorn
from loguru import logger

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from src.core.config import config
from src.core.logger import setup_logging
from src.core.honeypot import honeypot_manager
from src.database.models import create_tables
from src.honeypots.ssh import SSHHoneypot
from src.honeypots.http import HTTPHoneypot
from src.honeypots.modbus import ModbusHoneypot
from src.honeypots.ftp import FTPHoneypot
from src.honeypots.telnet import TelnetHoneypot
from src.web.interface import web_interface


class HoneypotApplication:
    """Main honeypot application"""
    
    def __init__(self):
        self.running = False
        self.web_server_thread = None
        
    async def initialize(self):
        """Initialize the application"""
        logger.info("Initializing Industrial IoT Honeypot System...")
        
        # Create database tables
        try:
            create_tables()
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
            return False
        
        # Register honeypot services
        self._register_honeypots()
        
        logger.info("Application initialized successfully")
        return True
    
    def _register_honeypots(self):
        """Register all honeypot services"""
        
        # SSH Honeypot
        if config.honeypots.ssh.get("enabled", True):
            ssh_honeypot = SSHHoneypot(config.honeypots.ssh)
            honeypot_manager.register_honeypot(ssh_honeypot)
        
        # HTTP Honeypot
        if config.honeypots.http.get("enabled", True):
            http_honeypot = HTTPHoneypot(config.honeypots.http)
            honeypot_manager.register_honeypot(http_honeypot)
        
        # Modbus Honeypot
        if config.honeypots.modbus.get("enabled", True):
            modbus_honeypot = ModbusHoneypot(config.honeypots.modbus)
            honeypot_manager.register_honeypot(modbus_honeypot)
        
        # FTP Honeypot
        if config.honeypots.ftp.get("enabled", True):
            try:
                ftp_honeypot = FTPHoneypot(config.honeypots.ftp)
                honeypot_manager.register_honeypot(ftp_honeypot)
            except Exception as e:
                logger.warning(f"FTP Honeypot not available: {e}")
        
        # Telnet Honeypot
        if config.honeypots.telnet.get("enabled", True):
            try:
                telnet_honeypot = TelnetHoneypot(config.honeypots.telnet)
                honeypot_manager.register_honeypot(telnet_honeypot)
            except Exception as e:
                logger.warning(f"Telnet Honeypot not available: {e}")
    
    def start_web_interface(self):
        """Start web interface in a separate thread"""
        def run_web_server():
            try:
                uvicorn.run(
                    web_interface.app,
                    host=config.app.host,
                    port=config.app.port,
                    log_level="warning",
                    access_log=False
                )
            except Exception as e:
                logger.error(f"Error running web interface: {e}")
        
        self.web_server_thread = threading.Thread(target=run_web_server, daemon=True)
        self.web_server_thread.start()
        logger.info(f"Web interface started on http://{config.app.host}:{config.app.port}")
    
    async def start(self):
        """Start the honeypot system"""
        if not await self.initialize():
            logger.error("Failed to initialize application")
            return False
        
        self.running = True
        
        # Start web interface
        self.start_web_interface()
        
        # Wait a moment for web server to start
        await asyncio.sleep(2)
        
        logger.info("🍯 Industrial IoT Honeypot System Starting...")
        logger.info("=" * 50)
        logger.info(f"Web Dashboard: http://{config.app.host}:{config.app.port}")
        logger.info(f"Prometheus Metrics: http://{config.app.host}:9090/metrics")
        logger.info("=" * 50)
        
        # Start honeypot services
        try:
            await honeypot_manager.start_all()
        except Exception as e:
            logger.error(f"Error starting honeypot services: {e}")
            return False
        
        logger.info("🛡️ All honeypot services are running!")
        logger.info("Press Ctrl+C to stop the system")
        
        return True
    
    async def stop(self):
        """Stop the honeypot system"""
        logger.info("Stopping Industrial IoT Honeypot System...")
        
        self.running = False
        
        # Stop honeypot services
        await honeypot_manager.stop_all()
        
        logger.info("Honeypot system stopped")
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}")
            if self.running:
                # Create a new event loop for the shutdown coroutine
                asyncio.run(self.stop())
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)


async def main():
    """Main function"""
    # Setup logging
    setup_logging()
    
    # Create application
    app = HoneypotApplication()
    
    # Setup signal handlers
    app.setup_signal_handlers()
    
    # Start application
    success = await app.start()
    
    if not success:
        logger.error("Failed to start honeypot system")
        return 1
    
    # Keep running until stopped
    try:
        while app.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        await app.stop()
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)