"""
Core honeypot implementation.
"""

import asyncio
import signal
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

from utils import Config, HoneypotLogger
from llm import LLMClient
from core.attack_detector import AttackDetector
from core.response_engine import ResponseEngine


class IndustrialHoneypot:
    """Main honeypot orchestrator."""
    
    def __init__(self, config_path: str = "config/honeypot.yaml"):
        # Initialize configuration
        self.config = Config(config_path)
        
        # Initialize logging
        self.logger_manager = HoneypotLogger(self.config)
        self.logger = logging.getLogger('honeypot.core')
        
        # Initialize components
        self.llm_client = LLMClient(self.config)
        self.attack_detector = AttackDetector(self.config)
        self.response_engine = ResponseEngine(self.config, self.llm_client)
        
        # Server instances
        self.servers = {}
        self.running = False
        
        # Statistics
        self.stats = {
            'connections': 0,
            'attacks_detected': 0,
            'responses_sent': 0,
            'start_time': None
        }
        
    async def start(self) -> None:
        """Start the honeypot system."""
        self.logger.info("Starting Industrial Honeypot System...")
        
        try:
            # Start all configured services
            await self._start_services()
            
            # Setup signal handlers
            self._setup_signal_handlers()
            
            self.running = True
            self.stats['start_time'] = asyncio.get_event_loop().time()
            
            self.logger.info("Honeypot system started successfully")
            self.logger.info(f"Listening on {self.config.bind_ip}:{list(self.config.ports.values())}")
            
            # Keep running until stopped
            await self._run_forever()
            
        except Exception as e:
            self.logger.error(f"Failed to start honeypot: {e}")
            await self.stop()
            raise
            
    async def stop(self) -> None:
        """Stop the honeypot system."""
        self.logger.info("Stopping honeypot system...")
        
        self.running = False
        
        # Stop all servers
        for service_name, server in self.servers.items():
            try:
                server.close()
                await server.wait_closed()
                self.logger.info(f"Stopped {service_name} service")
            except Exception as e:
                self.logger.error(f"Error stopping {service_name}: {e}")
                
        self.logger.info("Honeypot system stopped")
        
    async def _start_services(self) -> None:
        """Start all configured network services."""
        ports = self.config.ports
        bind_ip = self.config.bind_ip
        
        # Import protocol handlers
        from protocols import HTTPHandler, SSHHandler, TelnetHandler, ModbusHandler
        
        # Start HTTP service
        if 'http' in ports:
            handler = HTTPHandler(self.config, self.attack_detector, self.response_engine, self.logger_manager)
            server = await asyncio.start_server(
                handler.handle_connection,
                bind_ip,
                ports['http']
            )
            self.servers['http'] = server
            self.logger.info(f"HTTP service started on {bind_ip}:{ports['http']}")
            
        # Start SSH service
        if 'ssh' in ports:
            handler = SSHHandler(self.config, self.attack_detector, self.response_engine, self.logger_manager)
            server = await asyncio.start_server(
                handler.handle_connection,
                bind_ip,
                ports['ssh']
            )
            self.servers['ssh'] = server
            self.logger.info(f"SSH service started on {bind_ip}:{ports['ssh']}")
            
        # Start Telnet service
        if 'telnet' in ports:
            handler = TelnetHandler(self.config, self.attack_detector, self.response_engine, self.logger_manager)
            server = await asyncio.start_server(
                handler.handle_connection,
                bind_ip,
                ports['telnet']
            )
            self.servers['telnet'] = server
            self.logger.info(f"Telnet service started on {bind_ip}:{ports['telnet']}")
            
        # Start Modbus service
        if 'modbus' in ports:
            handler = ModbusHandler(self.config, self.attack_detector, self.response_engine, self.logger_manager)
            server = await asyncio.start_server(
                handler.handle_connection,
                bind_ip,
                ports['modbus']
            )
            self.servers['modbus'] = server
            self.logger.info(f"Modbus service started on {bind_ip}:{ports['modbus']}")
            
    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating shutdown...")
            asyncio.create_task(self.stop())
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
    async def _run_forever(self) -> None:
        """Keep the honeypot running."""
        try:
            while self.running:
                await asyncio.sleep(1)
                
                # Periodic tasks
                await self._periodic_tasks()
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}")
            
    async def _periodic_tasks(self) -> None:
        """Perform periodic maintenance tasks."""
        # Log statistics every 5 minutes
        current_time = asyncio.get_event_loop().time()
        if hasattr(self, '_last_stats_log'):
            if current_time - self._last_stats_log > 300:  # 5 minutes
                await self._log_statistics()
                self._last_stats_log = current_time
        else:
            self._last_stats_log = current_time
            
        # Analyze attack patterns every hour
        if hasattr(self, '_last_pattern_analysis'):
            if current_time - self._last_pattern_analysis > 3600:  # 1 hour
                await self._analyze_attack_patterns()
                self._last_pattern_analysis = current_time
        else:
            self._last_pattern_analysis = current_time
            
    async def _log_statistics(self) -> None:
        """Log system statistics."""
        stats = self.get_statistics()
        self.logger.info(f"Honeypot Statistics: {stats}")
        
    async def _analyze_attack_patterns(self) -> None:
        """Analyze recent attack patterns."""
        recent_attacks = self.attack_detector.get_recent_attacks(60)
        if recent_attacks and self.llm_client:
            analysis = await self.llm_client.analyze_attack_pattern(recent_attacks)
            if analysis:
                self.logger.info(f"Attack Pattern Analysis: {analysis}")
                
    def get_statistics(self) -> Dict[str, Any]:
        """Get current system statistics."""
        detector_stats = self.attack_detector.get_attack_stats()
        
        runtime = 0
        if self.stats['start_time']:
            runtime = asyncio.get_event_loop().time() - self.stats['start_time']
            
        return {
            'runtime_seconds': runtime,
            'active_services': len(self.servers),
            'total_connections': self.stats['connections'],
            'attacks_detected': detector_stats.get('total_attacks', 0),
            'recent_attacks': detector_stats.get('recent_attacks', 0),
            'responses_sent': self.stats['responses_sent'],
            'unique_attackers': detector_stats.get('unique_ips', 0),
            'attack_types': detector_stats.get('attack_types', {}),
            'most_targeted_port': detector_stats.get('most_targeted_port', 0)
        }
        
    async def handle_attack(self, attack_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle detected attack and generate response."""
        try:
            # Log the attack
            self.logger_manager.log_attack(attack_info)
            self.stats['attacks_detected'] += 1
            
            # Generate response
            response = await self.response_engine.generate_response(attack_info)
            
            if response:
                # Log the response
                response_info = {
                    'source_ip': attack_info.get('source_ip'),
                    'attack_type': attack_info.get('type'),
                    'response_type': response.get('type'),
                    'content': response.get('content', ''),
                    'delay': response.get('delay', 0),
                    'llm_generated': response.get('llm_generated', False)
                }
                self.logger_manager.log_response(response_info)
                self.stats['responses_sent'] += 1
                
            return response
            
        except Exception as e:
            self.logger.error(f"Error handling attack: {e}")
            return None