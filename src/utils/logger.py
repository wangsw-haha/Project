"""
Logging utilities for the honeypot system.
"""

import logging
import logging.handlers
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from rich.console import Console
from rich.logging import RichHandler


class HoneypotLogger:
    """Enhanced logger for honeypot events."""
    
    def __init__(self, config):
        self.config = config
        self.console = Console()
        self.setup_logging()
        
    def setup_logging(self) -> None:
        """Set up logging configuration."""
        # Create logs directory
        log_file = Path(self.config.log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure root logger
        logger = logging.getLogger()
        logger.setLevel(getattr(logging, self.config.log_level))
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=100*1024*1024,  # 100MB
            backupCount=5,
            encoding='utf-8'
        )
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        # Console handler with Rich formatting
        if self.config.get('honeypot.logging.console', True):
            console_handler = RichHandler(console=self.console, rich_tracebacks=True)
            console_handler.setFormatter(logging.Formatter('%(message)s'))
            logger.addHandler(console_handler)
            
    def log_attack(self, attack_info: Dict[str, Any]) -> None:
        """Log attack event with detailed information."""
        attack_log = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'attack_detected',
            'attack_type': attack_info.get('type', 'unknown'),
            'source_ip': attack_info.get('source_ip'),
            'target_port': attack_info.get('target_port'),
            'protocol': attack_info.get('protocol'),
            'payload': attack_info.get('payload'),
            'user_agent': attack_info.get('user_agent'),
            'severity': attack_info.get('severity', 'medium'),
            'detection_method': attack_info.get('detection_method'),
            'response_sent': attack_info.get('response_sent', False),
            'response_type': attack_info.get('response_type')
        }
        
        logger = logging.getLogger('honeypot.attacks')
        logger.warning(f"ATTACK DETECTED: {json.dumps(attack_log, ensure_ascii=False)}")
        
    def log_connection(self, conn_info: Dict[str, Any]) -> None:
        """Log connection event."""
        conn_log = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'connection',
            'source_ip': conn_info.get('source_ip'),
            'target_port': conn_info.get('target_port'),
            'protocol': conn_info.get('protocol'),
            'status': conn_info.get('status', 'established'),
            'duration': conn_info.get('duration'),
            'bytes_sent': conn_info.get('bytes_sent', 0),
            'bytes_received': conn_info.get('bytes_received', 0)
        }
        
        logger = logging.getLogger('honeypot.connections')
        logger.info(f"CONNECTION: {json.dumps(conn_log, ensure_ascii=False)}")
        
    def log_response(self, response_info: Dict[str, Any]) -> None:
        """Log response event."""
        response_log = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'response_sent',
            'source_ip': response_info.get('source_ip'),
            'attack_type': response_info.get('attack_type'),
            'response_type': response_info.get('response_type'),
            'content_length': len(response_info.get('content', '')),
            'delay': response_info.get('delay', 0),
            'llm_generated': response_info.get('llm_generated', False)
        }
        
        logger = logging.getLogger('honeypot.responses')
        logger.info(f"RESPONSE: {json.dumps(response_log, ensure_ascii=False)}")
        
    def log_error(self, error_info: Dict[str, Any]) -> None:
        """Log error event."""
        logger = logging.getLogger('honeypot.errors')
        logger.error(f"ERROR: {json.dumps(error_info, ensure_ascii=False)}")
        
    def log_system(self, message: str, level: str = 'INFO') -> None:
        """Log system event."""
        logger = logging.getLogger('honeypot.system')
        log_level = getattr(logging, level.upper(), logging.INFO)
        logger.log(log_level, message)