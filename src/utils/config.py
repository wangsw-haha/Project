"""
Configuration management for the honeypot system.
"""

import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path


class Config:
    """Configuration manager for the honeypot system."""
    
    def __init__(self, config_path: str = "config/honeypot.yaml"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.responses: Dict[str, Any] = {}
        self.load_config()
        
    def load_config(self) -> None:
        """Load configuration from YAML files."""
        try:
            # Load main configuration
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self.config = yaml.safe_load(f)
            else:
                raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
                
            # Load response templates
            responses_path = self.config_path.parent / "responses.yaml"
            if responses_path.exists():
                with open(responses_path, 'r', encoding='utf-8') as f:
                    self.responses = yaml.safe_load(f)
                    
        except Exception as e:
            raise ValueError(f"Failed to load configuration: {e}")
            
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation."""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
            
    def get_responses(self, attack_type: str) -> list:
        """Get response templates for specific attack type."""
        return self.responses.get('responses', {}).get(attack_type, 
                                                      self.responses.get('responses', {}).get('default', []))
                                                      
    def get_prompt_template(self, template_name: str) -> str:
        """Get LLM prompt template."""
        return self.responses.get('prompts', {}).get(template_name, "")
        
    def get_env_var(self, key: str, default: str = "") -> str:
        """Get environment variable with fallback."""
        return os.getenv(key, default)
        
    @property
    def llm_api_key(self) -> str:
        """Get LLM API key from environment."""
        key_env = self.get('honeypot.llm.api_key_env', 'OPENAI_API_KEY')
        return self.get_env_var(key_env)
        
    @property
    def bind_ip(self) -> str:
        """Get bind IP address."""
        return self.get('honeypot.network.bind_ip', '0.0.0.0')
        
    @property
    def ports(self) -> Dict[str, int]:
        """Get port configuration."""
        return self.get('honeypot.network.ports', {})
        
    @property
    def log_level(self) -> str:
        """Get logging level."""
        return self.get('honeypot.logging.level', 'INFO')
        
    @property
    def log_file(self) -> str:
        """Get log file path."""
        return self.get('honeypot.logging.file', 'logs/honeypot.log')