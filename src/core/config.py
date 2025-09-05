import yaml
import os
from typing import Dict, Any
from pydantic import BaseSettings, Field
from pathlib import Path


class AppConfig(BaseSettings):
    """Application configuration"""
    name: str = "Industrial IoT Honeypot"
    version: str = "1.0.0"
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False


class DatabaseConfig(BaseSettings):
    """Database configuration"""
    url: str = Field(default="postgresql://honeypot:honeypot123@localhost:5432/honeypot_db")
    echo: bool = False
    pool_size: int = 10
    max_overflow: int = 20

    class Config:
        env_prefix = "DATABASE_"


class RedisConfig(BaseSettings):
    """Redis configuration"""
    url: str = Field(default="redis://localhost:6379/0")

    class Config:
        env_prefix = "REDIS_"


class LLMConfig(BaseSettings):
    """LLM configuration"""
    provider: str = "openai"
    model: str = "gpt-3.5-turbo"
    api_key: str = Field(default="", env="OPENAI_API_KEY")
    max_tokens: int = 500
    temperature: float = 0.7
    local_model_path: str = "./models/llm"
    device: str = "cpu"

    class Config:
        env_prefix = "LLM_"


class HoneypotConfig:
    """Honeypot services configuration"""
    def __init__(self, config_dict: Dict[str, Any]):
        self.ssh = config_dict.get("ssh", {})
        self.http = config_dict.get("http", {})
        self.modbus = config_dict.get("modbus", {})
        self.ftp = config_dict.get("ftp", {})
        self.telnet = config_dict.get("telnet", {})
        self.snmp = config_dict.get("snmp", {})


class MonitoringConfig:
    """Monitoring configuration"""
    def __init__(self, config_dict: Dict[str, Any]):
        self.prometheus = config_dict.get("prometheus", {})
        self.elasticsearch = config_dict.get("elasticsearch", {})


class SecurityConfig:
    """Security configuration"""
    def __init__(self, config_dict: Dict[str, Any]):
        self.rate_limiting = config_dict.get("rate_limiting", {})
        self.geolocation = config_dict.get("geolocation", {})
        self.threat_intelligence = config_dict.get("threat_intelligence", {})


class AlertingConfig:
    """Alerting configuration"""
    def __init__(self, config_dict: Dict[str, Any]):
        self.email = config_dict.get("email", {})
        self.webhook = config_dict.get("webhook", {})
        self.slack = config_dict.get("slack", {})


class LoggingConfig:
    """Logging configuration"""
    def __init__(self, config_dict: Dict[str, Any]):
        self.level = config_dict.get("level", "INFO")
        self.file = config_dict.get("file", "./logs/honeypot.log")
        self.max_size = config_dict.get("max_size", "100MB")
        self.backup_count = config_dict.get("backup_count", 5)
        self.format = config_dict.get("format", "{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}")


class Config:
    """Main configuration class"""
    
    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = os.path.join(Path(__file__).parent.parent, "config", "config.yaml")
        
        self.config_path = config_path
        self._load_config()
        
    def _load_config(self):
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Configuration file {self.config_path} not found. Using defaults.")
            config_data = {}
        except yaml.YAMLError as e:
            print(f"Error parsing configuration file: {e}. Using defaults.")
            config_data = {}
        
        # Initialize configuration sections
        self.app = AppConfig(**config_data.get("app", {}))
        self.database = DatabaseConfig()
        self.redis = RedisConfig()
        self.llm = LLMConfig()
        self.honeypots = HoneypotConfig(config_data.get("honeypots", {}))
        self.monitoring = MonitoringConfig(config_data.get("monitoring", {}))
        self.security = SecurityConfig(config_data.get("security", {}))
        self.alerting = AlertingConfig(config_data.get("alerting", {}))
        self.logging = LoggingConfig(config_data.get("logging", {}))
    
    def reload(self):
        """Reload configuration from file"""
        self._load_config()


# Global configuration instance
config = Config()