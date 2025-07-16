"""
Test suite for the Industrial IoT Honeypot System
"""

import pytest
import asyncio
import tempfile
import os
from unittest.mock import Mock, patch

# Add src to path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.config import Config
from core.honeypot import BaseHoneypot, HoneypotManager
from honeypots.ssh import SSHHoneypot
from honeypots.http import HTTPHoneypot
from honeypots.modbus import ModbusHoneypot
from llm.service import LLMService


class TestConfig:
    """Test configuration management"""
    
    def test_config_loading(self):
        """Test configuration loading"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
app:
  name: "Test Honeypot"
  port: 9000

honeypots:
  ssh:
    enabled: true
    port: 2223
""")
            config_path = f.name
        
        try:
            config = Config(config_path)
            assert config.app.name == "Test Honeypot"
            assert config.app.port == 9000
            assert config.honeypots.ssh["enabled"] is True
            assert config.honeypots.ssh["port"] == 2223
        finally:
            os.unlink(config_path)
    
    def test_config_defaults(self):
        """Test default configuration values"""
        config = Config("/nonexistent/path")
        assert config.app.name == "Industrial IoT Honeypot"
        assert config.app.port == 8000


class TestHoneypotBase:
    """Test base honeypot functionality"""
    
    def test_base_honeypot_creation(self):
        """Test base honeypot initialization"""
        config = {"port": 1234, "enabled": True}
        
        class TestHoneypot(BaseHoneypot):
            async def start(self):
                pass
            
            async def stop(self):
                pass
        
        honeypot = TestHoneypot("test", 1234, config)
        assert honeypot.name == "test"
        assert honeypot.port == 1234
        assert honeypot.config == config
        assert len(honeypot.active_sessions) == 0
    
    def test_session_management(self):
        """Test session creation and management"""
        config = {"port": 1234}
        
        class TestHoneypot(BaseHoneypot):
            async def start(self):
                pass
            
            async def stop(self):
                pass
        
        honeypot = TestHoneypot("test", 1234, config)
        
        # Create session
        session_id = honeypot.create_session("192.168.1.100")
        assert session_id in honeypot.active_sessions
        assert honeypot.active_sessions[session_id]["source_ip"] == "192.168.1.100"
        
        # End session
        honeypot.end_session(session_id)
        assert session_id not in honeypot.active_sessions


class TestHoneypotManager:
    """Test honeypot manager"""
    
    def test_honeypot_registration(self):
        """Test honeypot registration"""
        manager = HoneypotManager()
        
        class TestHoneypot(BaseHoneypot):
            async def start(self):
                pass
            
            async def stop(self):
                pass
        
        honeypot = TestHoneypot("test", 1234, {})
        manager.register_honeypot(honeypot)
        
        assert "test" in manager.honeypots
        assert manager.honeypots["test"] == honeypot
    
    def test_status_reporting(self):
        """Test status reporting"""
        manager = HoneypotManager()
        
        class TestHoneypot(BaseHoneypot):
            async def start(self):
                pass
            
            async def stop(self):
                pass
        
        honeypot = TestHoneypot("test", 1234, {"enabled": True})
        manager.register_honeypot(honeypot)
        
        status = manager.get_status()
        assert "running" in status
        assert "services" in status
        assert "test" in status["services"]
        assert status["services"]["test"]["port"] == 1234
        assert status["services"]["test"]["enabled"] is True


class TestSSHHoneypot:
    """Test SSH honeypot"""
    
    def test_ssh_honeypot_creation(self):
        """Test SSH honeypot initialization"""
        config = {
            "port": 2222,
            "enabled": True,
            "banner": "SSH-2.0-Test"
        }
        
        ssh_honeypot = SSHHoneypot(config)
        assert ssh_honeypot.name == "ssh"
        assert ssh_honeypot.port == 2222
        assert "/" in ssh_honeypot.fake_filesystem
        assert "/home" in ssh_honeypot.fake_filesystem
    
    @pytest.mark.asyncio
    async def test_ssh_command_processing(self):
        """Test SSH command processing"""
        config = {"port": 2222}
        ssh_honeypot = SSHHoneypot(config)
        
        # Create a mock session
        session_id = "test-session"
        ssh_honeypot.active_sessions[session_id] = {
            "commands_count": 0,
            "commands_executed": []
        }
        ssh_honeypot.session_dirs[session_id] = "/home/user"
        
        # Mock the log_attack method
        ssh_honeypot.log_attack = Mock()
        
        # Test ls command
        response = await ssh_honeypot._process_command("ls", session_id, "192.168.1.1")
        assert "documents" in response or "downloads" in response
        
        # Test pwd command
        response = await ssh_honeypot._process_command("pwd", session_id, "192.168.1.1")
        assert response == "/home/user"
        
        # Test whoami command
        response = await ssh_honeypot._process_command("whoami", session_id, "192.168.1.1")
        assert response == "user"


class TestHTTPHoneypot:
    """Test HTTP honeypot"""
    
    def test_http_honeypot_creation(self):
        """Test HTTP honeypot initialization"""
        config = {
            "port": 8080,
            "enabled": True,
            "server_header": "Apache/2.4.41"
        }
        
        http_honeypot = HTTPHoneypot(config)
        assert http_honeypot.name == "http"
        assert http_honeypot.port == 8080
        assert "/" in http_honeypot.fake_pages
        assert "/admin" in http_honeypot.fake_pages


class TestModbusHoneypot:
    """Test Modbus honeypot"""
    
    def test_modbus_honeypot_creation(self):
        """Test Modbus honeypot initialization"""
        config = {
            "port": 502,
            "enabled": True,
            "device_name": "Test PLC"
        }
        
        modbus_honeypot = ModbusHoneypot(config)
        assert modbus_honeypot.name == "modbus"
        assert modbus_honeypot.port == 502
        assert len(modbus_honeypot.coils) == 1000
        assert len(modbus_honeypot.holding_registers) == 1000
    
    def test_modbus_data_initialization(self):
        """Test Modbus data initialization"""
        config = {"port": 502}
        modbus_honeypot = ModbusHoneypot(config)
        
        # Check that some fake data is initialized
        assert any(reg > 0 for reg in modbus_honeypot.input_registers[:20])
        assert any(reg > 0 for reg in modbus_honeypot.holding_registers[:10])


class TestLLMService:
    """Test LLM service"""
    
    def test_llm_service_initialization(self):
        """Test LLM service initialization"""
        llm_service = LLMService()
        assert llm_service.provider is not None
    
    @pytest.mark.asyncio
    async def test_llm_response_generation(self):
        """Test LLM response generation"""
        llm_service = LLMService()
        
        # Test with a simple command
        response = await llm_service.generate_response("ls", {"service": "ssh"})
        assert isinstance(response, str)
        assert len(response) > 0
    
    @pytest.mark.asyncio
    async def test_llm_attack_analysis(self):
        """Test LLM attack analysis"""
        llm_service = LLMService()
        
        attack_data = {
            "source_ip": "192.168.1.100",
            "service": "ssh",
            "payload": "rm -rf /",
            "attack_type": "command_injection"
        }
        
        analysis = await llm_service.analyze_attack(attack_data)
        assert "analysis" in analysis
        assert "severity" in analysis
        assert "confidence" in analysis


class TestIntegration:
    """Integration tests"""
    
    @pytest.mark.asyncio
    async def test_honeypot_manager_lifecycle(self):
        """Test complete honeypot manager lifecycle"""
        manager = HoneypotManager()
        
        # Mock honeypots to avoid actual network binding
        class MockHoneypot(BaseHoneypot):
            def __init__(self, name, port):
                super().__init__(name, port, {"enabled": True})
                self.started = False
                self.stopped = False
            
            async def start(self):
                self.started = True
            
            async def stop(self):
                self.stopped = True
        
        # Register mock honeypots
        ssh_honeypot = MockHoneypot("ssh", 2222)
        http_honeypot = MockHoneypot("http", 8080)
        
        manager.register_honeypot(ssh_honeypot)
        manager.register_honeypot(http_honeypot)
        
        # Test starting
        await manager.start_all()
        assert ssh_honeypot.started
        assert http_honeypot.started
        assert manager.running
        
        # Test stopping
        await manager.stop_all()
        assert ssh_honeypot.stopped
        assert http_honeypot.stopped
        assert not manager.running


if __name__ == "__main__":
    pytest.main([__file__])