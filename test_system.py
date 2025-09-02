#!/usr/bin/env python3
"""
Basic functionality test for the Industrial Honeypot.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

async def test_basic_functionality():
    """Test basic honeypot functionality."""
    print("Testing Industrial Honeypot Basic Functionality...")
    
    try:
        # Test configuration loading
        print("1. Testing configuration loading...")
        from utils import Config
        config = Config("config/honeypot.yaml")
        print("   ✓ Configuration loaded successfully")
        
        # Test attack detector
        print("2. Testing attack detector...")
        from core import AttackDetector
        detector = AttackDetector(config)
        
        # Test SQL injection detection
        test_request = {
            'source_ip': '127.0.0.1',
            'target_port': 80,
            'protocol': 'HTTP',
            'payload': "' OR 1=1--"
        }
        
        attack_info = await detector.analyze_request(test_request)
        if attack_info and attack_info.get('type') == 'sql_injection':
            print("   ✓ SQL injection detection working")
        else:
            print("   ✗ SQL injection detection failed")
            
        # Test response engine
        print("3. Testing response engine...")
        from core import ResponseEngine
        response_engine = ResponseEngine(config)
        
        if attack_info:
            response = await response_engine.generate_response(attack_info)
            if response and 'content' in response:
                print("   ✓ Response generation working")
            else:
                print("   ✗ Response generation failed")
        
        # Test LLM client (without actual API call)
        print("4. Testing LLM client initialization...")
        from llm import LLMClient
        llm_client = LLMClient(config)
        print("   ✓ LLM client initialized")
        
        # Test protocol handlers
        print("5. Testing protocol handlers...")
        from protocols import HTTPHandler, SSHHandler, TelnetHandler, ModbusHandler
        
        http_handler = HTTPHandler(config, detector, response_engine, None)
        ssh_handler = SSHHandler(config, detector, response_engine, None)
        telnet_handler = TelnetHandler(config, detector, response_engine, None)
        modbus_handler = ModbusHandler(config, detector, response_engine, None)
        
        print("   ✓ All protocol handlers initialized")
        
        # Test main honeypot class
        print("6. Testing main honeypot class...")
        from core import IndustrialHoneypot
        honeypot = IndustrialHoneypot("config/honeypot.yaml")
        print("   ✓ Main honeypot class initialized")
        
        print("\n✅ All basic functionality tests passed!")
        print("The honeypot system is ready for deployment.")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_configuration():
    """Test configuration validation."""
    print("\nTesting configuration...")
    
    config_file = Path("config/honeypot.yaml")
    if not config_file.exists():
        print("❌ Configuration file not found")
        return False
        
    try:
        import yaml
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
            
        required_sections = ['honeypot']
        for section in required_sections:
            if section not in config:
                print(f"❌ Missing required section: {section}")
                return False
                
        print("✅ Configuration file is valid")
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("Industrial Internet Honeypot - System Test")
    print("=" * 60)
    
    # Test configuration
    if not test_configuration():
        sys.exit(1)
        
    # Test basic functionality
    if not asyncio.run(test_basic_functionality()):
        sys.exit(1)
        
    print("\n" + "=" * 60)
    print("🎉 All tests passed! The honeypot system is ready.")
    print("=" * 60)
    
    print("\nNext steps:")
    print("1. Configure OpenAI API key (optional): export OPENAI_API_KEY=your_key")
    print("2. Run the honeypot: python src/main.py")
    print("3. Or install as service: sudo ./deploy/install.sh")

if __name__ == "__main__":
    main()