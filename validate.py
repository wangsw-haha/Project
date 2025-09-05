"""
Simple validation test for the honeypot system without external dependencies
"""

import os
import sys
import yaml


def test_project_structure():
    """Test that all necessary files exist"""
    required_files = [
        "src/main.py",
        "src/core/config.py",
        "src/core/honeypot.py",
        "src/honeypots/ssh.py",
        "src/honeypots/http.py",
        "src/honeypots/modbus.py",
        "src/database/models.py",
        "src/llm/service.py",
        "src/monitoring/metrics.py",
        "src/web/interface.py",
        "config/config.yaml",
        "requirements.txt",
        "Dockerfile",
        "docker-compose.yml",
        "scripts/install.sh",
        "scripts/honeypot.sh",
        "README.md"
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        return False
    else:
        print("✅ All required files present")
        return True


def test_config_file():
    """Test configuration file is valid YAML"""
    try:
        with open("config/config.yaml", 'r') as f:
            config = yaml.safe_load(f)
        
        required_sections = ['app', 'honeypots', 'database', 'llm']
        for section in required_sections:
            if section not in config:
                print(f"❌ Missing config section: {section}")
                return False
        
        print("✅ Configuration file is valid")
        return True
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False


def test_docker_compose():
    """Test Docker Compose file is valid YAML"""
    try:
        with open("docker-compose.yml", 'r') as f:
            compose = yaml.safe_load(f)
        
        if 'services' not in compose:
            print("❌ Docker Compose missing services section")
            return False
        
        required_services = ['honeypot', 'db', 'redis']
        for service in required_services:
            if service not in compose['services']:
                print(f"❌ Missing Docker service: {service}")
                return False
        
        print("✅ Docker Compose file is valid")
        return True
    except Exception as e:
        print(f"❌ Docker Compose error: {e}")
        return False


def test_python_syntax():
    """Test that Python files have valid syntax"""
    python_files = []
    for root, dirs, files in os.walk("src"):
        for file in files:
            if file.endswith(".py"):
                python_files.append(os.path.join(root, file))
    
    syntax_errors = []
    for file_path in python_files:
        try:
            with open(file_path, 'r') as f:
                compile(f.read(), file_path, 'exec')
        except SyntaxError as e:
            syntax_errors.append(f"{file_path}: {e}")
    
    if syntax_errors:
        print(f"❌ Python syntax errors: {syntax_errors}")
        return False
    else:
        print("✅ All Python files have valid syntax")
        return True


def test_executable_scripts():
    """Test that scripts are executable"""
    scripts = ["scripts/install.sh", "scripts/honeypot.sh"]
    
    non_executable = []
    for script in scripts:
        if not os.access(script, os.X_OK):
            non_executable.append(script)
    
    if non_executable:
        print(f"❌ Non-executable scripts: {non_executable}")
        return False
    else:
        print("✅ All scripts are executable")
        return True


def main():
    """Run all validation tests"""
    print("🍯 Industrial IoT Honeypot - Validation Test")
    print("=" * 50)
    
    tests = [
        test_project_structure,
        test_config_file,
        test_docker_compose,
        test_python_syntax,
        test_executable_scripts
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All validation tests passed!")
        print("The honeypot system is ready for deployment.")
        return 0
    else:
        print("❌ Some validation tests failed.")
        print("Please fix the issues before deployment.")
        return 1


if __name__ == "__main__":
    sys.exit(main())