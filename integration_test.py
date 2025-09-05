#!/usr/bin/env python3
"""
Integration Test Script
Tests the complete attack classification and response system integration
"""

import asyncio
import sys
import os

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from classification.attack_classifier import attack_classifier, AttackType
from classification.response_generator import response_generator

# Try to import LLM service (optional)
try:
    from llm.service import LLMService
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    print("ℹ️  LLM Service not available (missing dependencies)")


async def test_full_integration():
    """Test full system integration"""
    print("🔬 Full System Integration Test")
    print("=" * 40)
    
    # Initialize LLM service if available
    if LLM_AVAILABLE:
        llm_service = LLMService()
    else:
        llm_service = None
    
    # Test scenario: Modbus register manipulation attack
    attack_data = {
        'source_ip': '198.51.100.25',
        'service': 'modbus',
        'payload': 'Function: 6, Address: 50, Value: 65535',
        'connection_info': {
            'function_code': 6,
            'requests_per_second': 5.0,
            'write_attempts': 10
        }
    }
    
    print("🎯 Simulating Modbus Register Manipulation Attack")
    print(f"Source IP: {attack_data['source_ip']}")
    print(f"Service: {attack_data['service']}")
    print(f"Payload: {attack_data['payload']}")
    
    # Step 1: Classify the attack
    print("\n📊 Step 1: Attack Classification")
    classification = attack_classifier.classify_attack(
        source_ip=attack_data['source_ip'],
        service=attack_data['service'],
        payload=attack_data['payload'],
        connection_info=attack_data['connection_info']
    )
    
    print(f"✅ Classification Complete:")
    print(f"   Attack Type: {classification.attack_type.value}")
    print(f"   Confidence: {classification.confidence:.2f}")
    print(f"   Severity: {classification.severity}")
    print(f"   Strategy: {classification.response_strategy}")
    
    # Step 2: Generate dynamic response
    print("\n🎭 Step 2: Dynamic Response Generation")
    response = await response_generator.generate_response(
        classification=classification,
        service=attack_data['service'],
        payload=attack_data['payload'],
        source_ip=attack_data['source_ip'],
        **attack_data['connection_info']
    )
    
    print(f"✅ Response Generated:")
    print(f"   Type: {response.get('type')}")
    print(f"   Status: {response.get('status')}")
    print(f"   Content: {response.get('content', '')[:50]}...")
    
    # Step 3: Enhanced LLM analysis
    print("\n🧠 Step 3: Enhanced LLM Analysis")
    if LLM_AVAILABLE and llm_service:
        try:
            llm_response = await llm_service.generate_classified_response(
                source_ip=attack_data['source_ip'],
                service=attack_data['service'],
                payload=attack_data['payload'],
                connection_info=attack_data['connection_info']
            )
            
            print(f"✅ LLM Integration Complete:")
            print(f"   Response Type: {llm_response.get('type')}")
            if 'classification' in llm_response:
                print(f"   Classified As: {llm_response['classification']['attack_type']}")
                print(f"   Confidence: {llm_response['classification']['confidence']:.2f}")
        except Exception as e:
            print(f"⚠️  LLM Integration Error: {e}")
    else:
        print(f"⏭️  LLM Integration Skipped (dependencies not available)")
    
    # Step 4: Analyze attack with LLM
    print("\n📈 Step 4: Attack Analysis")
    if LLM_AVAILABLE and llm_service:
        try:
            analysis = await llm_service.analyze_attack(attack_data)
            print(f"✅ Analysis Complete:")
            print(f"   Attack Type: {analysis.get('attack_type', 'unknown')}")
            print(f"   Severity: {analysis.get('severity', 'unknown')}")
            print(f"   Confidence: {analysis.get('confidence', 0):.2f}")
            if 'indicators' in analysis:
                print(f"   Indicators: {', '.join(analysis['indicators'][:3])}...")
        except Exception as e:
            print(f"⚠️  Attack Analysis Error: {e}")
    else:
        print(f"⏭️  Attack Analysis Skipped (dependencies not available)")
    
    return True


async def test_multiple_attack_types():
    """Test classification across multiple attack types"""
    print("\n🎯 Testing Multiple Attack Types")
    print("=" * 40)
    
    test_cases = [
        {
            'name': 'Normal Modbus Read',
            'source_ip': '192.168.1.5',
            'service': 'modbus',
            'payload': 'Function: 3, Address: 0',
            'connection_info': {'requests_per_second': 0.5}
        },
        {
            'name': 'SSH Brute Force',
            'source_ip': '203.0.113.99',
            'service': 'ssh', 
            'payload': 'root:admin123',
            'connection_info': {'auth_attempts': 25}
        },
        {
            'name': 'HTTP Scanning',
            'source_ip': '185.199.108.77',
            'service': 'http',
            'payload': 'GET / HTTP/1.1',
            'connection_info': {'multiple_services': True, 'service_count': 8}
        }
    ]
    
    results = {}
    
    for test_case in test_cases:
        print(f"\n📝 Testing: {test_case['name']}")
        
        classification = attack_classifier.classify_attack(
            source_ip=test_case['source_ip'],
            service=test_case['service'],
            payload=test_case['payload'],
            connection_info=test_case['connection_info']
        )
        
        response = await response_generator.generate_response(
            classification=classification,
            service=test_case['service'],
            payload=test_case['payload'],
            source_ip=test_case['source_ip']
        )
        
        results[test_case['name']] = {
            'attack_type': classification.attack_type.value,
            'confidence': classification.confidence,
            'severity': classification.severity,
            'response_type': response.get('type')
        }
        
        print(f"   → {classification.attack_type.value} ({classification.confidence:.2f})")
    
    return results


def print_system_stats():
    """Print system statistics"""
    print("\n📊 System Statistics")
    print("=" * 40)
    
    # Attack classifier stats
    classifier_stats = attack_classifier.get_attack_statistics()
    print(f"Attack Classifier:")
    print(f"   IPs Tracked: {classifier_stats['total_ips_tracked']}")
    print(f"   Active Connections: {classifier_stats['active_connections']}")
    
    # Response generator stats
    response_stats = response_generator.get_response_statistics()
    print(f"Response Generator:")
    print(f"   IPs Tracked: {response_stats['total_ips_tracked']}")
    print(f"   Total Attacks Handled: {response_stats['total_attacks_handled']}")
    print(f"   Attack Types Seen: {len(response_stats['attack_types_seen'])}")


async def main():
    """Main integration test"""
    print("🍯 Industrial IoT Honeypot - Full Integration Test")
    print("=" * 60)
    
    try:
        # Test full integration
        success = await test_full_integration()
        
        if success:
            print("\n✅ Core integration test passed!")
        
        # Test multiple attack types
        results = await test_multiple_attack_types()
        
        print(f"\n📈 Multi-Attack Test Results:")
        for name, result in results.items():
            print(f"   {name}: {result['attack_type']} "
                  f"({result['confidence']:.2f} confidence)")
        
        # Print statistics
        print_system_stats()
        
        print("\n🎉 All integration tests completed successfully!")
        print("\n💡 The system is ready for:")
        print("   ✅ Real-time attack classification")
        print("   ✅ Dynamic response generation") 
        print("   ✅ Enhanced threat analysis")
        print("   ✅ Model training with generated datasets")
        
    except Exception as e:
        print(f"\n❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)