#!/usr/bin/env python3
"""
Test script to demonstrate the attack classification and dynamic response system
"""

import asyncio
import json
import sys
import os

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.classification.attack_classifier import attack_classifier, AttackType
from src.classification.response_generator import response_generator
from src.classification.dataset_generator import AttackDatasetGenerator


async def test_attack_classification():
    """Test the attack classification system"""
    print("🔍 Testing Attack Classification System")
    print("=" * 50)
    
    # Test scenarios
    test_scenarios = [
        {
            'name': 'Normal Modbus Traffic',
            'source_ip': '192.168.1.10',
            'service': 'modbus',
            'payload': 'Function: 3, Address: 0, Count: 4',
            'connection_info': {'requests_per_second': 1.0}
        },
        {
            'name': 'Modbus Flood Attack',
            'source_ip': '203.0.113.15',
            'service': 'modbus', 
            'payload': 'Function: 3, Rapid requests',
            'connection_info': {'requests_per_second': 50.0}
        },
        {
            'name': 'Register Manipulation',
            'source_ip': '45.32.123.45',
            'service': 'modbus',
            'payload': 'Function: 6, Address: 10, Value: 9999',
            'connection_info': {'function_code': 6, 'write_attempts': 20}
        },
        {
            'name': 'SSH Brute Force',
            'source_ip': '185.199.108.153',
            'service': 'ssh',
            'payload': 'admin:password123',
            'connection_info': {'auth_attempts': 15}
        },
        {
            'name': 'Port Scanning',
            'source_ip': '104.16.249.249',
            'service': 'ssh',
            'payload': 'SSH version probe',
            'connection_info': {'multiple_services': True, 'service_count': 10}
        },
        {
            'name': 'Malformed HTTP',
            'source_ip': '8.8.8.8',
            'service': 'http',
            'payload': 'INVALID_METHOD /test HTTP/1.1\r\nContent-Length: -1',
            'connection_info': {'malformed_headers': True}
        }
    ]
    
    results = []
    
    for scenario in test_scenarios:
        print(f"\n📊 Testing: {scenario['name']}")
        print("-" * 30)
        
        # Classify the attack
        classification = attack_classifier.classify_attack(
            source_ip=scenario['source_ip'],
            service=scenario['service'],
            payload=scenario['payload'],
            connection_info=scenario['connection_info']
        )
        
        # Generate dynamic response
        response = await response_generator.generate_response(
            classification=classification,
            service=scenario['service'],
            payload=scenario['payload'],
            source_ip=scenario['source_ip'],
            **scenario['connection_info']
        )
        
        # Display results
        print(f"Attack Type: {classification.attack_type.value}")
        print(f"Confidence: {classification.confidence:.2f}")
        print(f"Severity: {classification.severity}")
        print(f"Description: {classification.description}")
        print(f"Indicators: {', '.join(classification.indicators)}")
        print(f"Response Strategy: {classification.response_strategy}")
        print(f"Response Type: {response.get('type', 'unknown')}")
        print(f"Response Status: {response.get('status', 'unknown')}")
        
        # Store for summary
        results.append({
            'scenario': scenario['name'],
            'classification': classification.attack_type.value,
            'confidence': classification.confidence,
            'severity': classification.severity
        })
    
    # Summary
    print("\n📈 Classification Summary")
    print("=" * 50)
    attack_type_counts = {}
    severity_counts = {}
    
    for result in results:
        attack_type = result['classification']
        severity = result['severity']
        
        attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print("Attack Types Detected:")
    for attack_type, count in attack_type_counts.items():
        print(f"  {attack_type}: {count}")
    
    print("\nSeverity Distribution:")
    for severity, count in severity_counts.items():
        print(f"  {severity}: {count}")


async def test_dataset_generation():
    """Test the dataset generation"""
    print("\n📊 Testing Dataset Generation")
    print("=" * 50)
    
    generator = AttackDatasetGenerator()
    
    # Generate a small dataset
    dataset = generator.generate_dataset(100)
    
    print(f"Generated {len(dataset)} attack samples")
    
    # Show distribution
    from collections import Counter
    labels = [sample['true_label'] for sample in dataset]
    distribution = Counter(labels)
    
    print("\nDataset Distribution:")
    for label, count in distribution.items():
        percentage = (count / len(dataset)) * 100
        print(f"  {label}: {count} samples ({percentage:.1f}%)")
    
    # Show sample data
    print("\nSample Attack Data:")
    for i, sample in enumerate(dataset[:3]):
        print(f"\nSample {i+1}:")
        print(f"  Label: {sample['true_label']}")
        print(f"  Source IP: {sample['source_ip']}")
        print(f"  Service: {sample['service']}")
        print(f"  Payload: {sample['payload'][:50]}...")
    
    # Save dataset
    output_file = '/tmp/test_attack_dataset.json'
    generator.save_dataset(dataset, output_file)
    print(f"\nDataset saved to: {output_file}")


def test_response_matching():
    """Test response type matching"""
    print("\n🎯 Testing Response Type Matching")
    print("=" * 50)
    
    # Test all attack types have response templates
    from src.classification.response_generator import DynamicResponseGenerator
    
    generator = DynamicResponseGenerator()
    
    missing_templates = []
    for attack_type in AttackType:
        if attack_type not in generator.response_templates:
            missing_templates.append(attack_type.value)
    
    if missing_templates:
        print(f"❌ Missing response templates for: {', '.join(missing_templates)}")
    else:
        print("✅ All attack types have response templates")
    
    # Test response statistics
    stats = generator.get_response_statistics()
    print(f"\nResponse Statistics:")
    print(f"  Total IPs tracked: {stats['total_ips_tracked']}")
    print(f"  Attack types seen: {len(stats['attack_types_seen'])}")
    print(f"  Total attacks handled: {stats['total_attacks_handled']}")


async def main():
    """Main test function"""
    print("🍯 Industrial IoT Honeypot - Attack Classification System Test")
    print("=" * 70)
    
    try:
        # Test attack classification
        await test_attack_classification()
        
        # Test dataset generation
        await test_dataset_generation()
        
        # Test response matching
        test_response_matching()
        
        print("\n✅ All tests completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())