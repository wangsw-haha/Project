#!/usr/bin/env python3
"""
Attack Dataset Generation Script
Generates comprehensive attack datasets for testing the classification system
"""

import json
import sys
import os
from datetime import datetime

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from classification.dataset_generator import AttackDatasetGenerator


def main():
    """Generate attack datasets"""
    print("🚀 Generating Attack Datasets for Industrial IoT Honeypot")
    print("=" * 60)
    
    generator = AttackDatasetGenerator()
    
    # Generate training dataset (larger)
    print("📊 Generating training dataset...")
    training_data = generator.generate_dataset(2000)
    
    # Generate testing dataset (smaller)  
    print("📊 Generating testing dataset...")
    testing_data = generator.generate_dataset(500)
    
    # Generate validation dataset
    print("📊 Generating validation dataset...")
    validation_data = generator.generate_dataset(300)
    
    # Create output directory
    output_dir = "/tmp/honeypot_datasets"
    os.makedirs(output_dir, exist_ok=True)
    
    # Save datasets
    training_file = os.path.join(output_dir, "attack_training_dataset.json")
    testing_file = os.path.join(output_dir, "attack_testing_dataset.json")
    validation_file = os.path.join(output_dir, "attack_validation_dataset.json")
    
    generator.save_dataset(training_data, training_file)
    generator.save_dataset(testing_data, testing_file)
    generator.save_dataset(validation_data, validation_file)
    
    print(f"\n✅ Datasets generated successfully!")
    print(f"📁 Training dataset: {training_file} ({len(training_data)} samples)")
    print(f"📁 Testing dataset: {testing_file} ({len(testing_data)} samples)")
    print(f"📁 Validation dataset: {validation_file} ({len(validation_data)} samples)")
    
    # Show distribution analysis
    from collections import Counter
    
    def analyze_dataset(data, name):
        print(f"\n📈 {name} Dataset Analysis:")
        print("-" * 30)
        
        labels = [sample['true_label'] for sample in data]
        distribution = Counter(labels)
        
        print("Attack Type Distribution:")
        for label, count in sorted(distribution.items()):
            percentage = (count / len(data)) * 100
            print(f"  {label:<25}: {count:4d} samples ({percentage:5.1f}%)")
        
        # Service distribution
        services = [sample['service'] for sample in data]
        service_dist = Counter(services)
        print("\nService Distribution:")
        for service, count in sorted(service_dist.items()):
            percentage = (count / len(data)) * 100
            print(f"  {service:<10}: {count:4d} samples ({percentage:5.1f}%)")
    
    analyze_dataset(training_data, "Training")
    analyze_dataset(testing_data, "Testing")
    
    # Generate sample CSV for analysis
    csv_file = os.path.join(output_dir, "attack_sample_analysis.csv")
    with open(csv_file, 'w', encoding='utf-8') as f:
        f.write("timestamp,source_ip,service,attack_type,payload_preview,severity\n")
        
        # Sample from training data
        for sample in training_data[:100]:  # First 100 samples
            payload_preview = sample['payload'].replace('\n', ' ').replace(',', ';')[:50]
            f.write(f"{sample['timestamp']},{sample['source_ip']},{sample['service']},"
                   f"{sample['true_label']},{payload_preview},unknown\n")
    
    print(f"📁 Sample CSV for analysis: {csv_file}")
    
    # Generate summary report
    report_file = os.path.join(output_dir, "dataset_report.txt")
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("Industrial IoT Honeypot - Attack Dataset Report\n")
        f.write("=" * 50 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("Dataset Overview:\n")
        f.write(f"- Training samples: {len(training_data)}\n")
        f.write(f"- Testing samples: {len(testing_data)}\n") 
        f.write(f"- Validation samples: {len(validation_data)}\n")
        f.write(f"- Total samples: {len(training_data) + len(testing_data) + len(validation_data)}\n\n")
        
        f.write("Attack Types (十大攻击类型):\n")
        f.write("1. normal_traffic (正常流量)\n")
        f.write("2. modbus_flood (Modbus洪水攻击)\n")
        f.write("3. register_manipulation (寄存器操控)\n")
        f.write("4. protocol_anomaly (协议异常)\n")
        f.write("5. dos_attack (拒绝服务攻击)\n")
        f.write("6. mitm_attack (中间人攻击)\n") 
        f.write("7. scan_attack (扫描攻击)\n")
        f.write("8. brute_force (暴力破解)\n")
        f.write("9. malformed_packet (畸形数据包)\n")
        f.write("10. unknown_attack (未知攻击)\n\n")
        
        f.write("Usage Instructions:\n")
        f.write("1. Use training dataset for model training\n")
        f.write("2. Use testing dataset for performance evaluation\n")
        f.write("3. Use validation dataset for hyperparameter tuning\n")
        f.write("4. Each sample contains: source_ip, service, payload, connection_info, true_label\n")
        f.write("5. Timestamps are realistic and span the last 30 days\n\n")
        
        f.write("File Formats:\n")
        f.write("- JSON: Complete structured data with all fields\n")
        f.write("- CSV: Simplified format for quick analysis\n")
    
    print(f"📁 Dataset report: {report_file}")
    print(f"\n🎯 Ready for model training and testing!")
    print("\n💡 You can now use these datasets to:")
    print("   - Train machine learning models")
    print("   - Test attack classification accuracy")
    print("   - Validate dynamic response generation")
    print("   - Analyze attack patterns and trends")


if __name__ == "__main__":
    main()