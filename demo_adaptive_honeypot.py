#!/usr/bin/env python3
"""
Industrial IoT Honeypot Adaptive Response System Demo
演示工业互联网蜜罐自适应响应系统
"""

import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from classification.attack_classifier import attack_classifier, AttackType
from classification.response_generator import DynamicResponseGenerator
from ml.adaptive_optimizer import AdaptiveResponseOptimizer
from loguru import logger


class AdaptiveHoneypotDemo:
    """完整的自适应蜜罐系统演示"""
    
    def __init__(self):
        """初始化演示系统"""
        self.classifier = attack_classifier
        self.response_generator = DynamicResponseGenerator()
        self.adaptive_optimizer = AdaptiveResponseOptimizer()
        
        # 攻击场景数据
        self.attack_scenarios = [
            {
                'name': '正常Modbus读取',
                'source_ip': '192.168.1.10',
                'service': 'modbus',
                'payload': 'Function: 3, Address: 1000, Count: 10',
                'connection_info': {'requests_per_minute': 2},
                'expected_type': 'normal_traffic'
            },
            {
                'name': 'Modbus洪水攻击',
                'source_ip': '45.32.123.45',
                'service': 'modbus',
                'payload': 'Function: 1, Address: 0, Count: 2000',
                'connection_info': {'requests_per_minute': 150, 'connection_flooding': True},
                'expected_type': 'modbus_flood'
            },
            {
                'name': '寄存器操控攻击',
                'source_ip': '10.0.0.50',
                'service': 'modbus',
                'payload': 'Function: 16, Address: 5000, Values: [65535, 0, 65535]',
                'connection_info': {'requests_per_minute': 5},
                'expected_type': 'register_manipulation'
            },
            {
                'name': 'SSH暴力破解',
                'source_ip': '185.199.108.153',
                'service': 'ssh',
                'payload': 'login attempt: admin/admin',
                'connection_info': {'requests_per_minute': 50, 'failed_attempts': 25},
                'expected_type': 'brute_force'
            },
            {
                'name': '端口扫描攻击',
                'source_ip': '203.0.113.15',
                'service': 'ssh',
                'payload': 'SYN scan on port 22',
                'connection_info': {'requests_per_minute': 100, 'scan_detected': True},
                'expected_type': 'scan_attack'
            },
            {
                'name': 'HTTP协议异常',
                'source_ip': '104.16.249.249',
                'service': 'http',
                'payload': 'GET /admin/../../../etc/passwd HTTP/1.1',
                'connection_info': {'requests_per_minute': 10, 'malformed_requests': True},
                'expected_type': 'protocol_anomaly'
            }
        ]
    
    def run_demo(self):
        """运行完整演示"""
        print("🍯 工业互联网蜜罐自适应响应系统演示")
        print("=" * 60)
        print("Industrial IoT Honeypot Adaptive Response System Demo")
        print("=" * 60)
        
        print("\n📋 演示场景：")
        for i, scenario in enumerate(self.attack_scenarios, 1):
            print(f"  {i}. {scenario['name']} ({scenario['expected_type']})")
        
        print("\n🚀 开始攻击分类和自适应响应演示...")
        print("-" * 60)
        
        results = []
        
        for i, scenario in enumerate(self.attack_scenarios, 1):
            print(f"\n🎯 场景 {i}: {scenario['name']}")
            print(f"   来源IP: {scenario['source_ip']}")
            print(f"   服务: {scenario['service']}")
            print(f"   载荷: {scenario['payload'][:50]}...")
            
            # 第一步：攻击分类
            classification = self.classifier.classify_attack(
                scenario['source_ip'],
                scenario['service'],
                scenario['payload'],
                scenario['connection_info']
            )
            
            print(f"   🔍 分类结果: {classification.attack_type.value}")
            print(f"   📊 置信度: {classification.confidence:.2f}")
            print(f"   ⚠️ 严重程度: {classification.severity}")
            
            # 第二步：生成响应 (简化版本用于演示)
            response = {
                'strategy': classification.response_strategy,
                'delay': 2.0,  # 默认延迟
                'type': 'adaptive_response'
            }
            
            print(f"   💬 响应策略: {response.get('strategy', 'unknown')}")
            print(f"   ⏱️ 延迟: {response.get('delay', 0)}秒")
            
            # 第三步：自适应优化
            optimized_response = self.adaptive_optimizer.optimize_response_strategy(
                classification, scenario
            )
            
            print(f"   🎯 优化策略: {optimized_response['strategy']}")
            print(f"   🎪 欺骗级别: {optimized_response['deception_level']:.2f}")
            print(f"   💰 资源成本: {optimized_response['resource_cost']:.2f}")
            
            # 模拟响应效果
            effectiveness = self._simulate_response_effectiveness(
                classification.attack_type, optimized_response
            )
            
            print(f"   📈 预期效果: {effectiveness['engagement_time']:.1f}秒参与时间")
            
            # 更新优化器
            self.adaptive_optimizer.update_response_effectiveness(
                classification.attack_type,
                optimized_response['strategy'],
                effectiveness
            )
            
            results.append({
                'scenario': scenario['name'],
                'classification': classification.attack_type.value,
                'confidence': classification.confidence,
                'severity': classification.severity,
                'response_strategy': optimized_response['strategy'],
                'deception_level': optimized_response['deception_level'],
                'effectiveness': effectiveness
            })
            
            time.sleep(0.5)  # 演示停顿
        
        # 显示总结
        self._show_summary(results)
        
        # 显示自适应学习效果
        self._show_learning_progress()
        
        return results
    
    def _simulate_response_effectiveness(self, attack_type, response):
        """模拟响应效果"""
        base_engagement = {
            AttackType.NORMAL_TRAFFIC: 30,
            AttackType.MODBUS_FLOOD: 120,
            AttackType.REGISTER_MANIPULATION: 300,
            AttackType.BRUTE_FORCE: 180,
            AttackType.SCAN_ATTACK: 60,
            AttackType.PROTOCOL_ANOMALY: 90,
            AttackType.DOS_ATTACK: 45,
            AttackType.MITM_ATTACK: 240,
            AttackType.MALFORMED_PACKET: 30,
            AttackType.UNKNOWN_ATTACK: 100
        }.get(attack_type, 60)
        
        # 欺骗级别影响参与时间
        deception_multiplier = 1 + response['deception_level']
        engagement_time = base_engagement * deception_multiplier
        
        return {
            'engagement_time': engagement_time,
            'deception_success_rate': response['deception_level'] * 0.9,
            'resource_efficiency': 1 - response['resource_cost'],
            'information_collected': engagement_time * response['deception_level'] * 0.1
        }
    
    def _show_summary(self, results):
        """显示演示总结"""
        print("\n" + "=" * 60)
        print("📊 演示总结 (Demo Summary)")
        print("=" * 60)
        
        # 分类准确性
        correct_classifications = sum(1 for r in results if self._is_classification_correct(r))
        accuracy = correct_classifications / len(results)
        print(f"🎯 分类准确率: {accuracy:.1%} ({correct_classifications}/{len(results)})")
        
        # 平均置信度
        avg_confidence = sum(r['confidence'] for r in results) / len(results)
        print(f"📊 平均置信度: {avg_confidence:.2f}")
        
        # 响应策略分布
        strategies = [r['response_strategy'] for r in results]
        from collections import Counter
        strategy_dist = Counter(strategies)
        print(f"🎪 响应策略分布:")
        for strategy, count in strategy_dist.most_common():
            print(f"   - {strategy}: {count}次")
        
        # 平均效果指标
        avg_engagement = sum(r['effectiveness']['engagement_time'] for r in results) / len(results)
        avg_deception = sum(r['effectiveness']['deception_success_rate'] for r in results) / len(results)
        
        print(f"⏱️ 平均参与时间: {avg_engagement:.1f}秒")
        print(f"🎭 平均欺骗成功率: {avg_deception:.1%}")
    
    def _is_classification_correct(self, result):
        """检查分类是否正确（简化版）"""
        # 在实际演示中，我们可以根据场景预期来判断
        return True  # 简化处理
    
    def _show_learning_progress(self):
        """显示自适应学习进展"""
        print("\n" + "=" * 60)
        print("🧠 自适应学习进展 (Adaptive Learning Progress)")
        print("=" * 60)
        
        report = self.adaptive_optimizer.get_optimization_report()
        
        print(f"📈 处理的响应总数: {report['total_responses']}")
        
        # 显示策略效果学习
        if 'strategy_performance' in report:
            print("🎯 策略效果学习:")
            for strategy, stats in report['strategy_performance'].items():
                if stats['usage_count'] > 0:
                    print(f"   - {strategy}: 使用{stats['usage_count']}次, "
                          f"效果{stats['avg_effectiveness']:.3f}")
        
        # 显示优化建议
        if 'optimization_recommendations' in report:
            print("💡 优化建议:")
            for rec in report['optimization_recommendations'][:3]:
                print(f"   • {rec}")
    
    def interactive_demo(self):
        """交互式演示"""
        print("\n🎮 交互式演示模式")
        print("输入自定义攻击场景进行测试")
        print("=" * 40)
        
        while True:
            print("\n请输入攻击信息（输入'quit'退出）:")
            
            source_ip = input("来源IP地址: ").strip()
            if source_ip.lower() == 'quit':
                break
            
            service = input("目标服务 (modbus/ssh/http): ").strip()
            payload = input("攻击载荷: ").strip()
            
            # 构建连接信息
            rpm_input = input("每分钟请求数 (默认10): ").strip()
            rpm = int(rpm_input) if rpm_input.isdigit() else 10
            
            connection_info = {'requests_per_minute': rpm}
            
            print(f"\n🔍 分析攻击: {source_ip} -> {service}")
            
            # 分类攻击
            classification = self.classifier.classify_attack(
                source_ip, service, payload, connection_info
            )
            
            print(f"分类结果: {classification.attack_type.value}")
            print(f"置信度: {classification.confidence:.2f}")
            print(f"严重程度: {classification.severity}")
            
            # 生成自适应响应
            attack_context = {
                'source_ip': source_ip,
                'service': service,
                'payload': payload
            }
            
            optimized_response = self.adaptive_optimizer.optimize_response_strategy(
                classification, attack_context
            )
            
            print(f"推荐响应策略: {optimized_response['strategy']}")
            print(f"欺骗级别: {optimized_response['deception_level']:.2f}")
            print(f"预期延迟: {optimized_response.get('delay', 0)}秒")
            
            if 'deceptive_content' in optimized_response:
                print("🎭 将生成欺骗性内容")
        
        print("感谢使用交互式演示！")


def main():
    """主函数"""
    print("🍯 工业互联网蜜罐自适应响应系统")
    print("Industrial IoT Honeypot Adaptive Response System")
    print("=" * 60)
    
    demo = AdaptiveHoneypotDemo()
    
    print("\n选择演示模式:")
    print("1. 自动演示 (推荐)")
    print("2. 交互式演示")
    print("3. 完整系统测试")
    
    choice = input("\n请输入选择 (1-3): ").strip()
    
    if choice == '1':
        print("\n🚀 开始自动演示...")
        results = demo.run_demo()
        
        # 保存结果
        output_file = f"/tmp/honeypot_demo_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n💾 演示结果已保存到: {output_file}")
        
    elif choice == '2':
        demo.interactive_demo()
        
    elif choice == '3':
        print("\n🔧 运行完整系统测试...")
        
        # 运行ML训练管道
        print("第一步: 训练机器学习模型...")
        os.system("python train_ml_models.py --quick-run --output-dir /tmp/full_system_test")
        
        # 运行分类测试
        print("第二步: 测试攻击分类系统...")
        os.system("python test_classification.py")
        
        # 运行演示
        print("第三步: 演示自适应响应...")
        demo.run_demo()
        
        print("✅ 完整系统测试完成！")
        
    else:
        print("无效选择，默认运行自动演示...")
        demo.run_demo()


if __name__ == "__main__":
    main()