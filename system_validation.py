#!/usr/bin/env python3
"""
Comprehensive System Validation for Industrial IoT Honeypot
Tests all components and provides validation report
"""

import os
import sys
import json
import time
import traceback
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple
from loguru import logger

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from classification.attack_classifier import attack_classifier, AttackType
from classification.response_generator import DynamicResponseGenerator
from ml.adaptive_optimizer import AdaptiveResponseOptimizer
from ml.feature_extractor import FeatureExtractor
from ml.model_trainer import ModelTrainer
from ml.model_evaluator import ModelEvaluator


class SystemValidator:
    """Comprehensive system validation"""
    
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'validation_results': {},
            'performance_metrics': {},
            'issues_found': [],
            'recommendations': [],
            'overall_status': 'unknown'
        }
    
    def validate_attack_classification(self) -> Dict[str, Any]:
        """Validate attack classification system"""
        
        print("🔍 Testing Attack Classification System...")
        test_results = {
            'component': 'attack_classification',
            'tests_passed': 0,
            'tests_failed': 0,
            'test_details': [],
            'performance': {}
        }
        
        # Test scenarios
        test_scenarios = [
            {
                'name': 'Normal Modbus Traffic',
                'source_ip': '192.168.1.10',
                'service': 'modbus',
                'payload': 'Function: 3, Address: 1000, Count: 10',
                'expected_not': AttackType.DOS_ATTACK
            },
            {
                'name': 'Modbus Flood Attack',
                'source_ip': '45.32.123.45',
                'service': 'modbus',
                'payload': 'Function: 1, Address: 0, Count: 2000',
                'connection_info': {'requests_per_minute': 1000}
            },
            {
                'name': 'SSH Brute Force',
                'source_ip': '185.199.108.153',
                'service': 'ssh',
                'payload': 'login attempt: admin/admin',
                'connection_info': {'failed_logins': 50}
            },
            {
                'name': 'Port Scan',
                'source_ip': '203.0.113.15',
                'service': 'tcp',
                'payload': 'SYN scan on multiple ports',
                'connection_info': {'ports_scanned': 100}
            },
            {
                'name': 'HTTP Path Traversal',
                'source_ip': '104.16.249.249',
                'service': 'http',
                'payload': 'GET /admin/../../../etc/passwd HTTP/1.1'
            }
        ]
        
        start_time = time.time()
        
        for scenario in test_scenarios:
            try:
                # Classify attack
                classification = attack_classifier.classify_attack(
                    source_ip=scenario['source_ip'],
                    service=scenario['service'],
                    payload=scenario.get('payload', ''),
                    connection_info=scenario.get('connection_info', {})
                )
                
                # Validate result
                test_detail = {
                    'scenario': scenario['name'],
                    'classification': classification.attack_type.value,
                    'confidence': classification.confidence,
                    'severity': classification.severity,
                    'status': 'passed'
                }
                
                # Check if result makes sense
                if classification.confidence < 0.1 or classification.confidence > 1.0:
                    test_detail['status'] = 'failed'
                    test_detail['issue'] = 'Invalid confidence score'
                    test_results['tests_failed'] += 1
                elif 'expected_not' in scenario and classification.attack_type == scenario['expected_not']:
                    test_detail['status'] = 'failed'
                    test_detail['issue'] = f'Unexpected classification: {classification.attack_type.value}'
                    test_results['tests_failed'] += 1
                else:
                    test_results['tests_passed'] += 1
                
                test_results['test_details'].append(test_detail)
                
            except Exception as e:
                test_results['tests_failed'] += 1
                test_results['test_details'].append({
                    'scenario': scenario['name'],
                    'status': 'error',
                    'error': str(e)
                })
        
        # Performance metrics
        end_time = time.time()
        test_results['performance'] = {
            'total_time': end_time - start_time,
            'avg_time_per_classification': (end_time - start_time) / len(test_scenarios),
            'classifications_per_second': len(test_scenarios) / (end_time - start_time)
        }
        
        return test_results
    
    def validate_adaptive_response(self) -> Dict[str, Any]:
        """Validate adaptive response system"""
        
        print("🎯 Testing Adaptive Response System...")
        test_results = {
            'component': 'adaptive_response',
            'tests_passed': 0,
            'tests_failed': 0,
            'test_details': [],
            'performance': {}
        }
        
        try:
            optimizer = AdaptiveResponseOptimizer()
            
            # Test response optimization
            from classification.attack_classifier import AttackClassification
            
            test_classification = AttackClassification(
                attack_type=AttackType.MODBUS_FLOOD,
                confidence=0.9,
                severity='high',
                description='Test flood attack',
                indicators=['high_frequency'],
                response_strategy='rate_limit'
            )
            
            attack_context = {
                'source_ip': '192.168.1.100',
                'service': 'modbus',
                'payload': 'test payload'
            }
            
            start_time = time.time()
            
            # Test multiple optimizations
            for i in range(10):
                optimized_response = optimizer.optimize_response_strategy(
                    test_classification, attack_context
                )
                
                if not optimized_response or 'strategy' not in optimized_response:
                    test_results['tests_failed'] += 1
                    test_results['test_details'].append({
                        'test': f'optimization_{i}',
                        'status': 'failed',
                        'issue': 'Invalid response structure'
                    })
                else:
                    test_results['tests_passed'] += 1
                    test_results['test_details'].append({
                        'test': f'optimization_{i}',
                        'status': 'passed',
                        'strategy': optimized_response['strategy'],
                        'delay': optimized_response.get('delay', 0)
                    })
            
            end_time = time.time()
            test_results['performance'] = {
                'total_time': end_time - start_time,
                'avg_optimization_time': (end_time - start_time) / 10,
                'optimizations_per_second': 10 / (end_time - start_time)
            }
            
        except Exception as e:
            test_results['tests_failed'] += 1
            test_results['test_details'].append({
                'test': 'adaptive_response_system',
                'status': 'error',
                'error': str(e),
                'traceback': traceback.format_exc()
            })
        
        return test_results
    
    def validate_ml_pipeline(self) -> Dict[str, Any]:
        """Validate ML pipeline components"""
        
        print("🤖 Testing ML Pipeline Components...")
        test_results = {
            'component': 'ml_pipeline',
            'tests_passed': 0,
            'tests_failed': 0,
            'test_details': [],
            'performance': {}
        }
        
        # Test feature extractor
        try:
            feature_extractor = FeatureExtractor()
            
            # Sample data
            sample_data = [
                {
                    'source_ip': '192.168.1.10',
                    'service': 'modbus',
                    'payload': 'Function: 3, Address: 1000',
                    'true_label': 'normal_traffic',
                    'timestamp': datetime.now().isoformat(),
                    'connection_info': {'requests_per_minute': 5}
                },
                {
                    'source_ip': '45.32.123.45',
                    'service': 'modbus',
                    'payload': 'Function: 1, Address: 0, Count: 2000',
                    'true_label': 'modbus_flood',
                    'timestamp': datetime.now().isoformat(),
                    'connection_info': {'requests_per_minute': 1000}
                }
            ]
            
            start_time = time.time()
            features, labels, feature_names = feature_extractor.extract_features(sample_data)
            end_time = time.time()
            
            if len(features) != len(sample_data):
                test_results['tests_failed'] += 1
                test_results['test_details'].append({
                    'test': 'feature_extraction',
                    'status': 'failed',
                    'issue': 'Feature count mismatch'
                })
            else:
                test_results['tests_passed'] += 1
                test_results['test_details'].append({
                    'test': 'feature_extraction',
                    'status': 'passed',
                    'features_extracted': len(feature_names),
                    'samples_processed': len(features)
                })
            
            test_results['performance']['feature_extraction_time'] = end_time - start_time
            
        except Exception as e:
            test_results['tests_failed'] += 1
            test_results['test_details'].append({
                'test': 'feature_extraction',
                'status': 'error',
                'error': str(e)
            })
        
        # Test model trainer (basic functionality)
        try:
            model_trainer = ModelTrainer()
            
            # Check if trainer initializes properly
            if hasattr(model_trainer, 'models') and model_trainer.models:
                test_results['tests_passed'] += 1
                test_results['test_details'].append({
                    'test': 'model_trainer_init',
                    'status': 'passed',
                    'models_available': len(model_trainer.models)
                })
            else:
                test_results['tests_failed'] += 1
                test_results['test_details'].append({
                    'test': 'model_trainer_init',
                    'status': 'failed',
                    'issue': 'No models available'
                })
                
        except Exception as e:
            test_results['tests_failed'] += 1
            test_results['test_details'].append({
                'test': 'model_trainer_init',
                'status': 'error',
                'error': str(e)
            })
        
        return test_results
    
    def validate_response_generation(self) -> Dict[str, Any]:
        """Validate response generation system"""
        
        print("📡 Testing Response Generation System...")
        test_results = {
            'component': 'response_generation',
            'tests_passed': 0,
            'tests_failed': 0,
            'test_details': [],
            'performance': {}
        }
        
        try:
            import asyncio
            response_generator = DynamicResponseGenerator()
            
            # Test different attack types with proper classification objects
            from classification.attack_classifier import AttackClassification
            
            test_classifications = [
                AttackClassification(
                    attack_type=AttackType.NORMAL_TRAFFIC,
                    confidence=0.9,
                    severity='info',
                    description='Normal traffic',
                    indicators=['normal'],
                    response_strategy='normal'
                ),
                AttackClassification(
                    attack_type=AttackType.MODBUS_FLOOD,
                    confidence=0.8,
                    severity='high',
                    description='Modbus flood attack',
                    indicators=['flood'],
                    response_strategy='rate_limit'
                ),
                AttackClassification(
                    attack_type=AttackType.BRUTE_FORCE,
                    confidence=0.7,
                    severity='medium',
                    description='Brute force attack',
                    indicators=['brute_force'],
                    response_strategy='delay'
                ),
                AttackClassification(
                    attack_type=AttackType.SCAN_ATTACK,
                    confidence=0.6,
                    severity='low',
                    description='Scan attack',
                    indicators=['scan'],
                    response_strategy='minimal'
                ),
                AttackClassification(
                    attack_type=AttackType.DOS_ATTACK,
                    confidence=0.9,
                    severity='critical',
                    description='DoS attack',
                    indicators=['dos'],
                    response_strategy='block'
                )
            ]
            
            start_time = time.time()
            
            # Create async event loop for testing
            async def test_response_generation():
                results = []
                for classification in test_classifications:
                    try:
                        response = await response_generator.generate_response(
                            classification=classification,
                            service='modbus',
                            payload='test payload',
                            source_ip='192.168.1.100'
                        )
                        
                        if response and isinstance(response, dict):
                            results.append({
                                'test': f'response_for_{classification.attack_type.value}',
                                'status': 'passed',
                                'response_keys': list(response.keys())
                            })
                        else:
                            results.append({
                                'test': f'response_for_{classification.attack_type.value}',
                                'status': 'failed',
                                'issue': 'Invalid response structure'
                            })
                            
                    except Exception as e:
                        results.append({
                            'test': f'response_for_{classification.attack_type.value}',
                            'status': 'error',
                            'error': str(e)
                        })
                
                return results
            
            # Run async test
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                async_results = loop.run_until_complete(test_response_generation())
                loop.close()
                
                for result in async_results:
                    test_results['test_details'].append(result)
                    if result['status'] == 'passed':
                        test_results['tests_passed'] += 1
                    else:
                        test_results['tests_failed'] += 1
                        
            except Exception as e:
                # Fallback for systems without proper async support
                test_results['tests_failed'] += 1
                test_results['test_details'].append({
                    'test': 'async_response_generation',
                    'status': 'error',
                    'error': f'Async test failed: {str(e)}'
                })
            
            end_time = time.time()
            test_results['performance'] = {
                'total_time': end_time - start_time,
                'avg_response_time': (end_time - start_time) / len(test_classifications),
                'responses_per_second': len(test_classifications) / (end_time - start_time) if (end_time - start_time) > 0 else 0
            }
            
        except Exception as e:
            test_results['tests_failed'] += 1
            test_results['test_details'].append({
                'test': 'response_generation_system',
                'status': 'error',
                'error': str(e)
            })
        
        return test_results
    
    def run_comprehensive_validation(self) -> Dict[str, Any]:
        """Run all validation tests"""
        
        print("🔬 Industrial IoT Honeypot System Validation")
        print("=" * 60)
        
        # Run all component tests
        validation_tests = [
            ('attack_classification', self.validate_attack_classification),
            ('adaptive_response', self.validate_adaptive_response),
            ('ml_pipeline', self.validate_ml_pipeline),
            ('response_generation', self.validate_response_generation)
        ]
        
        for test_name, test_func in validation_tests:
            try:
                result = test_func()
                self.results['validation_results'][test_name] = result
                
                # Update performance metrics
                if 'performance' in result:
                    self.results['performance_metrics'][test_name] = result['performance']
                
                # Check for issues
                if result['tests_failed'] > 0:
                    self.results['issues_found'].append({
                        'component': test_name,
                        'failures': result['tests_failed'],
                        'details': [d for d in result['test_details'] if d.get('status') in ['failed', 'error']]
                    })
                
            except Exception as e:
                self.results['validation_results'][test_name] = {
                    'component': test_name,
                    'status': 'error',
                    'error': str(e),
                    'traceback': traceback.format_exc()
                }
                self.results['issues_found'].append({
                    'component': test_name,
                    'error': str(e)
                })
        
        # Calculate overall status
        total_passed = sum(r.get('tests_passed', 0) for r in self.results['validation_results'].values() if isinstance(r, dict))
        total_failed = sum(r.get('tests_failed', 0) for r in self.results['validation_results'].values() if isinstance(r, dict))
        total_tests = total_passed + total_failed
        
        if total_tests == 0:
            self.results['overall_status'] = 'no_tests'
        elif total_failed == 0:
            self.results['overall_status'] = 'all_passed'
        elif total_passed / total_tests >= 0.8:
            self.results['overall_status'] = 'mostly_passed'
        else:
            self.results['overall_status'] = 'significant_issues'
        
        self.results['test_summary'] = {
            'total_tests': total_tests,
            'tests_passed': total_passed,
            'tests_failed': total_failed,
            'success_rate': total_passed / total_tests if total_tests > 0 else 0
        }
        
        # Generate recommendations
        self.generate_recommendations()
        
        return self.results
    
    def generate_recommendations(self):
        """Generate recommendations based on validation results"""
        
        success_rate = self.results['test_summary']['success_rate']
        
        if success_rate >= 0.95:
            self.results['recommendations'].extend([
                "✅ System validation successful - ready for research deployment",
                "🔬 Consider running extended stress tests with larger datasets",
                "📊 Document current performance baselines for comparison"
            ])
        elif success_rate >= 0.8:
            self.results['recommendations'].extend([
                "⚠️  Most tests passed but some issues found - review failed tests",
                "🔧 Fix identified issues before production deployment",
                "🧪 Run additional validation after fixes"
            ])
        else:
            self.results['recommendations'].extend([
                "❌ Significant issues found - system needs attention",
                "🚨 Do not deploy until critical issues are resolved",
                "🔍 Investigate root causes of failures"
            ])
        
        # Component-specific recommendations
        for component, result in self.results['validation_results'].items():
            if isinstance(result, dict) and result.get('tests_failed', 0) > 0:
                self.results['recommendations'].append(
                    f"🔧 Address failures in {component} component"
                )
        
        # Performance recommendations
        if 'performance_metrics' in self.results:
            perf = self.results['performance_metrics']
            
            # Check classification performance
            if 'attack_classification' in perf:
                cps = perf['attack_classification'].get('classifications_per_second', 0)
                if cps < 10:
                    self.results['recommendations'].append(
                        "⚡ Consider optimizing attack classification for better performance"
                    )
            
            # Check response performance
            if 'response_generation' in perf:
                rps = perf['response_generation'].get('responses_per_second', 0)
                if rps < 100:
                    self.results['recommendations'].append(
                        "⚡ Consider optimizing response generation for better throughput"
                    )

def main():
    """Main validation function"""
    
    validator = SystemValidator()
    results = validator.run_comprehensive_validation()
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 VALIDATION SUMMARY")
    print("=" * 60)
    
    summary = results['test_summary']
    print(f"🧪 Total Tests: {summary['total_tests']}")
    print(f"✅ Tests Passed: {summary['tests_passed']}")
    print(f"❌ Tests Failed: {summary['tests_failed']}")
    print(f"📈 Success Rate: {summary['success_rate']:.1%}")
    print(f"🎯 Overall Status: {results['overall_status'].replace('_', ' ').title()}")
    
    # Print performance metrics
    if results['performance_metrics']:
        print(f"\n⚡ PERFORMANCE METRICS")
        print("-" * 30)
        for component, metrics in results['performance_metrics'].items():
            print(f"{component.replace('_', ' ').title()}:")
            for metric, value in metrics.items():
                if 'time' in metric:
                    print(f"  • {metric}: {value:.3f}s")
                elif 'per_second' in metric:
                    print(f"  • {metric}: {value:.1f}")
                else:
                    print(f"  • {metric}: {value}")
    
    # Print issues
    if results['issues_found']:
        print(f"\n⚠️  ISSUES FOUND")
        print("-" * 20)
        for issue in results['issues_found']:
            print(f"• {issue['component']}: {issue.get('failures', 'Error occurred')}")
    
    # Print recommendations
    if results['recommendations']:
        print(f"\n💡 RECOMMENDATIONS")
        print("-" * 25)
        for rec in results['recommendations']:
            print(f"• {rec}")
    
    # Save detailed results
    output_file = Path(f"/tmp/system_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Detailed results saved to: {output_file}")
    
    # Return exit code based on results
    if results['overall_status'] in ['all_passed', 'mostly_passed']:
        print("\n🎉 System validation completed successfully!")
        return 0
    else:
        print("\n⚠️  System validation found significant issues!")
        return 1

if __name__ == "__main__":
    exit(main())