"""
Adaptive Response Optimization System for Industrial IoT Honeypot
Optimizes response strategies based on attack patterns and effectiveness
"""

import json
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timedelta
from collections import defaultdict, deque
from loguru import logger
import random
import math

# Import existing classification components
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from classification.attack_classifier import AttackType, AttackClassification
from classification.response_generator import DynamicResponseGenerator


class AdaptiveResponseOptimizer:
    """Optimizes honeypot responses based on attack effectiveness and patterns"""
    
    def __init__(self, learning_rate: float = 0.1, memory_size: int = 1000):
        """
        Initialize adaptive response optimizer
        
        Args:
            learning_rate: Rate of adaptation to new information
            memory_size: Size of attack history memory
        """
        self.learning_rate = learning_rate
        self.memory_size = memory_size
        
        # Response effectiveness tracking
        self.response_effectiveness = defaultdict(lambda: defaultdict(float))
        self.attack_patterns = defaultdict(list)
        self.response_history = deque(maxlen=memory_size)
        
        # Optimization parameters
        self.strategy_weights = {
            'delay_effectiveness': 0.3,
            'deception_success': 0.4,
            'resource_efficiency': 0.2,
            'learning_potential': 0.1
        }
        
        # Response strategy configurations
        self.response_strategies = {
            'immediate_response': {'delay': 0, 'deception_level': 0.1, 'resource_cost': 0.1},
            'short_delay': {'delay': 2, 'deception_level': 0.3, 'resource_cost': 0.2},
            'medium_delay': {'delay': 5, 'deception_level': 0.5, 'resource_cost': 0.3},
            'long_delay': {'delay': 10, 'deception_level': 0.7, 'resource_cost': 0.4},
            'progressive_delay': {'delay': 'adaptive', 'deception_level': 0.6, 'resource_cost': 0.5},
            'honeypot_mode': {'delay': 1, 'deception_level': 0.9, 'resource_cost': 0.8},
            'minimal_response': {'delay': 0, 'deception_level': 0.0, 'resource_cost': 0.05}
        }
        
        # Attack pattern analysis
        self.pattern_analyzer = AttackPatternAnalyzer()
        
        # Response success metrics
        self.success_metrics = {
            'attacker_engagement_time': defaultdict(list),
            'subsequent_attack_complexity': defaultdict(list),
            'false_positive_rate': defaultdict(list),
            'resource_consumption': defaultdict(list)
        }
        
        logger.info("Adaptive Response Optimizer initialized")
    
    def optimize_response_strategy(self, attack_classification: AttackClassification, 
                                 attack_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Optimize response strategy based on attack type and historical effectiveness
        
        Args:
            attack_classification: Classified attack information
            attack_context: Additional context (IP, payload, etc.)
            
        Returns:
            Optimized response configuration
        """
        attack_type = attack_classification.attack_type
        source_ip = attack_context.get('source_ip', 'unknown')
        
        # Analyze historical patterns for this attacker
        attacker_history = self._get_attacker_history(source_ip)
        
        # Get current response effectiveness
        current_effectiveness = self.response_effectiveness[attack_type.value]
        
        # Select optimal strategy
        optimal_strategy = self._select_optimal_strategy(
            attack_type, attack_classification, attacker_history, current_effectiveness
        )
        
        # Generate adaptive response
        adaptive_response = self._generate_adaptive_response(
            optimal_strategy, attack_classification, attack_context, attacker_history
        )
        
        # Record decision for learning
        self._record_response_decision(
            attack_type, source_ip, optimal_strategy, adaptive_response, attack_context
        )
        
        return adaptive_response
    
    def _get_attacker_history(self, source_ip: str) -> Dict[str, Any]:
        """Get historical information about an attacker"""
        
        attacker_attacks = [entry for entry in self.response_history 
                          if entry.get('source_ip') == source_ip]
        
        if not attacker_attacks:
            return {
                'attack_count': 0,
                'attack_types': [],
                'avg_session_duration': 0,
                'escalation_pattern': [],
                'response_adaptation': False
            }
        
        # Analyze attacker behavior
        attack_types = [entry['attack_type'] for entry in attacker_attacks]
        session_durations = [entry.get('session_duration', 0) for entry in attacker_attacks]
        
        # Detect escalation patterns
        escalation_pattern = self._detect_escalation_pattern(attacker_attacks)
        
        # Check if attacker adapts to responses
        response_adaptation = self._detect_response_adaptation(attacker_attacks)
        
        return {
            'attack_count': len(attacker_attacks),
            'attack_types': list(set(attack_types)),
            'avg_session_duration': np.mean(session_durations) if session_durations else 0,
            'escalation_pattern': escalation_pattern,
            'response_adaptation': response_adaptation,
            'first_seen': min(entry['timestamp'] for entry in attacker_attacks),
            'last_seen': max(entry['timestamp'] for entry in attacker_attacks)
        }
    
    def _select_optimal_strategy(self, attack_type: AttackType, 
                               attack_classification: AttackClassification,
                               attacker_history: Dict[str, Any],
                               effectiveness_scores: Dict[str, float]) -> str:
        """Select optimal response strategy using multi-criteria optimization"""
        
        strategy_scores = {}
        
        for strategy_name, strategy_config in self.response_strategies.items():
            score = 0.0
            
            # Historical effectiveness
            historical_effectiveness = effectiveness_scores.get(strategy_name, 0.5)  # Default neutral
            score += self.strategy_weights['delay_effectiveness'] * historical_effectiveness
            
            # Deception potential based on attack type
            deception_score = self._calculate_deception_score(
                attack_type, strategy_config, attacker_history
            )
            score += self.strategy_weights['deception_success'] * deception_score
            
            # Resource efficiency
            resource_efficiency = 1.0 - strategy_config['resource_cost']
            score += self.strategy_weights['resource_efficiency'] * resource_efficiency
            
            # Learning potential (how much can we learn from this response)
            learning_potential = self._calculate_learning_potential(
                attack_type, strategy_config, attacker_history
            )
            score += self.strategy_weights['learning_potential'] * learning_potential
            
            strategy_scores[strategy_name] = score
        
        # Select strategy with highest score, with some randomization for exploration
        if random.random() < 0.1:  # 10% exploration
            return random.choice(list(strategy_scores.keys()))
        else:
            return max(strategy_scores.items(), key=lambda x: x[1])[0]
    
    def _calculate_deception_score(self, attack_type: AttackType, 
                                 strategy_config: Dict[str, Any], 
                                 attacker_history: Dict[str, Any]) -> float:
        """Calculate deception effectiveness score"""
        
        base_deception = strategy_config['deception_level']
        
        # Adjust based on attack type
        attack_type_multipliers = {
            AttackType.NORMAL_TRAFFIC: 0.1,  # Low deception for normal traffic
            AttackType.SCAN_ATTACK: 0.8,     # High deception potential for scans
            AttackType.BRUTE_FORCE: 0.9,     # Very high for brute force
            AttackType.REGISTER_MANIPULATION: 0.95,  # Critical - max deception
            AttackType.DOS_ATTACK: 0.3,      # Lower deception for DoS
            AttackType.MITM_ATTACK: 0.7,     # Moderate deception
            AttackType.PROTOCOL_ANOMALY: 0.6,
            AttackType.MODBUS_FLOOD: 0.4,
            AttackType.MALFORMED_PACKET: 0.5,
            AttackType.UNKNOWN_ATTACK: 0.6
        }
        
        multiplier = attack_type_multipliers.get(attack_type, 0.5)
        
        # Adjust based on attacker sophistication
        if attacker_history['response_adaptation']:
            multiplier *= 0.7  # Sophisticated attacker - reduce deception effectiveness
        
        if attacker_history['attack_count'] > 10:
            multiplier *= 0.8  # Experienced attacker
        
        return base_deception * multiplier
    
    def _calculate_learning_potential(self, attack_type: AttackType,
                                    strategy_config: Dict[str, Any],
                                    attacker_history: Dict[str, Any]) -> float:
        """Calculate potential learning value from this response"""
        
        # Higher learning potential for:
        # 1. New attack types
        # 2. Sophisticated attackers  
        # 3. Strategies that engage attackers longer
        
        learning_score = 0.5  # Base score
        
        # New attacker bonus
        if attacker_history['attack_count'] == 0:
            learning_score += 0.3
        
        # Sophisticated attacker bonus
        if attacker_history['response_adaptation']:
            learning_score += 0.2
        
        # Attack type rarity bonus
        attack_frequency = self._get_attack_type_frequency(attack_type)
        if attack_frequency < 0.1:  # Rare attack
            learning_score += 0.2
        
        # Strategy engagement potential
        if strategy_config['deception_level'] > 0.7:
            learning_score += 0.1
        
        return min(learning_score, 1.0)
    
    def _generate_adaptive_response(self, strategy_name: str, 
                                  attack_classification: AttackClassification,
                                  attack_context: Dict[str, Any],
                                  attacker_history: Dict[str, Any]) -> Dict[str, Any]:
        """Generate adaptive response based on selected strategy"""
        
        strategy_config = self.response_strategies[strategy_name]
        
        # Base response configuration
        response = {
            'strategy': strategy_name,
            'attack_type': attack_classification.attack_type.value,
            'base_delay': strategy_config['delay'],
            'deception_level': strategy_config['deception_level'],
            'resource_cost': strategy_config['resource_cost']
        }
        
        # Adaptive delay calculation
        if strategy_config['delay'] == 'adaptive':
            response['delay'] = self._calculate_adaptive_delay(
                attack_classification, attacker_history
            )
        else:
            response['delay'] = strategy_config['delay']
        
        # Adaptive content based on deception level
        if strategy_config['deception_level'] > 0.5:
            response['deceptive_content'] = self._generate_deceptive_content(
                attack_classification.attack_type, attack_context
            )
        
        # Progressive response adjustments
        if attacker_history['attack_count'] > 0:
            response = self._apply_progressive_adjustments(response, attacker_history)
        
        # Resource optimization
        response['resource_limits'] = self._calculate_resource_limits(
            strategy_config['resource_cost'], attack_classification.severity
        )
        
        return response
    
    def _calculate_adaptive_delay(self, attack_classification: AttackClassification,
                                attacker_history: Dict[str, Any]) -> float:
        """Calculate adaptive delay based on attack patterns"""
        
        base_delay = 2.0  # Base delay in seconds
        
        # Increase delay for repeated attacks
        repeat_multiplier = min(1 + (attacker_history['attack_count'] * 0.5), 5.0)
        
        # Adjust for attack severity
        severity_multipliers = {
            'low': 0.5,
            'medium': 1.0,
            'high': 2.0,
            'critical': 3.0
        }
        severity_multiplier = severity_multipliers.get(attack_classification.severity, 1.0)
        
        # Random jitter to avoid pattern detection
        jitter = random.uniform(0.8, 1.2)
        
        adaptive_delay = base_delay * repeat_multiplier * severity_multiplier * jitter
        
        # Cap at maximum delay
        return min(adaptive_delay, 30.0)
    
    def _generate_deceptive_content(self, attack_type: AttackType, 
                                  attack_context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate deceptive content based on attack type"""
        
        service = attack_context.get('service', 'unknown')
        
        deceptive_content = {
            'service': service,
            'content_type': 'deceptive'
        }
        
        if attack_type == AttackType.REGISTER_MANIPULATION:
            deceptive_content.update({
                'fake_register_values': self._generate_fake_register_data(),
                'simulated_plc_response': True,
                'industrial_context': 'water_treatment_plant'
            })
        
        elif attack_type == AttackType.BRUTE_FORCE:
            deceptive_content.update({
                'fake_authentication_delay': random.uniform(1, 3),
                'simulated_lockout_warning': True,
                'honeypot_accounts': ['operator', 'maintenance', 'admin']
            })
        
        elif attack_type == AttackType.SCAN_ATTACK:
            deceptive_content.update({
                'fake_open_ports': [22, 80, 443, 502, 1433],
                'simulated_services': ['ssh', 'http', 'modbus', 'mssql'],
                'honeypot_banners': True
            })
        
        return deceptive_content
    
    def _generate_fake_register_data(self) -> Dict[str, Any]:
        """Generate realistic fake industrial register data"""
        
        return {
            'temperature_sensors': [random.uniform(20, 80) for _ in range(8)],
            'pressure_readings': [random.uniform(1, 10) for _ in range(4)],
            'flow_rates': [random.uniform(0, 100) for _ in range(6)],
            'valve_positions': [random.choice([0, 1]) for _ in range(12)],
            'alarm_status': random.choice([0, 1, 2]),  # 0=normal, 1=warning, 2=alarm
            'system_mode': random.choice(['auto', 'manual', 'maintenance'])
        }
    
    def _apply_progressive_adjustments(self, response: Dict[str, Any], 
                                     attacker_history: Dict[str, Any]) -> Dict[str, Any]:
        """Apply progressive response adjustments based on attacker behavior"""
        
        # Increase security measures for persistent attackers
        if attacker_history['attack_count'] > 5:
            response['enhanced_logging'] = True
            response['delay'] = response.get('delay', 0) * 1.5
        
        # Adapt to escalation patterns
        if attacker_history['escalation_pattern']:
            response['escalation_countermeasures'] = True
            response['deception_level'] = min(response.get('deception_level', 0.5) * 1.2, 1.0)
        
        # Response to adaptation
        if attacker_history['response_adaptation']:
            response['anti_adaptation_measures'] = True
            response['randomization_factor'] = random.uniform(0.8, 1.2)
        
        return response
    
    def _calculate_resource_limits(self, base_cost: float, severity: str) -> Dict[str, Any]:
        """Calculate resource allocation limits"""
        
        severity_multipliers = {
            'low': 0.5,
            'medium': 1.0,
            'high': 1.5,
            'critical': 2.0
        }
        
        multiplier = severity_multipliers.get(severity, 1.0)
        adjusted_cost = base_cost * multiplier
        
        return {
            'max_cpu_usage': min(adjusted_cost * 0.1, 0.8),  # Max 80% CPU
            'max_memory_mb': int(adjusted_cost * 100),       # Up to adjusted MB
            'max_session_duration': int(adjusted_cost * 300), # Up to adjusted seconds
            'max_concurrent_sessions': max(1, int(10 * (1 - adjusted_cost)))  # Fewer sessions for expensive responses
        }
    
    def _record_response_decision(self, attack_type: AttackType, source_ip: str,
                                strategy: str, response: Dict[str, Any],
                                attack_context: Dict[str, Any]):
        """Record response decision for learning"""
        
        record = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_type.value,
            'source_ip': source_ip,
            'strategy': strategy,
            'response': response,
            'context': attack_context
        }
        
        self.response_history.append(record)
    
    def update_response_effectiveness(self, attack_type: AttackType, strategy: str,
                                   effectiveness_metrics: Dict[str, float]):
        """Update response effectiveness based on observed results"""
        
        attack_key = attack_type.value
        
        # Current effectiveness
        current_effectiveness = self.response_effectiveness[attack_key].get(strategy, 0.5)
        
        # Weighted average of metrics
        metric_weights = {
            'attacker_engagement_time': 0.3,
            'deception_success_rate': 0.4,
            'resource_efficiency': 0.2,
            'false_positive_rate': -0.1  # Negative weight - lower is better
        }
        
        new_effectiveness = 0.0
        for metric, weight in metric_weights.items():
            if metric in effectiveness_metrics:
                new_effectiveness += weight * effectiveness_metrics[metric]
        
        # Apply learning rate
        updated_effectiveness = (
            (1 - self.learning_rate) * current_effectiveness +
            self.learning_rate * new_effectiveness
        )
        
        self.response_effectiveness[attack_key][strategy] = updated_effectiveness
        
        logger.info(f"Updated effectiveness for {attack_key}:{strategy} -> {updated_effectiveness:.3f}")
    
    def _detect_escalation_pattern(self, attacker_attacks: List[Dict]) -> List[str]:
        """Detect if attacker is escalating attack complexity"""
        
        if len(attacker_attacks) < 3:
            return []
        
        # Sort by timestamp
        sorted_attacks = sorted(attacker_attacks, key=lambda x: x['timestamp'])
        
        # Define attack complexity scores
        complexity_scores = {
            'normal_traffic': 0,
            'scan_attack': 1,
            'brute_force': 2,
            'protocol_anomaly': 3,
            'dos_attack': 4,
            'malformed_packet': 4,
            'mitm_attack': 5,
            'modbus_flood': 5,
            'register_manipulation': 6,
            'unknown_attack': 3
        }
        
        escalation_pattern = []
        prev_complexity = 0
        
        for attack in sorted_attacks:
            current_complexity = complexity_scores.get(attack['attack_type'], 0)
            if current_complexity > prev_complexity:
                escalation_pattern.append(f"{attack['attack_type']}({current_complexity})")
            prev_complexity = max(prev_complexity, current_complexity)
        
        return escalation_pattern
    
    def _detect_response_adaptation(self, attacker_attacks: List[Dict]) -> bool:
        """Detect if attacker adapts to responses"""
        
        if len(attacker_attacks) < 5:
            return False
        
        # Look for patterns in attack timing that correlate with response delays
        response_delays = []
        next_attack_delays = []
        
        for i in range(len(attacker_attacks) - 1):
            current_attack = attacker_attacks[i]
            next_attack = attacker_attacks[i + 1]
            
            # Calculate time between attacks
            current_time = datetime.fromisoformat(current_attack['timestamp'])
            next_time = datetime.fromisoformat(next_attack['timestamp'])
            time_diff = (next_time - current_time).total_seconds()
            
            response_delays.append(current_attack.get('response_delay', 0))
            next_attack_delays.append(time_diff)
        
        # Simple correlation check
        if len(response_delays) > 3:
            correlation = np.corrcoef(response_delays, next_attack_delays)[0, 1]
            return abs(correlation) > 0.5  # Strong correlation indicates adaptation
        
        return False
    
    def _get_attack_type_frequency(self, attack_type: AttackType) -> float:
        """Get frequency of attack type in recent history"""
        
        if not self.response_history:
            return 0.5  # Default neutral frequency
        
        attack_counts = defaultdict(int)
        for record in self.response_history:
            attack_counts[record['attack_type']] += 1
        
        total_attacks = len(self.response_history)
        frequency = attack_counts[attack_type.value] / total_attacks
        
        return frequency
    
    def get_optimization_report(self) -> Dict[str, Any]:
        """Generate comprehensive optimization report"""
        
        report = {
            'report_timestamp': datetime.now().isoformat(),
            'total_responses': len(self.response_history),
            'effectiveness_summary': dict(self.response_effectiveness),
            'strategy_performance': self._analyze_strategy_performance(),
            'attack_pattern_insights': self._analyze_attack_patterns(),
            'optimization_recommendations': self._generate_optimization_recommendations()
        }
        
        return report
    
    def _analyze_strategy_performance(self) -> Dict[str, Any]:
        """Analyze performance of different response strategies"""
        
        strategy_stats = defaultdict(lambda: {
            'usage_count': 0,
            'avg_effectiveness': 0.0,
            'attack_types': set()
        })
        
        for record in self.response_history:
            strategy = record['strategy']
            attack_type = record['attack_type']
            
            strategy_stats[strategy]['usage_count'] += 1
            strategy_stats[strategy]['attack_types'].add(attack_type)
        
        # Calculate average effectiveness
        for attack_type, strategies in self.response_effectiveness.items():
            for strategy, effectiveness in strategies.items():
                if strategy in strategy_stats:
                    current_avg = strategy_stats[strategy]['avg_effectiveness']
                    count = strategy_stats[strategy]['usage_count']
                    strategy_stats[strategy]['avg_effectiveness'] = (
                        (current_avg * (count - 1) + effectiveness) / count
                    )
        
        # Convert sets to lists for JSON serialization
        for strategy, stats in strategy_stats.items():
            stats['attack_types'] = list(stats['attack_types'])
        
        return dict(strategy_stats)
    
    def _analyze_attack_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in attack data"""
        
        patterns = {
            'hourly_distribution': defaultdict(int),
            'attacker_behavior': defaultdict(lambda: {
                'attack_count': 0,
                'unique_attack_types': set(),
                'session_duration_avg': 0.0
            }),
            'attack_type_transitions': defaultdict(lambda: defaultdict(int))
        }
        
        for record in self.response_history:
            timestamp = datetime.fromisoformat(record['timestamp'])
            hour = timestamp.hour
            patterns['hourly_distribution'][hour] += 1
            
            # Attacker behavior
            ip = record['source_ip']
            attack_type = record['attack_type']
            patterns['attacker_behavior'][ip]['attack_count'] += 1
            patterns['attacker_behavior'][ip]['unique_attack_types'].add(attack_type)
        
        # Attack type transitions
        for i in range(len(self.response_history) - 1):
            current_attack = self.response_history[i]['attack_type']
            next_attack = self.response_history[i + 1]['attack_type']
            patterns['attack_type_transitions'][current_attack][next_attack] += 1
        
        # Convert sets to lists
        for ip, behavior in patterns['attacker_behavior'].items():
            behavior['unique_attack_types'] = list(behavior['unique_attack_types'])
        
        return {
            'hourly_distribution': dict(patterns['hourly_distribution']),
            'attacker_behavior': dict(patterns['attacker_behavior']),
            'attack_type_transitions': {k: dict(v) for k, v in patterns['attack_type_transitions'].items()}
        }
    
    def _generate_optimization_recommendations(self) -> List[str]:
        """Generate optimization recommendations based on analysis"""
        
        recommendations = []
        
        # Strategy effectiveness recommendations
        if self.response_effectiveness:
            best_strategies = {}
            for attack_type, strategies in self.response_effectiveness.items():
                if strategies:
                    best_strategy = max(strategies.items(), key=lambda x: x[1])
                    best_strategies[attack_type] = best_strategy
            
            for attack_type, (strategy, effectiveness) in best_strategies.items():
                if effectiveness > 0.8:
                    recommendations.append(
                        f"Strategy '{strategy}' highly effective for {attack_type} (effectiveness: {effectiveness:.2f})"
                    )
                elif effectiveness < 0.3:
                    recommendations.append(
                        f"Consider replacing strategy '{strategy}' for {attack_type} (low effectiveness: {effectiveness:.2f})"
                    )
        
        # Resource optimization
        high_cost_strategies = [
            strategy for strategy, config in self.response_strategies.items()
            if config['resource_cost'] > 0.6
        ]
        
        if high_cost_strategies:
            recommendations.append(
                f"Monitor resource usage for high-cost strategies: {', '.join(high_cost_strategies)}"
            )
        
        # Pattern-based recommendations
        if len(self.response_history) > 50:
            recommendations.append("Sufficient data available for advanced pattern analysis")
        else:
            recommendations.append("Collect more interaction data for better optimization")
        
        return recommendations


class AttackPatternAnalyzer:
    """Analyzes attack patterns for optimization insights"""
    
    def __init__(self):
        self.pattern_cache = {}
    
    def analyze_temporal_patterns(self, attack_history: List[Dict]) -> Dict[str, Any]:
        """Analyze temporal patterns in attacks"""
        
        if not attack_history:
            return {}
        
        timestamps = [datetime.fromisoformat(attack['timestamp']) for attack in attack_history]
        
        # Hour distribution
        hour_dist = defaultdict(int)
        for ts in timestamps:
            hour_dist[ts.hour] += 1
        
        # Day of week distribution
        dow_dist = defaultdict(int)
        for ts in timestamps:
            dow_dist[ts.weekday()] += 1
        
        return {
            'peak_hours': sorted(hour_dist.items(), key=lambda x: x[1], reverse=True)[:3],
            'peak_days': sorted(dow_dist.items(), key=lambda x: x[1], reverse=True)[:3],
            'total_timespan_days': (max(timestamps) - min(timestamps)).days
        }