"""
Comprehensive Model Evaluation System for Industrial IoT Honeypot
Provides detailed analysis and visualization of model performance
"""

import json
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime
from pathlib import Path
from loguru import logger
from collections import defaultdict
import math

# Visualization (optional)
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    logger.info("Matplotlib not available - visualizations disabled")
    MATPLOTLIB_AVAILABLE = False

# Advanced metrics (optional)
try:
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report, roc_auc_score,
        roc_curve, precision_recall_curve, average_precision_score
    )
    SKLEARN_METRICS_AVAILABLE = True
except ImportError:
    logger.info("Scikit-learn metrics not available - using basic metrics")
    SKLEARN_METRICS_AVAILABLE = False


class ModelEvaluator:
    """Comprehensive model evaluation and analysis"""
    
    def __init__(self):
        """Initialize evaluator"""
        self.evaluation_history = []
        self.performance_metrics = {}
        self.attack_type_analysis = {}
        
    def evaluate_model(self, model_name: str, y_true: np.ndarray, y_pred: np.ndarray, 
                      y_proba: Optional[np.ndarray] = None, 
                      attack_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Comprehensive model evaluation
        
        Args:
            model_name: Name of the model
            y_true: True labels
            y_pred: Predicted labels
            y_proba: Prediction probabilities (optional)
            attack_types: List of attack type names
            
        Returns:
            Comprehensive evaluation results
        """
        logger.info(f"Evaluating model: {model_name}")
        
        # Basic metrics
        results = {
            'model_name': model_name,
            'evaluation_timestamp': datetime.now().isoformat(),
            'sample_count': len(y_true),
            'basic_metrics': self._calculate_basic_metrics(y_true, y_pred),
            'per_class_metrics': self._calculate_per_class_metrics(y_true, y_pred, attack_types),
            'confusion_matrix_analysis': self._analyze_confusion_matrix(y_true, y_pred, attack_types),
            'attack_type_performance': self._analyze_attack_type_performance(y_true, y_pred, attack_types)
        }
        
        # Advanced metrics (if available)
        if SKLEARN_METRICS_AVAILABLE and y_proba is not None:
            results['advanced_metrics'] = self._calculate_advanced_metrics(y_true, y_pred, y_proba, attack_types)
        
        # Security-specific analysis
        results['security_analysis'] = self._security_analysis(y_true, y_pred, attack_types)
        
        # Store evaluation
        self.evaluation_history.append(results)
        self.performance_metrics[model_name] = results
        
        logger.info(f"Evaluation completed for {model_name}")
        return results
    
    def _calculate_basic_metrics(self, y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
        """Calculate basic classification metrics"""
        
        if SKLEARN_METRICS_AVAILABLE:
            accuracy = accuracy_score(y_true, y_pred)
            precision_macro = precision_score(y_true, y_pred, average='macro', zero_division=0)
            recall_macro = recall_score(y_true, y_pred, average='macro', zero_division=0)
            f1_macro = f1_score(y_true, y_pred, average='macro', zero_division=0)
            precision_micro = precision_score(y_true, y_pred, average='micro', zero_division=0)
            recall_micro = recall_score(y_true, y_pred, average='micro', zero_division=0)
            f1_micro = f1_score(y_true, y_pred, average='micro', zero_division=0)
        else:
            # Manual calculation
            accuracy = np.mean(y_true == y_pred)
            precision_macro = self._manual_precision(y_true, y_pred, average='macro')
            recall_macro = self._manual_recall(y_true, y_pred, average='macro')
            f1_macro = self._manual_f1(y_true, y_pred, average='macro')
            precision_micro = self._manual_precision(y_true, y_pred, average='micro')
            recall_micro = self._manual_recall(y_true, y_pred, average='micro')
            f1_micro = self._manual_f1(y_true, y_pred, average='micro')
        
        return {
            'accuracy': float(accuracy),
            'precision_macro': float(precision_macro),
            'recall_macro': float(recall_macro),
            'f1_score_macro': float(f1_macro),
            'precision_micro': float(precision_micro),
            'recall_micro': float(recall_micro),
            'f1_score_micro': float(f1_micro)
        }
    
    def _calculate_per_class_metrics(self, y_true: np.ndarray, y_pred: np.ndarray, 
                                   attack_types: Optional[List[str]] = None) -> Dict[str, Dict[str, float]]:
        """Calculate per-class metrics"""
        
        unique_labels = list(set(y_true) | set(y_pred))
        per_class = {}
        
        for label in unique_labels:
            # Binary masks for this class
            true_positive = np.sum((y_true == label) & (y_pred == label))
            false_positive = np.sum((y_true != label) & (y_pred == label))
            false_negative = np.sum((y_true == label) & (y_pred != label))
            true_negative = np.sum((y_true != label) & (y_pred != label))
            
            # Calculate metrics
            precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) > 0 else 0
            recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            support = true_positive + false_negative
            
            per_class[str(label)] = {
                'precision': float(precision),
                'recall': float(recall),
                'f1_score': float(f1),
                'support': int(support),
                'true_positive': int(true_positive),
                'false_positive': int(false_positive),
                'false_negative': int(false_negative),
                'true_negative': int(true_negative)
            }
        
        return per_class
    
    def _analyze_confusion_matrix(self, y_true: np.ndarray, y_pred: np.ndarray, 
                                attack_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analyze confusion matrix"""
        
        if SKLEARN_METRICS_AVAILABLE:
            cm = confusion_matrix(y_true, y_pred)
            labels = sorted(list(set(y_true) | set(y_pred)))
        else:
            # Manual confusion matrix
            labels = sorted(list(set(y_true) | set(y_pred)))
            cm = np.zeros((len(labels), len(labels)), dtype=int)
            
            label_to_idx = {label: i for i, label in enumerate(labels)}
            for true_label, pred_label in zip(y_true, y_pred):
                true_idx = label_to_idx[true_label]
                pred_idx = label_to_idx[pred_label]
                cm[true_idx, pred_idx] += 1
        
        # Normalize confusion matrix
        cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        cm_normalized = np.nan_to_num(cm_normalized)
        
        # Find most confused pairs
        confusion_pairs = []
        for i, true_label in enumerate(labels):
            for j, pred_label in enumerate(labels):
                if i != j and cm[i, j] > 0:
                    confusion_pairs.append({
                        'true_label': true_label,
                        'predicted_label': pred_label,
                        'count': int(cm[i, j]),
                        'percentage': float(cm_normalized[i, j] * 100)
                    })
        
        # Sort by confusion count
        confusion_pairs.sort(key=lambda x: x['count'], reverse=True)
        
        return {
            'confusion_matrix': cm.tolist(),
            'confusion_matrix_normalized': cm_normalized.tolist(),
            'labels': labels,
            'most_confused_pairs': confusion_pairs[:10],  # Top 10 most confused pairs
            'diagonal_accuracy': float(np.trace(cm) / np.sum(cm))
        }
    
    def _analyze_attack_type_performance(self, y_true: np.ndarray, y_pred: np.ndarray, 
                                       attack_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analyze performance for different attack types"""
        
        performance_by_type = {}
        unique_labels = list(set(y_true))
        
        # Group attack types into categories
        attack_categories = {
            'normal': ['normal_traffic'],
            'protocol_attacks': ['modbus_flood', 'register_manipulation', 'protocol_anomaly'],
            'network_attacks': ['dos_attack', 'mitm_attack', 'scan_attack'],
            'credential_attacks': ['brute_force'],
            'anomaly_attacks': ['malformed_packet', 'unknown_attack']
        }
        
        for category, attack_list in attack_categories.items():
            category_metrics = {'total_samples': 0, 'correct_predictions': 0, 'attack_types': []}
            
            for attack_type in attack_list:
                if attack_type in unique_labels:
                    # Samples of this attack type
                    mask = (y_true == attack_type)
                    type_samples = np.sum(mask)
                    type_correct = np.sum((y_true == attack_type) & (y_pred == attack_type))
                    
                    if type_samples > 0:
                        type_accuracy = type_correct / type_samples
                        
                        category_metrics['total_samples'] += type_samples
                        category_metrics['correct_predictions'] += type_correct
                        category_metrics['attack_types'].append({
                            'type': attack_type,
                            'samples': int(type_samples),
                            'correct': int(type_correct),
                            'accuracy': float(type_accuracy)
                        })
            
            if category_metrics['total_samples'] > 0:
                category_metrics['category_accuracy'] = category_metrics['correct_predictions'] / category_metrics['total_samples']
            else:
                category_metrics['category_accuracy'] = 0.0
            
            performance_by_type[category] = category_metrics
        
        return performance_by_type
    
    def _calculate_advanced_metrics(self, y_true: np.ndarray, y_pred: np.ndarray, 
                                  y_proba: np.ndarray, attack_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Calculate advanced metrics using probabilities"""
        
        advanced_metrics = {}
        
        try:
            # For multiclass, we'll calculate macro-averaged AUC
            unique_labels = sorted(list(set(y_true)))
            
            if len(unique_labels) > 2:
                # Multiclass AUC
                auc_scores = []
                for i, label in enumerate(unique_labels):
                    # Binary classification for this label vs rest
                    y_binary = (y_true == label).astype(int)
                    if len(np.unique(y_binary)) > 1:  # Need both classes present
                        if y_proba.shape[1] > i:
                            auc = roc_auc_score(y_binary, y_proba[:, i])
                            auc_scores.append(auc)
                
                if auc_scores:
                    advanced_metrics['auc_macro'] = float(np.mean(auc_scores))
                    advanced_metrics['auc_per_class'] = {unique_labels[i]: float(score) 
                                                       for i, score in enumerate(auc_scores)}
            
            # Average precision scores
            ap_scores = []
            for i, label in enumerate(unique_labels):
                y_binary = (y_true == label).astype(int)
                if len(np.unique(y_binary)) > 1 and y_proba.shape[1] > i:
                    ap = average_precision_score(y_binary, y_proba[:, i])
                    ap_scores.append(ap)
            
            if ap_scores:
                advanced_metrics['average_precision_macro'] = float(np.mean(ap_scores))
            
            # Confidence analysis
            advanced_metrics['confidence_analysis'] = self._analyze_prediction_confidence(y_true, y_pred, y_proba)
            
        except Exception as e:
            logger.warning(f"Could not calculate advanced metrics: {str(e)}")
        
        return advanced_metrics
    
    def _analyze_prediction_confidence(self, y_true: np.ndarray, y_pred: np.ndarray, 
                                     y_proba: np.ndarray) -> Dict[str, Any]:
        """Analyze prediction confidence"""
        
        # Maximum probability for each prediction
        max_probabilities = np.max(y_proba, axis=1)
        
        # Correct vs incorrect predictions
        correct_mask = (y_true == y_pred)
        
        confidence_analysis = {
            'mean_confidence': float(np.mean(max_probabilities)),
            'mean_confidence_correct': float(np.mean(max_probabilities[correct_mask])) if np.any(correct_mask) else 0.0,
            'mean_confidence_incorrect': float(np.mean(max_probabilities[~correct_mask])) if np.any(~correct_mask) else 0.0,
            'confidence_distribution': {
                'high_confidence': float(np.mean(max_probabilities > 0.8)),
                'medium_confidence': float(np.mean((max_probabilities >= 0.6) & (max_probabilities <= 0.8))),
                'low_confidence': float(np.mean(max_probabilities < 0.6))
            }
        }
        
        # Accuracy by confidence level
        if np.any(max_probabilities > 0.8):
            confidence_analysis['accuracy_high_confidence'] = float(np.mean(correct_mask[max_probabilities > 0.8]))
        
        if np.any(max_probabilities < 0.6):
            confidence_analysis['accuracy_low_confidence'] = float(np.mean(correct_mask[max_probabilities < 0.6]))
        
        return confidence_analysis
    
    def _security_analysis(self, y_true: np.ndarray, y_pred: np.ndarray, 
                          attack_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Security-specific analysis"""
        
        security_metrics = {}
        
        # False positive rate (legitimate traffic classified as attack)
        if 'normal_traffic' in y_true:
            normal_mask = (y_true == 'normal_traffic')
            if np.any(normal_mask):
                false_positive_rate = float(np.mean(y_pred[normal_mask] != 'normal_traffic'))
                security_metrics['false_positive_rate'] = false_positive_rate
        
        # False negative rate (attacks classified as normal)
        attack_mask = (y_true != 'normal_traffic')
        if np.any(attack_mask):
            false_negative_rate = float(np.mean(y_pred[attack_mask] == 'normal_traffic'))
            security_metrics['false_negative_rate'] = false_negative_rate
        
        # Critical attack detection (high-severity attacks)
        critical_attacks = ['register_manipulation', 'dos_attack', 'mitm_attack']
        critical_mask = np.isin(y_true, critical_attacks)
        if np.any(critical_mask):
            critical_detection_rate = float(np.mean(np.isin(y_pred[critical_mask], critical_attacks)))
            security_metrics['critical_attack_detection_rate'] = critical_detection_rate
        
        # Attack type confusion analysis
        attack_confusion = defaultdict(int)
        for true_label, pred_label in zip(y_true, y_pred):
            if true_label != pred_label and true_label != 'normal_traffic':
                attack_confusion[f"{true_label}_as_{pred_label}"] += 1
        
        security_metrics['attack_type_confusions'] = dict(attack_confusion)
        
        return security_metrics
    
    def compare_models(self, model_evaluations: Dict[str, Dict]) -> Dict[str, Any]:
        """Compare multiple model evaluations"""
        
        logger.info(f"Comparing {len(model_evaluations)} models")
        
        comparison = {
            'model_count': len(model_evaluations),
            'comparison_timestamp': datetime.now().isoformat(),
            'metrics_comparison': {},
            'rankings': {},
            'recommendations': {}
        }
        
        # Extract key metrics for comparison
        metrics_to_compare = ['accuracy', 'f1_score_macro', 'precision_macro', 'recall_macro']
        
        for metric in metrics_to_compare:
            comparison['metrics_comparison'][metric] = {}
            scores = []
            
            for model_name, evaluation in model_evaluations.items():
                score = evaluation.get('basic_metrics', {}).get(metric, 0.0)
                comparison['metrics_comparison'][metric][model_name] = float(score)
                scores.append((model_name, score))
            
            # Rank models by this metric
            scores.sort(key=lambda x: x[1], reverse=True)
            comparison['rankings'][metric] = [model_name for model_name, _ in scores]
        
        # Overall ranking (weighted average)
        weights = {'accuracy': 0.3, 'f1_score_macro': 0.4, 'precision_macro': 0.15, 'recall_macro': 0.15}
        overall_scores = {}
        
        for model_name in model_evaluations.keys():
            weighted_score = 0.0
            for metric, weight in weights.items():
                score = comparison['metrics_comparison'][metric].get(model_name, 0.0)
                weighted_score += score * weight
            overall_scores[model_name] = weighted_score
        
        # Sort by overall score
        sorted_models = sorted(overall_scores.items(), key=lambda x: x[1], reverse=True)
        comparison['rankings']['overall'] = [model_name for model_name, _ in sorted_models]
        comparison['overall_scores'] = overall_scores
        
        # Generate recommendations
        best_model = sorted_models[0][0] if sorted_models else None
        comparison['recommendations'] = self._generate_model_recommendations(model_evaluations, best_model)
        
        return comparison
    
    def _generate_model_recommendations(self, evaluations: Dict[str, Dict], 
                                      best_model: Optional[str]) -> Dict[str, Any]:
        """Generate recommendations based on evaluation results"""
        
        recommendations = {
            'best_overall_model': best_model,
            'model_specific_recommendations': {},
            'deployment_considerations': []
        }
        
        if not best_model:
            return recommendations
        
        # Model-specific recommendations
        for model_name, evaluation in evaluations.items():
            model_rec = {}
            
            # Performance assessment
            accuracy = evaluation.get('basic_metrics', {}).get('accuracy', 0.0)
            f1_score = evaluation.get('basic_metrics', {}).get('f1_score_macro', 0.0)
            
            if accuracy >= 0.95 and f1_score >= 0.95:
                model_rec['performance'] = 'excellent'
            elif accuracy >= 0.90 and f1_score >= 0.90:
                model_rec['performance'] = 'good'
            elif accuracy >= 0.80 and f1_score >= 0.80:
                model_rec['performance'] = 'acceptable'
            else:
                model_rec['performance'] = 'needs_improvement'
            
            # Security analysis
            security_analysis = evaluation.get('security_analysis', {})
            fpr = security_analysis.get('false_positive_rate', 0.0)
            fnr = security_analysis.get('false_negative_rate', 0.0)
            
            if fpr <= 0.05 and fnr <= 0.05:
                model_rec['security_rating'] = 'high'
            elif fpr <= 0.10 and fnr <= 0.10:
                model_rec['security_rating'] = 'medium'
            else:
                model_rec['security_rating'] = 'low'
            
            recommendations['model_specific_recommendations'][model_name] = model_rec
        
        # Deployment considerations
        if best_model:
            best_eval = evaluations[best_model]
            
            # False positive rate consideration
            fpr = best_eval.get('security_analysis', {}).get('false_positive_rate', 0.0)
            if fpr > 0.10:
                recommendations['deployment_considerations'].append(
                    f"High false positive rate ({fpr:.2%}) - consider adjusting thresholds"
                )
            
            # False negative rate consideration
            fnr = best_eval.get('security_analysis', {}).get('false_negative_rate', 0.0)
            if fnr > 0.10:
                recommendations['deployment_considerations'].append(
                    f"High false negative rate ({fnr:.2%}) - may miss attacks"
                )
            
            # Critical attack detection
            critical_rate = best_eval.get('security_analysis', {}).get('critical_attack_detection_rate', 0.0)
            if critical_rate < 0.90:
                recommendations['deployment_considerations'].append(
                    f"Critical attack detection rate low ({critical_rate:.2%}) - enhance monitoring"
                )
        
        return recommendations
    
    def generate_evaluation_report(self, save_path: str = "/tmp/honeypot_evaluation_report.json"):
        """Generate comprehensive evaluation report"""
        
        report = {
            'report_metadata': {
                'generation_timestamp': datetime.now().isoformat(),
                'evaluations_count': len(self.evaluation_history),
                'models_evaluated': list(self.performance_metrics.keys())
            },
            'evaluation_history': self.evaluation_history,
            'performance_summary': self.performance_metrics
        }
        
        # Add model comparison if multiple models
        if len(self.performance_metrics) > 1:
            report['model_comparison'] = self.compare_models(self.performance_metrics)
        
        # Save report
        with open(save_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Evaluation report saved to {save_path}")
        return report
    
    # Manual metric calculations (fallback when sklearn not available)
    def _manual_precision(self, y_true, y_pred, average='macro'):
        """Manual precision calculation"""
        unique_labels = list(set(y_true) | set(y_pred))
        precisions = []
        
        for label in unique_labels:
            tp = np.sum((y_true == label) & (y_pred == label))
            fp = np.sum((y_true != label) & (y_pred == label))
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            precisions.append(precision)
        
        if average == 'macro':
            return np.mean(precisions)
        elif average == 'micro':
            total_tp = sum(np.sum((y_true == label) & (y_pred == label)) for label in unique_labels)
            total_fp = sum(np.sum((y_true != label) & (y_pred == label)) for label in unique_labels)
            return total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    
    def _manual_recall(self, y_true, y_pred, average='macro'):
        """Manual recall calculation"""
        unique_labels = list(set(y_true) | set(y_pred))
        recalls = []
        
        for label in unique_labels:
            tp = np.sum((y_true == label) & (y_pred == label))
            fn = np.sum((y_true == label) & (y_pred != label))
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            recalls.append(recall)
        
        if average == 'macro':
            return np.mean(recalls)
        elif average == 'micro':
            total_tp = sum(np.sum((y_true == label) & (y_pred == label)) for label in unique_labels)
            total_fn = sum(np.sum((y_true == label) & (y_pred != label)) for label in unique_labels)
            return total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    
    def _manual_f1(self, y_true, y_pred, average='macro'):
        """Manual F1 score calculation"""
        precision = self._manual_precision(y_true, y_pred, average)
        recall = self._manual_recall(y_true, y_pred, average)
        return 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0