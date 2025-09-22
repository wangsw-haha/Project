#!/usr/bin/env python3
"""
Enhanced Research Analysis Tool for Industrial IoT Honeypot
Provides comprehensive analysis and visualization for research purposes
"""

import os
import sys
import json
import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
from loguru import logger

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def analyze_training_results(results_dir: Path) -> Dict[str, Any]:
    """Analyze training results for research insights"""
    
    analysis = {
        'timestamp': datetime.now().isoformat(),
        'results_directory': str(results_dir),
        'analysis_summary': {},
        'research_insights': {},
        'recommendations': []
    }
    
    try:
        # Load complete pipeline results
        pipeline_results_file = results_dir / "complete_pipeline_results.json"
        if pipeline_results_file.exists():
            with open(pipeline_results_file, 'r') as f:
                pipeline_results = json.load(f)
            
            analysis['pipeline_results'] = pipeline_results
            
            # Analyze model performance
            if 'model_evaluation' in pipeline_results:
                model_eval = pipeline_results['model_evaluation']
                
                # Extract performance metrics
                performance_summary = {}
                best_model = None
                best_f1 = 0
                
                for model_name, metrics in model_eval.items():
                    if isinstance(metrics, dict) and 'basic_metrics' in metrics:
                        basic_metrics = metrics['basic_metrics']
                        performance_summary[model_name] = {
                            'accuracy': basic_metrics.get('accuracy', 0),
                            'f1_score': basic_metrics.get('f1_score_macro', 0),
                            'precision': basic_metrics.get('precision_macro', 0),
                            'recall': basic_metrics.get('recall_macro', 0)
                        }
                        
                        current_f1 = basic_metrics.get('f1_score_macro', 0)
                        if current_f1 > best_f1:
                            best_f1 = current_f1
                            best_model = model_name
                
                analysis['analysis_summary']['performance_metrics'] = performance_summary
                analysis['analysis_summary']['best_model'] = best_model
                analysis['analysis_summary']['best_f1_score'] = best_f1
                
                # Research insights
                analysis['research_insights']['model_comparison'] = {
                    'total_models_tested': len(performance_summary),
                    'models_with_perfect_f1': len([m for m, metrics in performance_summary.items() 
                                                 if metrics['f1_score'] >= 0.99]),
                    'average_accuracy': np.mean([metrics['accuracy'] for metrics in performance_summary.values()]),
                    'accuracy_std': np.std([metrics['accuracy'] for metrics in performance_summary.values()]),
                    'best_performers': sorted(performance_summary.items(), 
                                            key=lambda x: x[1]['f1_score'], reverse=True)[:3]
                }
        
        # Analyze feature importance if available
        feature_file = results_dir / "feature_names.json"
        if feature_file.exists():
            with open(feature_file, 'r') as f:
                features = json.load(f)
            
            analysis['research_insights']['feature_analysis'] = {
                'total_features': len(features),
                'feature_categories': categorize_features(features),
                'feature_recommendations': generate_feature_recommendations(features)
            }
        
        # Generate research recommendations
        analysis['recommendations'] = generate_research_recommendations(analysis)
        
    except Exception as e:
        logger.error(f"Error analyzing results: {e}")
        analysis['error'] = str(e)
    
    return analysis

def categorize_features(features: List[str]) -> Dict[str, List[str]]:
    """Categorize features for analysis"""
    
    categories = {
        'protocol_features': [],
        'statistical_features': [],
        'temporal_features': [],
        'behavioral_features': [],
        'metadata_features': [],
        'other_features': []
    }
    
    for feature in features:
        feature_lower = feature.lower()
        
        if any(protocol in feature_lower for protocol in ['modbus', 'ssh', 'http', 'tcp', 'udp']):
            categories['protocol_features'].append(feature)
        elif any(stat in feature_lower for stat in ['entropy', 'length', 'ratio', 'freq', 'count']):
            categories['statistical_features'].append(feature)
        elif any(temp in feature_lower for temp in ['time', 'hour', 'day', 'week']):
            categories['temporal_features'].append(feature)
        elif any(behav in feature_lower for behav in ['request', 'connection', 'pattern', 'sequence']):
            categories['behavioral_features'].append(feature)
        elif any(meta in feature_lower for meta in ['ip', 'port', 'service', 'source']):
            categories['metadata_features'].append(feature)
        else:
            categories['other_features'].append(feature)
    
    return categories

def generate_feature_recommendations(features: List[str]) -> List[str]:
    """Generate feature engineering recommendations"""
    
    recommendations = []
    
    # Check feature coverage
    has_temporal = any('time' in f.lower() or 'hour' in f.lower() for f in features)
    has_statistical = any('entropy' in f.lower() or 'length' in f.lower() for f in features)
    has_protocol = any('modbus' in f.lower() or 'ssh' in f.lower() for f in features)
    
    if not has_temporal:
        recommendations.append("Consider adding temporal features (time-of-day, seasonality)")
    
    if not has_statistical:
        recommendations.append("Consider adding statistical features (entropy, character distributions)")
    
    if not has_protocol:
        recommendations.append("Consider adding protocol-specific features")
    
    recommendations.append("Explore feature interactions and polynomial features")
    recommendations.append("Consider dimensionality reduction techniques (PCA, LDA)")
    recommendations.append("Investigate feature selection methods for optimization")
    
    return recommendations

def generate_research_recommendations(analysis: Dict[str, Any]) -> List[str]:
    """Generate research recommendations based on analysis"""
    
    recommendations = []
    
    # Performance-based recommendations
    insights = analysis.get('research_insights', {})
    model_comparison = insights.get('model_comparison', {})
    
    if model_comparison.get('models_with_perfect_f1', 0) > 0:
        recommendations.append("⚠️  Perfect F1 scores may indicate overfitting - validate with real-world data")
        recommendations.append("📊 Consider cross-validation with larger, more diverse datasets")
    
    avg_accuracy = model_comparison.get('average_accuracy', 0)
    if avg_accuracy > 0.95:
        recommendations.append("🎯 High accuracy achieved - focus on real-world robustness testing")
    elif avg_accuracy < 0.8:
        recommendations.append("📈 Consider feature engineering improvements and hyperparameter tuning")
    
    # Research direction recommendations
    recommendations.extend([
        "🔬 Conduct adversarial testing with sophisticated attack patterns",
        "🏭 Validate models with real industrial network data",
        "🤖 Explore ensemble methods combining multiple best performers",
        "📚 Document feature importance for domain expert validation",
        "🔄 Implement online learning for adaptive model updates",
        "🎭 Test adaptive response effectiveness with human attackers",
        "📊 Create benchmarking datasets for reproducible research",
        "🔍 Investigate zero-day attack detection capabilities"
    ])
    
    return recommendations

def generate_research_report(analysis: Dict[str, Any], output_file: Path):
    """Generate comprehensive research report"""
    
    report_content = f"""
# Industrial IoT Honeypot ML Analysis Report

Generated: {analysis['timestamp']}
Results Directory: {analysis['results_directory']}

## Executive Summary

This analysis provides comprehensive insights into the machine learning pipeline performance for the Industrial IoT Honeypot Adaptive Response System.

## Model Performance Analysis

"""
    
    # Add performance metrics table
    insights = analysis.get('research_insights', {})
    model_comparison = insights.get('model_comparison', {})
    
    if 'best_performers' in model_comparison:
        report_content += "### Top Performing Models\n\n"
        report_content += "| Model | F1 Score | Accuracy | Precision | Recall |\n"
        report_content += "|-------|----------|----------|-----------|--------|\n"
        
        for model_name, metrics in model_comparison['best_performers']:
            report_content += f"| {model_name} | {metrics['f1_score']:.4f} | {metrics['accuracy']:.4f} | {metrics['precision']:.4f} | {metrics['recall']:.4f} |\n"
        
        report_content += "\n"
    
    # Add feature analysis
    if 'feature_analysis' in insights:
        feature_analysis = insights['feature_analysis']
        report_content += f"""
### Feature Analysis

- **Total Features**: {feature_analysis['total_features']}
- **Feature Categories**:
"""
        
        for category, features in feature_analysis['feature_categories'].items():
            if features:
                report_content += f"  - {category.replace('_', ' ').title()}: {len(features)} features\n"
    
    # Add recommendations
    if analysis.get('recommendations'):
        report_content += "\n## Research Recommendations\n\n"
        for i, rec in enumerate(analysis['recommendations'], 1):
            report_content += f"{i}. {rec}\n"
    
    report_content += f"""

## Statistical Summary

- **Models Tested**: {model_comparison.get('total_models_tested', 0)}
- **Models with Perfect F1**: {model_comparison.get('models_with_perfect_f1', 0)}
- **Average Accuracy**: {model_comparison.get('average_accuracy', 0):.4f}
- **Accuracy Standard Deviation**: {model_comparison.get('accuracy_std', 0):.4f}

## Next Steps for Research

1. **Validate with Real Data**: Test models with actual industrial network traffic
2. **Adversarial Testing**: Evaluate robustness against sophisticated attacks  
3. **Feature Engineering**: Explore advanced feature combinations
4. **Online Learning**: Implement continuous model improvement
5. **Publication**: Document findings for academic publication

---

*This report was generated automatically by the Industrial IoT Honeypot Research Analysis Tool*
"""
    
    with open(output_file, 'w') as f:
        f.write(report_content)
    
    logger.info(f"Research report saved to {output_file}")

def main():
    """Main function for research analysis"""
    
    parser = argparse.ArgumentParser(description="Enhanced Research Analysis Tool")
    parser.add_argument("--results-dir", type=Path, default="/tmp/honeypot_ml_training",
                       help="Directory containing training results")
    parser.add_argument("--output-dir", type=Path, default="/tmp/research_analysis",
                       help="Output directory for analysis results")
    
    args = parser.parse_args()
    
    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    print("🔬 Industrial IoT Honeypot Research Analysis Tool")
    print("=" * 60)
    
    # Perform analysis
    print(f"📊 Analyzing results from: {args.results_dir}")
    analysis = analyze_training_results(args.results_dir)
    
    # Save detailed analysis
    analysis_file = args.output_dir / "detailed_analysis.json"
    with open(analysis_file, 'w') as f:
        json.dump(analysis, f, indent=2)
    
    # Generate research report
    report_file = args.output_dir / "research_report.md"
    generate_research_report(analysis, report_file)
    
    # Print summary
    print("\n📈 Analysis Summary:")
    print("-" * 40)
    
    if 'analysis_summary' in analysis:
        summary = analysis['analysis_summary']
        if 'best_model' in summary:
            print(f"🏆 Best Model: {summary['best_model']}")
            print(f"📊 Best F1 Score: {summary['best_f1_score']:.4f}")
    
    insights = analysis.get('research_insights', {})
    if 'model_comparison' in insights:
        model_comp = insights['model_comparison']
        print(f"🤖 Models Tested: {model_comp.get('total_models_tested', 0)}")
        print(f"⭐ Perfect F1 Models: {model_comp.get('models_with_perfect_f1', 0)}")
        print(f"📊 Average Accuracy: {model_comp.get('average_accuracy', 0):.4f}")
    
    print(f"\n💾 Detailed analysis saved to: {analysis_file}")
    print(f"📄 Research report saved to: {report_file}")
    print(f"📁 All outputs in: {args.output_dir}")
    
    # Show key recommendations
    if analysis.get('recommendations'):
        print("\n💡 Key Research Recommendations:")
        for i, rec in enumerate(analysis['recommendations'][:5], 1):
            print(f"   {i}. {rec}")
        
        if len(analysis['recommendations']) > 5:
            print(f"   ... and {len(analysis['recommendations']) - 5} more (see full report)")
    
    print("\n✅ Research analysis completed successfully!")

if __name__ == "__main__":
    main()