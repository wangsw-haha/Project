#!/usr/bin/env python3
"""
Industrial IoT Honeypot Machine Learning Training Pipeline
Comprehensive training system for attack classification and adaptive response optimization
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path
from loguru import logger

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import ML components
from ml.feature_extractor import FeatureExtractor
from ml.model_trainer import ModelTrainer
from ml.model_evaluator import ModelEvaluator
from ml.adaptive_optimizer import AdaptiveResponseOptimizer

# Import existing classification components
from classification.dataset_generator import AttackDatasetGenerator
from classification.attack_classifier import AttackType


class HoneypotMLPipeline:
    """Complete ML pipeline for Industrial IoT Honeypot"""
    
    def __init__(self, output_dir: str = "/tmp/honeypot_ml_training"):
        """Initialize ML pipeline"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self.feature_extractor = FeatureExtractor()
        self.model_trainer = ModelTrainer()
        self.model_evaluator = ModelEvaluator()
        self.adaptive_optimizer = AdaptiveResponseOptimizer()
        self.dataset_generator = AttackDatasetGenerator()
        
        # Configuration
        self.config = {
            'training_samples': 3000,
            'testing_samples': 800,
            'validation_samples': 500,
            'test_size': 0.2,
            'cv_folds': 5,
            'hyperparameter_tuning': True,
            'feature_selection': True,
            'model_comparison': True
        }
        
        logger.info(f"ML Pipeline initialized - Output directory: {self.output_dir}")
    
    def run_complete_pipeline(self, config_updates: dict = None) -> dict:
        """Run the complete ML training pipeline"""
        
        if config_updates:
            self.config.update(config_updates)
        
        logger.info("🚀 Starting Complete ML Pipeline for Industrial IoT Honeypot")
        logger.info("=" * 80)
        
        pipeline_results = {
            'pipeline_start': datetime.now().isoformat(),
            'config': self.config.copy(),
            'stages': {}
        }
        
        try:
            # Stage 1: Dataset Generation
            logger.info("📊 Stage 1: Generating Attack Datasets")
            dataset_results = self._generate_datasets()
            pipeline_results['stages']['dataset_generation'] = dataset_results
            
            # Stage 2: Feature Extraction
            logger.info("🔍 Stage 2: Feature Extraction")
            feature_results = self._extract_features(dataset_results)
            pipeline_results['stages']['feature_extraction'] = feature_results
            
            # Stage 3: Model Training
            logger.info("🤖 Stage 3: Model Training")
            training_results = self._train_models(feature_results)
            pipeline_results['stages']['model_training'] = training_results
            
            # Stage 4: Model Evaluation
            logger.info("📈 Stage 4: Model Evaluation")
            evaluation_results = self._evaluate_models(feature_results, training_results)
            pipeline_results['stages']['model_evaluation'] = evaluation_results
            
            # Stage 5: Hyperparameter Tuning (if enabled)
            if self.config['hyperparameter_tuning']:
                logger.info("⚙️ Stage 5: Hyperparameter Tuning")
                tuning_results = self._hyperparameter_tuning(feature_results, evaluation_results)
                pipeline_results['stages']['hyperparameter_tuning'] = tuning_results
            
            # Stage 6: Adaptive Response Optimization
            logger.info("🎯 Stage 6: Adaptive Response Optimization")
            optimization_results = self._optimize_responses(dataset_results, evaluation_results)
            pipeline_results['stages']['response_optimization'] = optimization_results
            
            # Stage 7: Final Model Selection and Deployment Prep
            logger.info("🏆 Stage 7: Final Model Selection")
            deployment_results = self._prepare_deployment(pipeline_results)
            pipeline_results['stages']['deployment_preparation'] = deployment_results
            
            pipeline_results['pipeline_end'] = datetime.now().isoformat()
            pipeline_results['success'] = True
            
            # Save comprehensive results
            self._save_pipeline_results(pipeline_results)
            
            logger.info("✅ Complete ML Pipeline Finished Successfully!")
            self._print_final_summary(pipeline_results)
            
        except Exception as e:
            logger.error(f"❌ Pipeline failed: {str(e)}")
            pipeline_results['error'] = str(e)
            pipeline_results['success'] = False
            raise
        
        return pipeline_results
    
    def _generate_datasets(self) -> dict:
        """Generate attack datasets"""
        
        # Generate comprehensive datasets
        training_data = self.dataset_generator.generate_dataset(self.config['training_samples'])
        testing_data = self.dataset_generator.generate_dataset(self.config['testing_samples'])
        validation_data = self.dataset_generator.generate_dataset(self.config['validation_samples'])
        
        # Save datasets
        dataset_files = {
            'training': self.output_dir / "attack_training_dataset.json",
            'testing': self.output_dir / "attack_testing_dataset.json",
            'validation': self.output_dir / "attack_validation_dataset.json"
        }
        
        self.dataset_generator.save_dataset(training_data, str(dataset_files['training']))
        self.dataset_generator.save_dataset(testing_data, str(dataset_files['testing']))
        self.dataset_generator.save_dataset(validation_data, str(dataset_files['validation']))
        
        # Analyze dataset distribution
        from collections import Counter
        
        def analyze_distribution(data, name):
            labels = [sample['true_label'] for sample in data]
            services = [sample['service'] for sample in data]
            
            return {
                'size': len(data),
                'attack_types': dict(Counter(labels)),
                'services': dict(Counter(services)),
                'balance_score': min(Counter(labels).values()) / max(Counter(labels).values())
            }
        
        results = {
            'datasets_generated': len(dataset_files),
            'training_analysis': analyze_distribution(training_data, 'Training'),
            'testing_analysis': analyze_distribution(testing_data, 'Testing'),
            'validation_analysis': analyze_distribution(validation_data, 'Validation'),
            'total_samples': len(training_data) + len(testing_data) + len(validation_data),
            'dataset_files': {k: str(v) for k, v in dataset_files.items()}
        }
        
        logger.info(f"Generated {results['total_samples']} samples across {len(dataset_files)} datasets")
        return results
    
    def _extract_features(self, dataset_results: dict) -> dict:
        """Extract features from datasets"""
        
        # Load datasets
        with open(dataset_results['dataset_files']['training'], 'r') as f:
            training_data = json.load(f)
        
        with open(dataset_results['dataset_files']['testing'], 'r') as f:
            testing_data = json.load(f)
        
        # Extract features
        X_train, y_train, feature_names = self.feature_extractor.extract_features(training_data)
        X_test, y_test, _ = self.feature_extractor.extract_features(testing_data)
        
        # Save feature data
        feature_files = {
            'X_train': self.output_dir / "X_train.npy",
            'y_train': self.output_dir / "y_train.npy",
            'X_test': self.output_dir / "X_test.npy",
            'y_test': self.output_dir / "y_test.npy",
            'feature_names': self.output_dir / "feature_names.json"
        }
        
        import numpy as np
        np.save(feature_files['X_train'], X_train)
        np.save(feature_files['y_train'], y_train)
        np.save(feature_files['X_test'], X_test)
        np.save(feature_files['y_test'], y_test)
        
        with open(feature_files['feature_names'], 'w') as f:
            json.dump(feature_names, f, indent=2)
        
        results = {
            'feature_count': len(feature_names), 
            'training_samples': X_train.shape[0],
            'testing_samples': X_test.shape[0],
            'feature_names': feature_names,
            'feature_files': {k: str(v) for k, v in feature_files.items()},
            'feature_importance_preview': self.feature_extractor.get_feature_importance_names()
        }
        
        logger.info(f"Extracted {results['feature_count']} features from {results['training_samples']} training samples")
        return results
    
    def _train_models(self, feature_results: dict) -> dict:
        """Train multiple ML models"""
        
        # Load feature data
        import numpy as np
        X_train = np.load(feature_results['feature_files']['X_train'])
        y_train = np.load(feature_results['feature_files']['y_train'])
        X_test = np.load(feature_results['feature_files']['X_test'])
        y_test = np.load(feature_results['feature_files']['y_test'])
        
        feature_names = feature_results['feature_names']
        
        # Combine for training (we'll split again internally)
        import numpy as np
        X_combined = np.vstack([X_train, X_test])
        y_combined = np.hstack([y_train, y_test])
        
        # Train models
        training_results = self.model_trainer.train_models(
            X_combined, y_combined, feature_names,
            test_size=self.config['test_size'],
            cv_folds=self.config['cv_folds']
        )
        
        # Save models
        model_save_path = self.model_trainer.save_models(str(self.output_dir / "models"))
        training_results['model_save_path'] = model_save_path
        
        # Get feature importance for best model
        if training_results['best_model']:
            feature_importance = self.model_trainer.get_feature_importance(
                training_results['best_model'], top_n=20
            )
            training_results['top_features'] = feature_importance
        
        logger.info(f"Trained {len(training_results['models_trained'])} models")
        logger.info(f"Best model: {training_results['best_model']} (F1: {training_results['best_score']:.4f})")
        
        return training_results
    
    def _evaluate_models(self, feature_results: dict, training_results: dict) -> dict:
        """Evaluate trained models"""
        
        # Load test data
        import numpy as np
        X_test = np.load(feature_results['feature_files']['X_test'])
        y_test = np.load(feature_results['feature_files']['y_test'])
        
        evaluation_results = {}
        
        # Evaluate each trained model
        for model_name in training_results['models_trained']:
            try:
                # Make predictions
                y_pred, y_proba = self.model_trainer.predict(model_name, X_test)
                
                # Evaluate
                eval_result = self.model_evaluator.evaluate_model(
                    model_name, y_test, y_pred, y_proba,
                    attack_types=list(set(y_test))
                )
                
                evaluation_results[model_name] = eval_result
                
            except Exception as e:
                logger.error(f"Failed to evaluate {model_name}: {str(e)}")
                continue
        
        # Model comparison
        if len(evaluation_results) > 1:
            comparison_results = self.model_evaluator.compare_models(evaluation_results)
            evaluation_results['model_comparison'] = comparison_results
        
        # Generate evaluation report
        report_path = self.output_dir / "evaluation_report.json"
        full_report = self.model_evaluator.generate_evaluation_report(str(report_path))
        evaluation_results['report_path'] = str(report_path)
        
        logger.info(f"Evaluated {len(evaluation_results)} models")
        return evaluation_results
    
    def _hyperparameter_tuning(self, feature_results: dict, evaluation_results: dict) -> dict:
        """Perform hyperparameter tuning on best models"""
        
        # Load combined data for tuning
        import numpy as np
        X_train = np.load(feature_results['feature_files']['X_train'])
        y_train = np.load(feature_results['feature_files']['y_train'])
        X_test = np.load(feature_results['feature_files']['X_test'])
        y_test = np.load(feature_results['feature_files']['y_test'])
        
        X_combined = np.vstack([X_train, X_test])
        y_combined = np.hstack([y_train, y_test])
        
        # Select top models for tuning
        if 'model_comparison' in evaluation_results:
            top_models = evaluation_results['model_comparison']['rankings']['overall'][:3]
        else:
            top_models = list(evaluation_results.keys())[:3]
        
        tuning_results = {}
        
        for model_name in top_models:
            if model_name == 'model_comparison':  # Skip comparison entry
                continue
                
            try:
                logger.info(f"Tuning hyperparameters for {model_name}")
                
                tuning_result = self.model_trainer.hyperparameter_tuning(
                    model_name, X_combined, y_combined
                )
                
                if tuning_result:
                    tuning_results[model_name] = tuning_result
                    logger.info(f"Tuning completed for {model_name}: {tuning_result['best_score']:.4f}")
                
            except Exception as e:
                logger.error(f"Hyperparameter tuning failed for {model_name}: {str(e)}")
                continue
        
        # Save updated models
        if tuning_results:
            updated_model_path = self.model_trainer.save_models(str(self.output_dir / "tuned_models"))
            tuning_results['updated_models_path'] = updated_model_path
        
        return tuning_results
    
    def _optimize_responses(self, dataset_results: dict, evaluation_results: dict) -> dict:
        """Optimize adaptive responses"""
        
        # Load training data for response optimization
        with open(dataset_results['dataset_files']['training'], 'r') as f:
            training_data = json.load(f)
        
        # Simulate adaptive response optimization
        optimization_results = {
            'simulated_attacks': 0,
            'response_strategies_tested': 0,
            'optimization_metrics': {}
        }
        
        # Simulate different attack scenarios and optimize responses
        for i, sample in enumerate(training_data[:100]):  # Sample subset for demo
            try:
                # Create mock attack classification
                from classification.attack_classifier import AttackClassification, AttackType
                
                attack_type = AttackType(sample['true_label'])
                classification = AttackClassification(
                    attack_type=attack_type,
                    confidence=0.8,
                    severity='medium',
                    description=f"Simulated {attack_type.value}",
                    indicators=['simulation'],
                    response_strategy='adaptive'
                )
                
                # Get optimized response
                attack_context = {
                    'source_ip': sample['source_ip'],
                    'service': sample['service'],
                    'payload': sample['payload']
                }
                
                optimized_response = self.adaptive_optimizer.optimize_response_strategy(
                    classification, attack_context
                )
                
                # Simulate effectiveness feedback
                effectiveness_metrics = {
                    'attacker_engagement_time': 0.7 + (i % 3) * 0.1,
                    'deception_success_rate': 0.8 + (i % 4) * 0.05,
                    'resource_efficiency': 0.6 + (i % 5) * 0.08,
                    'false_positive_rate': 0.05 + (i % 3) * 0.02
                }
                
                self.adaptive_optimizer.update_response_effectiveness(
                    attack_type, optimized_response['strategy'], effectiveness_metrics
                )
                
                optimization_results['simulated_attacks'] += 1
                
            except Exception as e:
                logger.warning(f"Response optimization simulation failed for sample {i}: {str(e)}")
                continue
        
        # Generate optimization report
        optimization_report = self.adaptive_optimizer.get_optimization_report()
        
        # Save optimization report
        opt_report_path = self.output_dir / "response_optimization_report.json"
        with open(opt_report_path, 'w') as f:
            json.dump(optimization_report, f, indent=2)
        
        optimization_results.update({
            'optimization_report': optimization_report,
            'report_path': str(opt_report_path),
            'strategies_optimized': len(optimization_report.get('strategy_performance', {}))
        })
        
        logger.info(f"Optimized responses for {optimization_results['simulated_attacks']} attack scenarios")
        return optimization_results
    
    def _prepare_deployment(self, pipeline_results: dict) -> dict:
        """Prepare models and optimizations for deployment"""
        
        deployment_results = {
            'deployment_timestamp': datetime.now().isoformat(),
            'best_model_info': {},
            'deployment_artifacts': [],
            'deployment_recommendations': []
        }
        
        # Best model information
        if 'model_evaluation' in pipeline_results['stages']:
            eval_results = pipeline_results['stages']['model_evaluation']
            if 'model_comparison' in eval_results:
                best_model = eval_results['model_comparison']['rankings']['overall'][0]
                best_score = eval_results['model_comparison']['overall_scores'][best_model]
                
                deployment_results['best_model_info'] = {
                    'model_name': best_model,
                    'overall_score': best_score,
                    'model_path': pipeline_results['stages']['model_training']['model_save_path']
                }
        
        # Create deployment package
        deployment_package = {
            'model_artifacts': str(self.output_dir / "models"),
            'feature_extractor_config': str(self.output_dir / "feature_names.json"),
            'evaluation_report': str(self.output_dir / "evaluation_report.json"),
            'optimization_config': str(self.output_dir / "response_optimization_report.json"),
            'pipeline_config': self.config
        }
        
        # Save deployment package info
        deployment_info_path = self.output_dir / "deployment_package.json"
        with open(deployment_info_path, 'w') as f:
            json.dump(deployment_package, f, indent=2)
        
        deployment_results['deployment_package'] = str(deployment_info_path)
        deployment_results['deployment_artifacts'] = list(deployment_package.values())
        
        # Generate deployment recommendations
        recommendations = []
        
        if deployment_results['best_model_info']:
            score = deployment_results['best_model_info']['overall_score']
            if score > 0.9:
                recommendations.append("✅ Model performance excellent - ready for production deployment")
            elif score > 0.8:
                recommendations.append("⚠️ Model performance good - consider monitoring in production")
            else:
                recommendations.append("❌ Model performance needs improvement before deployment")
        
        recommendations.extend([
            "📊 Monitor model performance in production environment",
            "🔄 Implement periodic model retraining pipeline",
            "🛡️ Set up response effectiveness monitoring",
            "📈 Configure adaptive optimization feedback loops"
        ])
        
        deployment_results['deployment_recommendations'] = recommendations
        
        return deployment_results
    
    def _save_pipeline_results(self, results: dict):
        """Save comprehensive pipeline results"""
        
        results_file = self.output_dir / "complete_pipeline_results.json"
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Complete pipeline results saved to {results_file}")
    
    def _print_final_summary(self, results: dict):
        """Print final summary of pipeline results"""
        
        print("\n" + "="*80)
        print("🎯 INDUSTRIAL IOT HONEYPOT ML PIPELINE SUMMARY")
        print("="*80)
        
        # Dataset summary
        if 'dataset_generation' in results['stages']:
            ds_results = results['stages']['dataset_generation']
            print(f"📊 Dataset: {ds_results['total_samples']} samples generated")
        
        # Feature extraction summary
        if 'feature_extraction' in results['stages']:
            fe_results = results['stages']['feature_extraction']
            print(f"🔍 Features: {fe_results['feature_count']} features extracted")
        
        # Model training summary
        if 'model_training' in results['stages']:
            mt_results = results['stages']['model_training']
            print(f"🤖 Models: {len(mt_results['models_trained'])} models trained")
            print(f"🏆 Best Model: {mt_results['best_model']} (F1: {mt_results['best_score']:.4f})")
        
        # Evaluation summary
        if 'model_evaluation' in results['stages']:
            eval_results = results['stages']['model_evaluation'] 
            evaluated_count = len([k for k in eval_results.keys() if k != 'model_comparison' and k != 'report_path'])
            print(f"📈 Evaluation: {evaluated_count} models evaluated")
        
        # Optimization summary
        if 'response_optimization' in results['stages']:
            opt_results = results['stages']['response_optimization']
            print(f"🎯 Optimization: {opt_results['simulated_attacks']} attack scenarios processed")
        
        # Deployment readiness
        if 'deployment_preparation' in results['stages']:
            deploy_results = results['stages']['deployment_preparation']
            print(f"🚀 Deployment: Ready with {len(deploy_results['deployment_artifacts'])} artifacts")
        
        print(f"\n📁 All results saved to: {self.output_dir}")
        
        print("\n💡 Next Steps for Research:")
        print("   1. Analyze model performance metrics in evaluation report")
        print("   2. Review feature importance for domain insights")
        print("   3. Test adaptive response optimization in controlled environment")  
        print("   4. Implement continuous learning pipeline")
        print("   5. Deploy best model in honeypot system")
        
        print("\n" + "="*80)


def main():
    """Main function for running the ML pipeline"""
    
    parser = argparse.ArgumentParser(description='Industrial IoT Honeypot ML Training Pipeline')
    parser.add_argument('--output-dir', default='/tmp/honeypot_ml_training',
                       help='Output directory for results')
    parser.add_argument('--training-samples', type=int, default=3000,
                       help='Number of training samples to generate')
    parser.add_argument('--testing-samples', type=int, default=800,
                       help='Number of testing samples to generate')
    parser.add_argument('--validation-samples', type=int, default=500,
                       help='Number of validation samples to generate')
    parser.add_argument('--no-hyperparameter-tuning', action='store_true',
                       help='Skip hyperparameter tuning')
    parser.add_argument('--quick-run', action='store_true',
                       help='Quick run with reduced samples for testing')
    
    args = parser.parse_args()
    
    # Configuration updates based on arguments
    config_updates = {
        'training_samples': args.training_samples,
        'testing_samples': args.testing_samples,
        'validation_samples': args.validation_samples,
        'hyperparameter_tuning': not args.no_hyperparameter_tuning
    }
    
    # Quick run configuration
    if args.quick_run:
        config_updates.update({
            'training_samples': 500,
            'testing_samples': 150,
            'validation_samples': 100,
            'hyperparameter_tuning': False
        })
        logger.info("🚀 Quick run mode enabled - using reduced sample sizes")
    
    # Initialize and run pipeline
    pipeline = HoneypotMLPipeline(args.output_dir)
    
    try:
        results = pipeline.run_complete_pipeline(config_updates)
        
        if results['success']:
            print("\n✅ ML Pipeline completed successfully!")
            print(f"📊 Results available in: {args.output_dir}")
            return 0
        else:
            print("\n❌ ML Pipeline failed!")
            return 1
            
    except KeyboardInterrupt:
        logger.info("Pipeline interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Pipeline failed with error: {str(e)}")
        return 1


if __name__ == "__main__":
    exit(main())