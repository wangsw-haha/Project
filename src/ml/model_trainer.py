"""
Comprehensive Machine Learning Model Training Pipeline
Supports multiple algorithms for Industrial IoT Honeypot attack classification
"""

import json
import pickle
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple, Optional, Union
from datetime import datetime
from pathlib import Path
from loguru import logger
import warnings
warnings.filterwarnings('ignore')

# Core ML libraries (using scikit-learn as base)
try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier
    from sklearn.svm import SVC
    from sklearn.naive_bayes import GaussianNB
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV, StratifiedKFold
    from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
    from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
    from sklearn.utils.class_weight import compute_class_weight
    SKLEARN_AVAILABLE = True
except ImportError:
    logger.warning("Scikit-learn not available, using simplified models")
    SKLEARN_AVAILABLE = False


class ModelTrainer:
    """Comprehensive ML model training pipeline"""
    
    def __init__(self, random_state: int = 42):
        """Initialize trainer with configurable random state"""
        self.random_state = random_state
        self.models = {}
        self.scalers = {}
        self.label_encoder = None
        self.feature_names = []
        self.training_history = []
        
        # Initialize model configurations
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize different ML models with optimized parameters"""
        
        if not SKLEARN_AVAILABLE:
            # Simple fallback models
            self.models = {
                'simple_classifier': SimpleClassifier()
            }
            return
        
        self.models = {
            # Ensemble methods (typically best performance)
            'random_forest': RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                max_features='sqrt',
                class_weight='balanced',
                random_state=self.random_state,
                n_jobs=-1
            ),
            
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=8,
                min_samples_split=10,
                min_samples_leaf=5,
                subsample=0.8,
                random_state=self.random_state
            ),
            
            'extra_trees': ExtraTreesClassifier(
                n_estimators=200,
                max_depth=None,
                min_samples_split=5,
                min_samples_leaf=2,
                max_features='sqrt',
                class_weight='balanced',
                random_state=self.random_state,
                n_jobs=-1
            ),
            
            # Support Vector Machine
            'svm_rbf': SVC(
                C=10.0,
                gamma='scale',
                kernel='rbf',
                class_weight='balanced',
                probability=True,
                random_state=self.random_state
            ),
            
            'svm_linear': SVC(
                C=1.0,
                kernel='linear',
                class_weight='balanced',
                probability=True,
                random_state=self.random_state
            ),
            
            # Neural Network
            'neural_network': MLPClassifier(
                hidden_layer_sizes=(200, 100, 50),
                activation='relu',
                solver='adam',
                alpha=0.001,
                learning_rate='adaptive',
                max_iter=500,
                early_stopping=True,
                validation_fraction=0.1,
                random_state=self.random_state
            ),
            
            # Linear models
            'logistic_regression': LogisticRegression(
                C=1.0,
                class_weight='balanced',
                max_iter=1000,
                random_state=self.random_state,
                n_jobs=-1
            ),
            
            # Tree-based
            'decision_tree': DecisionTreeClassifier(
                max_depth=15,
                min_samples_split=10,
                min_samples_leaf=5,
                class_weight='balanced',
                random_state=self.random_state
            ),
            
            # Instance-based
            'knn': KNeighborsClassifier(
                n_neighbors=7,
                weights='distance',
                metric='minkowski',
                n_jobs=-1
            ),
            
            # Probabilistic
            'naive_bayes': GaussianNB()
        }
        
        # Initialize scalers for different models
        self.scalers = {
            'standard': StandardScaler(),
            'robust': RobustScaler()
        }
    
    def train_models(self, X: np.ndarray, y: np.ndarray, feature_names: List[str], 
                    test_size: float = 0.2, cv_folds: int = 5) -> Dict[str, Any]:
        """
        Train multiple models and compare performance
        
        Args:
            X: Feature matrix
            y: Target labels
            feature_names: List of feature names
            test_size: Test set proportion
            cv_folds: Cross-validation folds
            
        Returns:
            Dictionary with training results and model comparisons
        """
        logger.info(f"Training {len(self.models)} models on {X.shape[0]} samples with {X.shape[1]} features")
        
        self.feature_names = feature_names
        
        # Encode labels
        if SKLEARN_AVAILABLE:
            self.label_encoder = LabelEncoder()
            y_encoded = self.label_encoder.fit_transform(y)
        else:
            # Simple label encoding
            unique_labels = list(set(y))
            label_to_int = {label: i for i, label in enumerate(unique_labels)}
            self.label_encoder = label_to_int
            y_encoded = np.array([label_to_int[label] for label in y])
        
        # Split data
        if SKLEARN_AVAILABLE:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_encoded, test_size=test_size, random_state=self.random_state, 
                stratify=y_encoded
            )
        else:
            # Simple train/test split without sklearn
            split_idx = int(len(X) * (1 - test_size))
            indices = np.random.RandomState(self.random_state).permutation(len(X))
            train_idx, test_idx = indices[:split_idx], indices[split_idx:]
            X_train, X_test = X[train_idx], X[test_idx]
            y_train, y_test = y_encoded[train_idx], y_encoded[test_idx]
        
        results = {
            'models_trained': [],
            'performance_summary': {},
            'best_model': None,
            'training_time': datetime.now().isoformat(),
            'dataset_info': {
                'total_samples': X.shape[0],
                'features': X.shape[1],
                'classes': len(np.unique(y_encoded)),
                'train_samples': X_train.shape[0],
                'test_samples': X_test.shape[0]
            }
        }
        
        best_score = 0
        best_model_name = None
        
        for model_name, model in self.models.items():
            logger.info(f"Training model: {model_name}")
            
            try:
                # Train model with appropriate preprocessing
                model_result = self._train_single_model(
                    model_name, model, X_train, X_test, y_train, y_test, cv_folds
                )
                
                results['models_trained'].append(model_name)
                results['performance_summary'][model_name] = model_result
                
                # Track best model
                if model_result['test_f1_score'] > best_score:
                    best_score = model_result['test_f1_score']
                    best_model_name = model_name
                
                logger.info(f"Model {model_name} - Test F1 Score: {model_result['test_f1_score']:.4f}")
                
            except Exception as e:
                logger.error(f"Failed to train {model_name}: {str(e)}")
                continue
        
        results['best_model'] = best_model_name
        results['best_score'] = best_score
        
        # Store training history
        self.training_history.append(results)
        
        logger.info(f"Training completed. Best model: {best_model_name} (F1: {best_score:.4f})")
        
        return results
    
    def _train_single_model(self, model_name: str, model: Any, 
                           X_train: np.ndarray, X_test: np.ndarray,
                           y_train: np.ndarray, y_test: np.ndarray,
                           cv_folds: int) -> Dict[str, Any]:
        """Train a single model and evaluate performance"""
        
        start_time = datetime.now()
        
        # Determine if model needs scaling
        needs_scaling = model_name in ['svm_rbf', 'svm_linear', 'neural_network', 'knn', 'logistic_regression']
        
        if needs_scaling and SKLEARN_AVAILABLE:
            # Use robust scaler for better handling of outliers
            scaler = RobustScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            
            # Store scaler for this model
            self.scalers[model_name] = scaler
        else:
            X_train_scaled = X_train
            X_test_scaled = X_test
        
        # Train model
        if not SKLEARN_AVAILABLE:
            # Simple training for fallback
            model.fit(X_train_scaled, y_train)
            train_score = model.score(X_train_scaled, y_train)
            test_score = model.score(X_test_scaled, y_test)
            cv_scores = [test_score] * 3  # Mock CV scores
        else:
            model.fit(X_train_scaled, y_train)
            
            # Cross-validation
            cv_scores = cross_val_score(model, X_train_scaled, y_train, 
                                      cv=StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state),
                                      scoring='f1_macro')
            
            # Predictions
            train_pred = model.predict(X_train_scaled)
            test_pred = model.predict(X_test_scaled)
            
            # Scores
            train_score = f1_score(y_train, train_pred, average='macro')
            test_score = f1_score(y_test, test_pred, average='macro')
        
        training_time = (datetime.now() - start_time).total_seconds()
        
        result = {
            'model_name': model_name,
            'cv_mean': float(np.mean(cv_scores)),
            'cv_std': float(np.std(cv_scores)),
            'train_f1_score': float(train_score),
            'test_f1_score': float(test_score),
            'training_time_seconds': training_time,
            'requires_scaling': needs_scaling
        }
        
        # Add detailed metrics if sklearn is available
        if SKLEARN_AVAILABLE:
            test_accuracy = accuracy_score(y_test, test_pred)
            result['test_accuracy'] = float(test_accuracy)
            
            # Classification report
            if hasattr(self.label_encoder, 'classes_'):
                target_names = self.label_encoder.classes_
            else:
                target_names = [f'class_{i}' for i in range(len(np.unique(y_test)))]
            
            class_report = classification_report(y_test, test_pred, 
                                               target_names=target_names, 
                                               output_dict=True, zero_division=0)
            result['classification_report'] = class_report
        
        return result
    
    def hyperparameter_tuning(self, model_name: str, X: np.ndarray, y: np.ndarray, 
                            param_grid: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Perform hyperparameter tuning for a specific model
        
        Args:
            model_name: Name of model to tune
            X: Feature matrix
            y: Target labels
            param_grid: Parameter grid for tuning (optional)
            
        Returns:
            Tuning results with best parameters
        """
        if not SKLEARN_AVAILABLE:
            logger.warning("Hyperparameter tuning requires scikit-learn")
            return {}
        
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")
        
        logger.info(f"Starting hyperparameter tuning for {model_name}")
        
        # Default parameter grids
        default_param_grids = {
            'random_forest': {
                'n_estimators': [100, 200, 300],
                'max_depth': [10, 15, 20, None],
                'min_samples_split': [5, 10, 15],
                'min_samples_leaf': [1, 2, 4]
            },
            'gradient_boosting': {
                'n_estimators': [100, 150, 200],
                'learning_rate': [0.05, 0.1, 0.15],
                'max_depth': [5, 8, 10],
                'subsample': [0.8, 0.9, 1.0]
            },
            'svm_rbf': {
                'C': [0.1, 1, 10, 100],
                'gamma': ['scale', 'auto', 0.001, 0.01, 0.1]
            }
        }
        
        param_grid = param_grid or default_param_grids.get(model_name, {})
        
        if not param_grid:
            logger.warning(f"No parameter grid defined for {model_name}")
            return {}
        
        # Encode labels
        y_encoded = self.label_encoder.transform(y) if hasattr(self.label_encoder, 'transform') else y
        
        # Prepare data
        needs_scaling = model_name in ['svm_rbf', 'svm_linear', 'neural_network', 'knn', 'logistic_regression']
        if needs_scaling:
            scaler = RobustScaler()
            X_scaled = scaler.fit_transform(X)
        else:
            X_scaled = X
        
        # Grid search
        grid_search = GridSearchCV(
            estimator=self.models[model_name],
            param_grid=param_grid,
            scoring='f1_macro',
            cv=StratifiedKFold(n_splits=3, shuffle=True, random_state=self.random_state),
            n_jobs=-1,
            verbose=1
        )
        
        grid_search.fit(X_scaled, y_encoded)
        
        # Update model with best parameters
        self.models[model_name] = grid_search.best_estimator_
        
        result = {
            'model_name': model_name,
            'best_params': grid_search.best_params_,
            'best_score': float(grid_search.best_score_),
            'cv_results': {
                'mean_scores': grid_search.cv_results_['mean_test_score'].tolist(),
                'std_scores': grid_search.cv_results_['std_test_score'].tolist()
            }
        }
        
        logger.info(f"Hyperparameter tuning completed for {model_name}")
        logger.info(f"Best parameters: {grid_search.best_params_}")
        logger.info(f"Best CV score: {grid_search.best_score_:.4f}")
        
        return result
    
    def get_feature_importance(self, model_name: str, top_n: int = 20) -> Dict[str, float]:
        """Get feature importance from trained model"""
        
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")
        
        model = self.models[model_name]
        
        # Different models have different ways to get feature importance
        importance_dict = {}
        
        if hasattr(model, 'feature_importances_'):
            # Tree-based models
            importances = model.feature_importances_
            for i, importance in enumerate(importances):
                if i < len(self.feature_names):
                    importance_dict[self.feature_names[i]] = float(importance)
        
        elif hasattr(model, 'coef_'):
            # Linear models
            if len(model.coef_.shape) == 1:
                coefficients = np.abs(model.coef_)
            else:
                coefficients = np.mean(np.abs(model.coef_), axis=0)
            
            for i, coef in enumerate(coefficients):
                if i < len(self.feature_names):
                    importance_dict[self.feature_names[i]] = float(coef)
        
        else:
            logger.warning(f"Cannot extract feature importance from {model_name}")
            return {}
        
        # Sort by importance and return top N
        sorted_features = sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_features[:top_n])
    
    def save_models(self, save_dir: str = "/tmp/honeypot_models"):
        """Save all trained models and preprocessing components"""
        
        save_path = Path(save_dir)
        save_path.mkdir(exist_ok=True)
        
        # Save models
        for model_name, model in self.models.items():
            model_file = save_path / f"{model_name}_model.pkl"
            with open(model_file, 'wb') as f:
                pickle.dump(model, f)
        
        # Save scalers
        scalers_file = save_path / "scalers.pkl"
        with open(scalers_file, 'wb') as f:
            pickle.dump(self.scalers, f)
        
        # Save label encoder
        if self.label_encoder is not None:
            encoder_file = save_path / "label_encoder.pkl"
            with open(encoder_file, 'wb') as f:
                pickle.dump(self.label_encoder, f)
        
        # Save metadata
        metadata = {
            'feature_names': self.feature_names,
            'training_history': self.training_history,
            'models_available': list(self.models.keys()),
            'save_timestamp': datetime.now().isoformat()
        }
        
        metadata_file = save_path / "models_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Models saved to {save_path}")
        
        return str(save_path)
    
    def load_models(self, save_dir: str = "/tmp/honeypot_models"):
        """Load previously trained models"""
        
        save_path = Path(save_dir)
        if not save_path.exists():
            raise FileNotFoundError(f"Model directory {save_path} not found")
        
        # Load metadata
        metadata_file = save_path / "models_metadata.json"
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            self.feature_names = metadata.get('feature_names', [])
            self.training_history = metadata.get('training_history', [])
        
        # Load models
        for model_file in save_path.glob("*_model.pkl"):
            model_name = model_file.stem.replace('_model', '')
            with open(model_file, 'rb') as f:
                self.models[model_name] = pickle.load(f)
        
        # Load scalers
        scalers_file = save_path / "scalers.pkl"
        if scalers_file.exists():
            with open(scalers_file, 'rb') as f:
                self.scalers = pickle.load(f)
        
        # Load label encoder
        encoder_file = save_path / "label_encoder.pkl"
        if encoder_file.exists():
            with open(encoder_file, 'rb') as f:
                self.label_encoder = pickle.load(f)
        
        logger.info(f"Models loaded from {save_path}")
        logger.info(f"Available models: {list(self.models.keys())}")
    
    def predict(self, model_name: str, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Make predictions using trained model
        
        Args:
            model_name: Name of model to use
            X: Feature matrix
            
        Returns:
            Tuple of (predictions, probabilities)
        """
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not trained")
        
        model = self.models[model_name]
        
        # Apply scaling if needed
        if model_name in self.scalers:
            X_scaled = self.scalers[model_name].transform(X)
        else:
            X_scaled = X
        
        # Predictions
        predictions = model.predict(X_scaled)
        
        # Probabilities (if available)
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(X_scaled)
        else:
            # Create dummy probabilities
            probabilities = np.ones((len(predictions), len(np.unique(predictions)))) / len(np.unique(predictions))
        
        # Decode labels
        if SKLEARN_AVAILABLE and hasattr(self.label_encoder, 'inverse_transform'):
            predictions = self.label_encoder.inverse_transform(predictions)
        
        return predictions, probabilities


class SimpleClassifier:
    """Simple fallback classifier when sklearn is not available"""
    
    def __init__(self):
        self.patterns = {}
        self.default_class = 'unknown_attack'
    
    def fit(self, X, y):
        """Simple pattern-based training"""
        # Learn simple patterns based on feature values
        for i, label in enumerate(y):
            if label not in self.patterns:
                self.patterns[label] = []
            self.patterns[label].append(X[i])
        return self
    
    def predict(self, X):
        """Simple pattern matching prediction"""
        predictions = []
        for sample in X:
            best_match = self.default_class
            best_distance = float('inf')
            
            for label, patterns in self.patterns.items():
                for pattern in patterns:
                    # Simple Euclidean distance
                    distance = np.sqrt(np.sum((sample - pattern) ** 2))
                    if distance < best_distance:
                        best_distance = distance
                        best_match = label
            
            predictions.append(best_match)
        
        return np.array(predictions)
    
    def score(self, X, y):
        """Simple accuracy score"""
        predictions = self.predict(X)
        return np.mean(predictions == y)