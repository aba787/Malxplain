
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os

class MLPredictor:
    def __init__(self):
        self.models = {
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'svm': SVC(kernel='rbf', random_state=42),
            'neural_network': MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=500, random_state=42)
        }
        self.trained_models = {}
        self.best_model = None
        self.best_model_name = None
        
    def train_models(self, X, y, test_size=0.2):
        """Train all models and evaluate performance"""
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42)
        
        results = {}
        
        for name, model in self.models.items():
            print(f"Training {name}...")
            
            # Train model
            model.fit(X_train, y_train)
            
            # Make predictions
            y_pred = model.predict(X_test)
            
            # Calculate accuracy
            accuracy = accuracy_score(y_test, y_pred)
            
            # Get classification report
            report = classification_report(y_test, y_pred, output_dict=True)
            
            # Get confusion matrix
            cm = confusion_matrix(y_test, y_pred)
            
            # Cross validation
            cv_scores = cross_val_score(model, X_train, y_train, cv=5)
            
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'classification_report': report,
                'confusion_matrix': cm,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'y_test': y_test,
                'y_pred': y_pred
            }
            
            self.trained_models[name] = model
            
            print(f"{name} - Accuracy: {accuracy:.4f}, CV Mean: {cv_scores.mean():.4f}")
            
        # Find best model
        best_accuracy = max(results.values(), key=lambda x: x['accuracy'])['accuracy']
        self.best_model_name = [name for name, result in results.items() if result['accuracy'] == best_accuracy][0]
        self.best_model = self.trained_models[self.best_model_name]
        
        print(f"\nBest model: {self.best_model_name} with accuracy: {best_accuracy:.4f}")
        
        return results
    
    def evaluate_models(self, results):
        """Generate evaluation plots and reports"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Model Evaluation Results', fontsize=16)
        
        # Accuracy comparison
        model_names = list(results.keys())
        accuracies = [results[name]['accuracy'] for name in model_names]
        
        axes[0, 0].bar(model_names, accuracies)
        axes[0, 0].set_title('Model Accuracy Comparison')
        axes[0, 0].set_ylabel('Accuracy')
        axes[0, 0].set_ylim(0, 1)
        
        # Cross-validation scores
        cv_means = [results[name]['cv_mean'] for name in model_names]
        cv_stds = [results[name]['cv_std'] for name in model_names]
        
        axes[0, 1].bar(model_names, cv_means, yerr=cv_stds, capsize=5)
        axes[0, 1].set_title('Cross-Validation Scores')
        axes[0, 1].set_ylabel('CV Score')
        axes[0, 1].set_ylim(0, 1)
        
        # Confusion matrix for best model
        best_result = results[self.best_model_name]
        sns.heatmap(best_result['confusion_matrix'], annot=True, fmt='d', ax=axes[1, 0])
        axes[1, 0].set_title(f'Confusion Matrix - {self.best_model_name}')
        axes[1, 0].set_xlabel('Predicted')
        axes[1, 0].set_ylabel('Actual')
        
        # Feature importance (for Random Forest)
        if self.best_model_name == 'random_forest':
            feature_importance = self.best_model.feature_importances_
            feature_indices = np.argsort(feature_importance)[-10:]  # Top 10 features
            
            axes[1, 1].barh(range(len(feature_indices)), feature_importance[feature_indices])
            axes[1, 1].set_title('Feature Importance (Top 10)')
            axes[1, 1].set_xlabel('Importance')
        else:
            axes[1, 1].text(0.5, 0.5, 'Feature importance\nnot available for\nthis model', 
                           horizontalalignment='center', verticalalignment='center',
                           transform=axes[1, 1].transAxes)
            axes[1, 1].set_title('Feature Importance')
        
        plt.tight_layout()
        plt.savefig('model_evaluation.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        # Print detailed classification reports
        print("\nDetailed Classification Reports:")
        print("=" * 50)
        
        for name, result in results.items():
            print(f"\n{name.upper()}:")
            print("-" * 30)
            print(f"Accuracy: {result['accuracy']:.4f}")
            print(f"Cross-validation: {result['cv_mean']:.4f} (+/- {result['cv_std']:.4f})")
            print("\nClassification Report:")
            
            report = result['classification_report']
            for label, metrics in report.items():
                if label not in ['accuracy', 'macro avg', 'weighted avg']:
                    print(f"  Class {label}:")
                    if isinstance(metrics, dict):
                        print(f"    Precision: {metrics['precision']:.3f}")
                        print(f"    Recall: {metrics['recall']:.3f}")
                        print(f"    F1-score: {metrics['f1-score']:.3f}")
        
        return results
    
    def save_best_model(self, filename='best_model.pkl'):
        """Save the best performing model"""
        if self.best_model is not None:
            model_data = {
                'model': self.best_model,
                'model_name': self.best_model_name,
                'model_type': type(self.best_model).__name__
            }
            joblib.dump(model_data, filename)
            print(f"Best model ({self.best_model_name}) saved as {filename}")
        else:
            print("No trained model available to save")
    
    def load_model(self, filename='best_model.pkl'):
        """Load a saved model"""
        try:
            model_data = joblib.load(filename)
            self.best_model = model_data['model']
            self.best_model_name = model_data['model_name']
            print(f"Model loaded: {self.best_model_name}")
            return True
        except FileNotFoundError:
            print(f"Model file {filename} not found")
            return False
        except Exception as e:
            print(f"Error loading model: {str(e)}")
            return False
    
    def predict(self, X):
        """Make predictions using the best model"""
        if self.best_model is not None:
            return self.best_model.predict(X)
        else:
            raise ValueError("No trained model available for prediction")
    
    def predict_proba(self, X):
        """Get prediction probabilities"""
        if self.best_model is not None and hasattr(self.best_model, 'predict_proba'):
            return self.best_model.predict_proba(X)
        else:
            raise ValueError("Model does not support probability prediction")
    
    def generate_sample_dataset(self, n_samples=1000):
        """Generate sample dataset for demonstration"""
        np.random.seed(42)
        
        # Generate random features
        features = {}
        
        # Static analysis features
        features['file_size'] = np.random.lognormal(15, 2, n_samples)
        features['number_of_sections'] = np.random.randint(1, 10, n_samples)
        features['number_of_imports'] = np.random.randint(0, 100, n_samples)
        features['entropy'] = np.random.uniform(0, 8, n_samples)
        features['suspicious_imports_count'] = np.random.randint(0, 20, n_samples)
        features['is_packed'] = np.random.randint(0, 2, n_samples)
        
        # Dynamic analysis features
        features['behavior_score'] = np.random.randint(0, 100, n_samples)
        features['tcp_connections_count'] = np.random.randint(0, 50, n_samples)
        features['registry_keys_created'] = np.random.randint(0, 20, n_samples)
        features['files_created_count'] = np.random.randint(0, 15, n_samples)
        features['processes_created_count'] = np.random.randint(0, 10, n_samples)
        
        # Create DataFrame
        X = pd.DataFrame(features)
        
        # Generate labels (malicious vs benign)
        # Create some correlation with features for realistic data
        malicious_probability = (
            0.3 * (features['entropy'] > 6) +
            0.4 * (features['behavior_score'] > 50) +
            0.2 * (features['suspicious_imports_count'] > 5) +
            0.3 * (features['is_packed'] == 1) +
            0.2 * (features['tcp_connections_count'] > 20)
        ) / 1.4  # Normalize
        
        y = np.random.binomial(1, malicious_probability, n_samples)
        
        return X, y
