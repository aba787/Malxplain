import os
import json
from .static_analysis import StaticAnalyzer
from .dynamic_analysis import DynamicAnalyzer
from .feature_engineering import FeatureEngineer
from .ml_models import MLPredictor
from datetime import datetime

class PredictionEngine:
    def __init__(self):
        self.static_analyzer = StaticAnalyzer()
        self.dynamic_analyzer = DynamicAnalyzer()
        self.feature_engineer = FeatureEngineer()
        self.ml_predictor = MLPredictor()

        # Try to load pre-trained model
        if not self.ml_predictor.load_model():
            print("No pre-trained model found. Will create sample model.")
            self._create_sample_model()

    def _create_sample_model(self):
        """Create and train a sample model for demonstration"""
        print("Creating sample dataset and training models...")

        # Generate sample data
        X, y = self.ml_predictor.generate_sample_dataset(n_samples=1000)

        # Train models
        results = self.ml_predictor.train_models(X, y)

        # Save the best model
        self.ml_predictor.save_best_model()

        print("Sample model created and saved.")

    def analyze_file(self, filepath):
        """Complete analysis pipeline for a single file"""
        analysis_id = f"analysis_{int(datetime.now().timestamp())}"

        try:
            # Step 1: Static Analysis
            print("Performing static analysis...")
            static_result = self.static_analyzer.analyze_file(filepath)

            if 'error' in static_result:
                return {
                    'analysis_id': analysis_id,
                    'error': static_result['error'],
                    'timestamp': datetime.now().isoformat(),
                    'filename': os.path.basename(filepath),
                    'recommendation': 'تأكد من أن الملف من نوع Windows PE (.exe, .dll) وأنه غير تالف'
                }

            # Step 2: Dynamic Analysis (mock for demonstration)
            print("Performing dynamic analysis...")
            dynamic_result = self.dynamic_analyzer.analyze_file(filepath, use_sandbox=False)

            # Step 3: Feature Engineering
            print("Engineering features...")
            features = self.feature_engineer.extract_features(static_result, dynamic_result)

            # Step 4: Prediction
            print("Making prediction...")
            prediction_result = self._make_prediction(features)

            # Step 5: Generate comprehensive report
            sha256 = static_result.get('file_info', {}).get('sha256', '')

            # Generate explanation
            explanation = self._generate_explanation(static_result, dynamic_result, prediction_result)

            report = {
                'analysis_id': analysis_id,
                'sha256': sha256,
                'filename': os.path.basename(filepath),
                'timestamp': datetime.now().isoformat(),
                'prediction': prediction_result['prediction'],
                'confidence': prediction_result['confidence'],
                'top_features': prediction_result.get('top_features', {}),
                'explanation': explanation,
                'static_analysis': static_result,
                'dynamic_analysis': dynamic_result,
                'features': features,
                'overall_assessment': self._generate_assessment(static_result, dynamic_result, prediction_result)
            }

            # Save report
            self._save_report(report, analysis_id)

            return report

        except Exception as e:
            return {
                'analysis_id': analysis_id,
                'error': f'Analysis failed: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }

    def _make_prediction(self, features):
        """Make malware prediction using trained model"""
        try:
            # Process features for ML model
            processed_features = self.feature_engineer.process_single_sample(features)

            # Get prediction
            prediction = self.ml_predictor.predict(processed_features)[0]

            # Get prediction probability if available
            try:
                probabilities = self.ml_predictor.predict_proba(processed_features)[0]
                confidence = max(probabilities)
            except:
                confidence = 0.5

            # Determine result
            result = "malicious" if prediction == 1 else "benign"

            # Get top features that influenced the decision
            top_features = self._get_top_features(features, processed_features)

            return {
                'prediction': result,
                'confidence': round(float(confidence), 4),
                'prediction_score': float(prediction),
                'model_used': self.ml_predictor.best_model_name or 'unknown',
                'top_features': top_features
            }

        except Exception as e:
            return {
                'prediction': 'unknown',
                'confidence': 0.0,
                'error': f'Prediction failed: {str(e)}',
                'model_used': 'none',
                'top_features': {}
            }

    def _get_top_features(self, original_features, processed_features):
        """Get top features that influenced the prediction"""
        try:
            if hasattr(self.ml_predictor.best_model, 'feature_importances_'):
                importances = self.ml_predictor.best_model.feature_importances_
                feature_names = list(original_features.keys())

                # Get top 5 features
                top_indices = sorted(range(len(importances)), key=lambda i: importances[i], reverse=True)[:5]

                top_features = {}
                for i, idx in enumerate(top_indices):
                    if idx < len(feature_names):
                        feature_name = feature_names[idx]
                        if feature_name in original_features:
                            top_features[feature_name] = original_features[feature_name]

                return top_features
        except:
            pass

        # Fallback: return first 5 features
        return dict(list(original_features.items())[:5])

    def _generate_assessment(self, static_result, dynamic_result, prediction_result):
        """Generate overall security assessment"""
        assessment = {
            'risk_level': 'Unknown',
            'key_indicators': [],
            'recommendations': []
        }

        try:
            # Determine risk level
            if prediction_result.get('prediction') == 'malicious':
                if prediction_result.get('confidence', 0) > 0.8:
                    assessment['risk_level'] = 'HIGH'
                elif prediction_result.get('confidence', 0) > 0.6:
                    assessment['risk_level'] = 'MEDIUM'
                else:
                    assessment['risk_level'] = 'LOW'
            else:
                assessment['risk_level'] = 'SAFE'

            # Extract key indicators
            indicators = []

            # Static indicators
            if 'suspicious_indicators' in static_result:
                si = static_result['suspicious_indicators']
                if si.get('packed'):
                    indicators.append("File appears to be packed")
                if si.get('high_entropy'):
                    indicators.append("High entropy detected (possible encryption)")
                if si.get('suspicious_imports'):
                    indicators.append(f"Suspicious API imports: {len(si.get('suspicious_imports', []))}")

            # Dynamic indicators
            if 'behavior_score' in dynamic_result:
                score = dynamic_result['behavior_score']
                if score > 50:
                    indicators.append(f"High behavior score: {score}")

            # String indicators
            if 'strings' in static_result:
                sus_strings = static_result['strings'].get('suspicious_strings', [])
                if sus_strings:
                    indicators.append(f"Suspicious strings found: {len(sus_strings)}")

            assessment['key_indicators'] = indicators

            # Generate recommendations
            recommendations = []

            if assessment['risk_level'] == 'HIGH':
                recommendations.extend([
                    "Do not execute this file",
                    "Quarantine immediately",
                    "Run additional scans with updated antivirus"
                ])
            elif assessment['risk_level'] == 'MEDIUM':
                recommendations.extend([
                    "Exercise extreme caution",
                    "Scan with multiple antivirus engines",
                    "Consider sandbox analysis"
                ])
            elif assessment['risk_level'] == 'LOW':
                recommendations.extend([
                    "Monitor file behavior if executed",
                    "Verify file source and authenticity"
                ])
            else:
                recommendations.append("File appears safe, but remain vigilant")

            assessment['recommendations'] = recommendations

        except Exception as e:
            assessment['error'] = f"Assessment generation failed: {str(e)}"

        return assessment

    def _generate_explanation(self, static_result, dynamic_result, prediction_result):
        """Generate simple explanation for the prediction"""
        explanation_parts = []

        # Base explanation
        if prediction_result['prediction'] == 'malicious':
            explanation_parts.append("The file is classified as malicious")
        else:
            explanation_parts.append("The file appears to be benign")

        # Add specific reasons based on features
        if 'suspicious_indicators' in static_result:
            indicators = static_result['suspicious_indicators']

            if indicators.get('packed'):
                explanation_parts.append("because it appears to be packed")

            if indicators.get('high_entropy'):
                explanation_parts.append("due to high entropy indicating encryption or compression")

            if indicators.get('suspicious_imports'):
                sus_count = len(indicators.get('suspicious_imports', []))
                if sus_count > 0:
                    explanation_parts.append(f"and contains {sus_count} suspicious API imports")

        if 'behavior_score' in dynamic_result:
            score = dynamic_result['behavior_score']
            if score > 50:
                explanation_parts.append(f"with suspicious behavior score of {score}/100")

        # Join explanation parts
        if len(explanation_parts) == 1:
            return explanation_parts[0] + "."
        elif len(explanation_parts) == 2:
            return f"{explanation_parts[0]} {explanation_parts[1]}."
        else:
            main_explanation = explanation_parts[0]
            reasons = ", ".join(explanation_parts[1:-1])
            last_reason = explanation_parts[-1]
            return f"{main_explanation} {reasons}, and {last_reason}."


    def _save_report(self, report, analysis_id):
        """Save analysis report as JSON"""
        try:
            os.makedirs('reports', exist_ok=True)
            report_path = f'reports/{analysis_id}_report.json'

            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)

            print(f"Report saved: {report_path}")

        except Exception as e:
            print(f"Failed to save report: {str(e)}")

    def get_analysis_summary(self, report):
        """Get a simplified summary for UI display"""
        try:
            return {
                'filename': report.get('filename', 'Unknown'),
                'result': report.get('prediction', 'unknown'),
                'confidence': report.get('confidence', 0.0),
                'risk_level': report.get('overall_assessment', {}).get('risk_level', 'UNKNOWN'),
                'key_indicators': report.get('overall_assessment', {}).get('key_indicators', [])[:3],  # Top 3
                'timestamp': report.get('timestamp', datetime.now().isoformat())
            }
        except Exception as e:
            return {
                'filename': 'Unknown',
                'result': 'Error',
                'confidence': 0.0,
                'risk_level': 'UNKNOWN',
                'key_indicators': [f"Analysis error: {str(e)}"],
                'timestamp': datetime.now().isoformat()
            }