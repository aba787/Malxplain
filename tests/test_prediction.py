
import unittest
import tempfile
import os
from modules.prediction_engine import PredictionEngine
from modules.ml_models import MLPredictor

class TestPrediction(unittest.TestCase):
    def setUp(self):
        self.engine = PredictionEngine()
        
        # Create dummy file
        self.test_file = tempfile.NamedTemporaryFile(delete=False, suffix='.exe')
        self.test_file.write(b'MZ' + b'\x00' * 100)  # Minimal executable
        self.test_file.close()
    
    def tearDown(self):
        os.unlink(self.test_file.name)
    
    def test_model_loading(self):
        """Test model loading"""
        # Should have a model loaded (either pre-trained or sample)
        self.assertIsNotNone(self.engine.ml_predictor.best_model)
        self.assertIsNotNone(self.engine.ml_predictor.best_model_name)
    
    def test_file_analysis(self):
        """Test complete file analysis"""
        result = self.engine.analyze_file(self.test_file.name)
        
        # Should have required fields
        self.assertIn('analysis_id', result)
        self.assertIn('filename', result)
        self.assertIn('prediction', result)
        
        if 'error' not in result:
            # If analysis succeeded, check prediction structure
            prediction = result['prediction']
            self.assertIn('result', prediction)
            self.assertIn('confidence', prediction)
            self.assertIn(prediction['result'], ['Malicious', 'Safe', 'Unknown'])
    
    def test_prediction_format(self):
        """Test prediction response format"""
        # Test with sample features
        features = {
            'file_size': 1024,
            'entropy': 5.2,
            'number_of_imports': 10,
            'behavior_score': 30
        }
        
        prediction = self.engine._make_prediction(features)
        
        # Should have required fields
        self.assertIn('result', prediction)
        self.assertIn('confidence', prediction)
        self.assertIn('model_used', prediction)

if __name__ == '__main__':
    unittest.main()
