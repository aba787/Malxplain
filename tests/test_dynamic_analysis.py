
import unittest
import json
import tempfile
import os
from modules.dynamic_analysis import DynamicAnalyzer

class TestDynamicAnalysis(unittest.TestCase):
    def setUp(self):
        self.analyzer = DynamicAnalyzer()
        
        # Create sample Any.Run report
        self.sample_report = {
            "network": {
                "tcp": [{"ip": "192.168.1.100", "port": 80}],
                "dns": ["google.com", "malicious-site.com"]
            },
            "registry": {
                "created": ["HKEY_LOCAL_MACHINE\\Software\\Test"],
                "modified": ["HKEY_CURRENT_USER\\Software\\Test"]
            },
            "files": {
                "created": ["C:\\temp\\test.exe"],
                "deleted": ["C:\\temp\\old.txt"]
            }
        }
        
        # Create temporary JSON file
        self.report_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(self.sample_report, self.report_file)
        self.report_file.close()
    
    def tearDown(self):
        os.unlink(self.report_file.name)
    
    def test_parse_anyrun_report(self):
        """Test parsing Any.Run JSON report"""
        result = self.analyzer._parse_existing_report(self.report_file.name)
        
        # Should not have error
        self.assertNotIn('error', result)
        
        # Should have expected structure
        self.assertIsInstance(result, dict)
    
    def test_mock_analysis(self):
        """Test mock dynamic analysis"""
        result = self.analyzer._generate_mock_analysis("test.exe")
        
        # Should have required fields
        self.assertIn('filename', result)
        self.assertIn('behavior_score', result)
        self.assertIn('risk_level', result)
        
        # Behavior score should be valid
        self.assertIsInstance(result['behavior_score'], int)
        self.assertGreaterEqual(result['behavior_score'], 0)
        self.assertLessEqual(result['behavior_score'], 100)
    
    def test_behavior_scoring(self):
        """Test behavior scoring calculation"""
        behavior = {
            'network_activity': {
                'tcp_connections': [{'ip': '1.1.1.1', 'port': 80}],
                'http_requests': [{'url': 'http://malicious-site.com/payload'}]
            }
        }
        
        score = self.analyzer._calculate_behavior_score(behavior)
        self.assertIsInstance(score, int)
        self.assertGreater(score, 0)  # Should have some score due to malicious URL

if __name__ == '__main__':
    unittest.main()
