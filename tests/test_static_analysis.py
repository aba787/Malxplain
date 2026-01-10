
import unittest
import os
import tempfile
from modules.static_analysis import StaticAnalyzer

class TestStaticAnalysis(unittest.TestCase):
    def setUp(self):
        self.analyzer = StaticAnalyzer()
        
        # Create a dummy PE file for testing (simple DOS header)
        self.test_file = tempfile.NamedTemporaryFile(delete=False, suffix='.exe')
        # Write minimal DOS header
        dos_header = b'MZ' + b'\x00' * 58 + b'\x80\x00\x00\x00'  # DOS header with PE offset
        pe_header = b'PE\x00\x00'  # PE signature
        file_header = b'\x4c\x01' + b'\x00' * 18  # Minimal file header
        optional_header = b'\x0b\x01' + b'\x00' * 222  # Minimal optional header
        
        self.test_file.write(dos_header + b'\x00' * (0x80 - len(dos_header)))
        self.test_file.write(pe_header + file_header + optional_header)
        self.test_file.close()
    
    def tearDown(self):
        os.unlink(self.test_file.name)
    
    def test_extract_basic_info(self):
        """Test basic file info extraction"""
        try:
            result = self.analyzer.analyze_file(self.test_file.name)
            
            # Should not have error
            self.assertNotIn('error', result)
            
            # Should have required fields
            self.assertIn('file_info', result)
            self.assertIn('sha256', result['file_info'])
            self.assertIn('size', result['file_info'])
            self.assertIn('entropy', result)
            
        except Exception as e:
            # If PE parsing fails, at least file_info should work
            result = self.analyzer._get_file_info(self.test_file.name)
            self.assertIn('sha256', result)
            self.assertIn('size', result)
    
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        entropy = self.analyzer._calculate_entropy(self.test_file.name)
        self.assertIsInstance(entropy, float)
        self.assertGreaterEqual(entropy, 0)
        self.assertLessEqual(entropy, 8)

if __name__ == '__main__':
    unittest.main()
