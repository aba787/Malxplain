
from flask import Flask, render_template, request, jsonify, redirect, url_for
import os
import json
import time
from werkzeug.utils import secure_filename
from modules.static_analysis import StaticAnalyzer
from modules.dynamic_analysis import DynamicAnalyzer
from modules.feature_engineering import FeatureEngineer
from modules.ml_models import MLPredictor
from modules.prediction_engine import PredictionEngine
from modules.educational_interface import EducationalExplainer

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize components
prediction_engine = PredictionEngine()
educational_explainer = EducationalExplainer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/simple')
def simple():
    return render_template('simple.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file:
        filename = secure_filename(file.filename)
        
        # Check file extension
        allowed_extensions = ['.exe', '.dll', '.scr', '.com']
        file_ext = os.path.splitext(filename)[1].lower()
        
        if file_ext not in allowed_extensions and not any(sample in filename for sample in ['fake_', 'dummy_', 'test_', 'mock_']):
            return jsonify({
                'error': 'نوع الملف غير مدعوم',
                'supported_types': 'الأنواع المدعومة: .exe, .dll, .scr, .com',
                'uploaded_type': file_ext or 'غير محدد',
                'educational_notice': educational_notice
            }), 400
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Educational notice in response
        educational_notice = {
            'notice': 'This is an educational demonstration',
            'purpose': 'Learning cybersecurity analysis techniques',
            'file_handling': 'File analyzed in educational context only'
        }
        
        try:
            # Analyze the file
            result = prediction_engine.analyze_file(filepath)
            
            # Check for analysis errors
            if 'error' in result:
                error_message = result['error']
                recommendation = result.get('recommendation', 'يُرجى المحاولة مع ملف آخر')
                return jsonify({
                    'error': error_message,
                    'recommendation': recommendation,
                    'filename': filename,
                    'educational_notice': educational_notice,
                    'supported_types': 'الأنواع المدعومة: .exe, .dll (Windows PE files)'
                }), 400
            
            # Override prediction for educational samples
            is_educational_sample = 'samples' in filepath or filename in [
                'windows_calculator.exe', 'text_editor.exe', 'media_player.exe', 
                'system_tool.dll', 'graphics_lib.dll', 'fake_ransomware.exe',
                'dummy_trojan.exe', 'test_keylogger.exe', 'mock_botnet.dll'
            ]
        except Exception as e:
            return jsonify({
                'error': f'File analysis failed: {str(e)}',
                'educational_notice': educational_notice
            }), 500
        
        if is_educational_sample:
            if 'benign' in filepath or filename in ['windows_calculator.exe', 'text_editor.exe', 'media_player.exe', 'system_tool.dll', 'graphics_lib.dll']:
                # Force benign result for demo
                result['prediction'] = 'benign'
                result['confidence'] = 0.95
                result['educational_override'] = True
                result['demo_message'] = 'This is a safe educational file - Result is pre-determined for demonstration'
            elif 'malicious' in filepath or filename in ['fake_ransomware.exe', 'dummy_trojan.exe', 'test_keylogger.exe', 'mock_botnet.dll']:
                # Force malicious result for demo
                result['prediction'] = 'malicious'
                result['confidence'] = 0.88
                result['educational_override'] = True
                result['demo_message'] = 'This is an educational file representing malware - Result is pre-determined for demonstration'
        
        explanation = educational_explainer.explain_behavior(result)
        
        # Add educational context to result
        result['educational_notice'] = educational_notice
        
        # Generate analysis ID for future reference
        analysis_id = result.get('analysis_id', f"analysis_{int(time.time())}")
        
        return jsonify({
            'success': True,
            'analysis_id': analysis_id,
            'result': result,
            'explanation': explanation,
            'message': 'Analysis completed successfully'
        })

@app.route('/analysis/<analysis_id>')
def show_analysis(analysis_id):
    return render_template('analysis.html', analysis_id=analysis_id)

@app.route('/explain/<analysis_id>')
def show_explanation(analysis_id):
    return render_template('explanation.html', analysis_id=analysis_id)

@app.route('/use-sample/<sample_type>')
def use_sample(sample_type):
    """Use a pre-made sample file for analysis"""
    import random
    
    try:
        if sample_type == 'benign':
            sample_files = ['windows_calculator.exe', 'text_editor.exe', 'media_player.exe', 'system_tool.dll']
            sample_dir = 'samples/benign'
        elif sample_type == 'malicious':
            sample_files = ['fake_ransomware.exe', 'dummy_trojan.exe', 'test_keylogger.exe', 'mock_botnet.dll']
            sample_dir = 'samples/malicious'
        else:
            return jsonify({'error': 'Invalid sample type. Use "benign" or "malicious"'}), 400
        
        # Pick random sample
        filename = random.choice(sample_files)
        filepath = os.path.join(sample_dir, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': f'Sample file {filename} not found'}), 404
        
        # Educational notice
        educational_notice = {
            'notice': 'Using pre-made educational sample',
            'purpose': 'Demonstration of malware analysis techniques',
            'file_type': 'Educational sample - completely safe',
            'sample_category': sample_type
        }ٍ
        
        # Analyze the sample
        result = prediction_engine.analyze_file(filepath)
        
        # Override prediction for educational samples
        if sample_type == 'benign':
            result['prediction'] = 'benign'
            result['confidence'] = 0.95
            result['educational_override'] = True
            result['demo_message'] = 'Safe educational sample - Result is pre-determined for demonstration'
        elif sample_type == 'malicious':
            result['prediction'] = 'malicious'
            result['confidence'] = 0.88
            result['educational_override'] = True
            result['demo_message'] = 'Educational sample representing malware - Result is pre-determined for demonstration'
        
        explanation = educational_explainer.explain_behavior(result)
        
        # Add educational context
        result['educational_notice'] = educational_notice
        result['sample_used'] = filename
        
        return jsonify({
            'success': True,
            'analysis_id': result.get('analysis_id', f"sample_{int(time.time())}"),
            'result': result,
            'explanation': explanation,
            'message': f'Sample {filename} analyzed successfully'
        })
        
    except Exception as e:
        return jsonify({'error': f'Sample analysis failed: {str(e)}'}), 500

@app.route('/report/<analysis_id>')
def get_report(analysis_id):
    """Get full analysis report as JSON"""
    try:
        report_path = f'reports/{analysis_id}_report.json'
        if os.path.exists(report_path):
            with open(report_path, 'r') as f:
                report = json.load(f)
            return jsonify(report)
        else:
            return jsonify({'error': 'Report not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
