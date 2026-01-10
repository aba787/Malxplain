
import json
import requests
import time
import os
from datetime import datetime

class DynamicAnalyzer:
    def __init__(self):
        self.behavior_categories = {
            'network': ['tcp_connections', 'dns_requests', 'http_requests'],
            'registry': ['reg_key_created', 'reg_value_set', 'reg_key_deleted'],
            'filesystem': ['file_created', 'file_deleted', 'file_modified'],
            'process': ['process_created', 'process_terminated', 'dll_loaded']
        }
    
    def analyze_file(self, filepath, use_sandbox=False, report_json=None):
        """Perform dynamic analysis using sandbox or provided report"""
        
        if report_json:
            # Use provided JSON report
            return self._parse_existing_report(report_json)
        elif use_sandbox:
            # Submit to sandbox (placeholder - would need actual sandbox API)
            return self._submit_to_sandbox(filepath)
        else:
            # Generate mock dynamic analysis for demonstration
            return self._generate_mock_analysis(filepath)
    
    def _parse_existing_report(self, report_path):
        """Parse existing dynamic analysis report"""
        try:
            with open(report_path, 'r') as f:
                report = json.load(f)
            
            return self._extract_behavior_features(report)
            
        except Exception as e:
            return {'error': f'Failed to parse report: {str(e)}'}
    
    def _submit_to_sandbox(self, filepath):
        """Submit file to sandbox for analysis (placeholder)"""
        # This would integrate with actual sandbox APIs like Any.Run, Joe Sandbox, etc.
        # For now, return mock data
        
        return {
            'analysis_id': f'sandbox_{int(time.time())}',
            'status': 'completed',
            'network_activity': self._mock_network_activity(),
            'registry_changes': self._mock_registry_changes(),
            'file_operations': self._mock_file_operations(),
            'process_creation': self._mock_process_creation(),
            'behavior_score': self._calculate_behavior_score({})
        }
    
    def _generate_mock_analysis(self, filepath):
        """Generate mock dynamic analysis for demonstration"""
        filename = os.path.basename(filepath)
        
        # Generate realistic mock behavior based on filename patterns
        behavior = {
            'network_activity': self._mock_network_activity(),
            'registry_changes': self._mock_registry_changes(),
            'file_operations': self._mock_file_operations(),
            'process_creation': self._mock_process_creation()
        }
        
        behavior_score = self._calculate_behavior_score(behavior)
        
        return {
            'filename': filename,
            'analysis_timestamp': datetime.now().isoformat(),
            'behavior': behavior,
            'behavior_score': behavior_score,
            'risk_level': self._determine_risk_level(behavior_score)
        }
    
    def _mock_network_activity(self):
        """Generate mock network activity"""
        return {
            'tcp_connections': [
                {'destination': '192.168.1.100', 'port': 80, 'protocol': 'TCP'},
                {'destination': '8.8.8.8', 'port': 53, 'protocol': 'UDP'}
            ],
            'dns_requests': [
                'google.com',
                'microsoft.com'
            ],
            'http_requests': [
                {'url': 'http://example.com/update', 'method': 'GET'},
                {'url': 'http://malicious-site.com/payload', 'method': 'POST'}
            ]
        }
    
    def _mock_registry_changes(self):
        """Generate mock registry changes"""
        return {
            'keys_created': [
                'HKEY_CURRENT_USER\\Software\\MyApp',
                'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MyApp'
            ],
            'values_set': [
                {'key': 'HKEY_CURRENT_USER\\Software\\MyApp', 'value': 'AutoStart', 'data': '1'},
                {'key': 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'value': 'Malware', 'data': 'C:\\temp\\malware.exe'}
            ],
            'keys_deleted': []
        }
    
    def _mock_file_operations(self):
        """Generate mock file operations"""
        return {
            'files_created': [
                'C:\\temp\\malware.exe',
                'C:\\Users\\User\\AppData\\Roaming\\config.dat'
            ],
            'files_deleted': [
                'C:\\Users\\User\\Documents\\important.doc'
            ],
            'files_modified': [
                'C:\\Windows\\System32\\hosts'
            ]
        }
    
    def _mock_process_creation(self):
        """Generate mock process creation"""
        return {
            'processes_created': [
                {'name': 'cmd.exe', 'command_line': 'cmd.exe /c whoami'},
                {'name': 'powershell.exe', 'command_line': 'powershell.exe -enc aGVsbG8='}
            ],
            'dlls_loaded': [
                'kernel32.dll',
                'ntdll.dll',
                'advapi32.dll'
            ]
        }
    
    def _calculate_behavior_score(self, behavior):
        """Calculate numerical behavior score"""
        score = 0
        
        # Network activity scoring
        if 'network_activity' in behavior:
            net = behavior['network_activity']
            score += len(net.get('tcp_connections', [])) * 2
            score += len(net.get('http_requests', [])) * 3
            
            # Check for suspicious URLs
            for req in net.get('http_requests', []):
                if 'malicious' in req.get('url', '').lower():
                    score += 10
        
        # Registry changes scoring
        if 'registry_changes' in behavior:
            reg = behavior['registry_changes']
            score += len(reg.get('keys_created', [])) * 1
            score += len(reg.get('values_set', [])) * 2
            
            # Check for persistence mechanisms
            for key in reg.get('keys_created', []):
                if 'Run' in key:
                    score += 15
        
        # File operations scoring
        if 'file_operations' in behavior:
            files = behavior['file_operations']
            score += len(files.get('files_created', [])) * 1
            score += len(files.get('files_deleted', [])) * 3
            score += len(files.get('files_modified', [])) * 2
        
        # Process creation scoring
        if 'process_creation' in behavior:
            procs = behavior['process_creation']
            for proc in procs.get('processes_created', []):
                if 'cmd.exe' in proc.get('name', ''):
                    score += 5
                if 'powershell' in proc.get('name', ''):
                    score += 7
        
        return min(score, 100)  # Cap at 100
    
    def _determine_risk_level(self, score):
        """Determine risk level based on behavior score"""
        if score >= 70:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _extract_behavior_features(self, report):
        """Extract behavior features from report for ML model"""
        features = {
            'network_connections_count': 0,
            'registry_modifications': 0,
            'file_operations_count': 0,
            'process_creations': 0,
            'suspicious_api_calls': 0
        }
        
        # This would parse actual sandbox report structure
        # Implementation depends on specific sandbox format
        
        return features
