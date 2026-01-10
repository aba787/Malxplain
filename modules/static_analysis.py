
import pefile
import os
import json
import hashlib
import math
from collections import Counter
import string
import re

class StaticAnalyzer:
    def __init__(self):
        self.suspicious_strings = [
            'CreateProcess', 'WriteProcessMemory', 'VirtualAlloc', 'GetProcAddress',
            'LoadLibrary', 'RegCreateKey', 'RegSetValue', 'InternetOpen',
            'HttpSendRequest', 'CreateFile', 'WriteFile', 'DeleteFile',
            'CreateService', 'StartService', 'cmd.exe', 'powershell',
            'whoami', 'net user', 'taskkill', 'schtasks'
        ]
        
    def analyze_file(self, filepath):
        """Perform complete static analysis on PE file"""
        try:
            # Check if file exists and is readable
            if not os.path.exists(filepath):
                return {'error': 'الملف غير موجود'}
            
            if os.path.getsize(filepath) == 0:
                return {'error': 'الملف فارغ'}
            
            # Get basic file info first (this always works)
            file_info = self._get_file_info(filepath)
            strings_info = self._extract_strings(filepath)
            entropy = self._calculate_entropy(filepath)
            
            # Try to parse as PE file
            pe = None
            pe_analysis_error = None
            try:
                pe = pefile.PE(filepath)
            except pefile.PEFormatError:
                pe_analysis_error = 'الملف ليس من نوع PE (Windows Executable)'
            except Exception as e:
                pe_analysis_error = f'خطأ في قراءة الملف: {str(e)}'
            
            # Build analysis result based on what we can extract
            analysis_result = {
                'file_info': file_info,
                'strings': strings_info,
                'entropy': entropy
            }
            
            if pe is not None:
                # Full PE analysis
                analysis_result.update({
                    'pe_headers': self._extract_pe_headers(pe),
                    'imports': self._extract_imports(pe),
                    'metadata': self._extract_metadata(pe),
                    'suspicious_indicators': self._check_suspicious_indicators(pe, filepath)
                })
            else:
                # Basic analysis without PE parsing
                analysis_result.update({
                    'pe_headers': {},
                    'imports': {},
                    'metadata': {},
                    'suspicious_indicators': self._check_basic_suspicious_indicators(filepath, strings_info, entropy),
                    'analysis_note': pe_analysis_error or 'تم إجراء تحليل أساسي فقط'
                })
            
            # Save results as JSON (optional)
            try:
                output_path = filepath + '_static_analysis.json'
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(analysis_result, f, indent=2, default=str, ensure_ascii=False)
            except:
                pass  # Don't fail analysis if we can't save the report
                
            return analysis_result
            
        except Exception as e:
            return {'error': f'فشل تحليل الملف: {str(e)}'}
    
    def _get_file_info(self, filepath):
        """Extract basic file information"""
        stat = os.stat(filepath)
        
        # Calculate file hashes
        with open(filepath, 'rb') as f:
            data = f.read()
            
        return {
            'filename': os.path.basename(filepath),
            'size': stat.st_size,
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()
        }
    
    def _extract_pe_headers(self, pe):
        """Extract PE header information"""
        return {
            'machine': hex(pe.FILE_HEADER.Machine),
            'timestamp': pe.FILE_HEADER.TimeDateStamp,
            'number_of_sections': pe.FILE_HEADER.NumberOfSections,
            'size_of_optional_header': pe.FILE_HEADER.SizeOfOptionalHeader,
            'characteristics': hex(pe.FILE_HEADER.Characteristics),
            'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
            'section_alignment': pe.OPTIONAL_HEADER.SectionAlignment,
            'file_alignment': pe.OPTIONAL_HEADER.FileAlignment,
            'subsystem': pe.OPTIONAL_HEADER.Subsystem
        }
    
    def _extract_imports(self, pe):
        """Extract imported functions and DLLs"""
        imports = {}
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')
                functions = []
                
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode('utf-8'))
                
                imports[dll_name] = functions
                
        return imports
    
    def _extract_strings(self, filepath):
        """Extract ASCII and Unicode strings from file"""
        strings_found = []
        
        with open(filepath, 'rb') as f:
            data = f.read()
            
        # ASCII strings
        ascii_strings = re.findall(b'[ -~]{4,}', data)
        for s in ascii_strings[:100]:  # Limit to first 100 strings
            strings_found.append(s.decode('ascii', errors='ignore'))
            
        # Unicode strings  
        unicode_strings = re.findall(b'(?:[ -~]\x00){4,}', data)
        for s in unicode_strings[:100]:  # Limit to first 100 strings
            try:
                strings_found.append(s.decode('utf-16le', errors='ignore'))
            except:
                pass
                
        return {
            'total_strings': len(strings_found),
            'strings': strings_found,
            'suspicious_strings': [s for s in strings_found if any(sus in s for sus in self.suspicious_strings)]
        }
    
    def _calculate_entropy(self, filepath):
        """Calculate file entropy"""
        with open(filepath, 'rb') as f:
            data = f.read()
            
        if len(data) == 0:
            return 0
            
        # Count byte frequencies
        byte_counts = Counter(data)
        
        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def _extract_metadata(self, pe):
        """Extract PE metadata"""
        metadata = {}
        
        if hasattr(pe, 'VS_VERSIONINFO'):
            for entry in pe.VS_VERSIONINFO:
                if hasattr(entry, 'StringTable'):
                    for st in entry.StringTable:
                        for key, value in st.entries.items():
                            metadata[key.decode('utf-8')] = value.decode('utf-8')
                            
        return metadata
    
    def _check_suspicious_indicators(self, pe, filepath):
        """Check for suspicious indicators"""
        indicators = {
            'packed': self._check_if_packed(pe),
            'unusual_sections': self._check_unusual_sections(pe),
            'suspicious_imports': self._check_suspicious_imports(pe),
            'high_entropy': self._calculate_entropy(filepath) > 7.0
        }
        
        return indicators
    
    def _check_if_packed(self, pe):
        """Check if PE file is packed"""
        # Simple heuristic: check for unusual section names or high entropy
        suspicious_sections = ['.UPX', '.packed', '.compressed', 'UPX0', 'UPX1']
        
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            if any(sus in section_name for sus in suspicious_sections):
                return True
                
        return False
    
    def _check_unusual_sections(self, pe):
        """Check for unusual section names"""
        common_sections = ['.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc']
        unusual = []
        
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            if section_name not in common_sections:
                unusual.append(section_name)
                
        return unusual
    
    def _check_suspicious_imports(self, pe):
        """Check for suspicious API imports"""
        suspicious_apis = [
            'CreateProcess', 'WriteProcessMemory', 'VirtualAlloc', 'GetProcAddress',
            'SetWindowsHookEx', 'CreateRemoteThread', 'OpenProcess', 'RegCreateKey'
        ]
        
        found_suspicious = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8')
                        if any(sus in api_name for sus in suspicious_apis):
                            found_suspicious.append(api_name)
                            
        return found_suspicious

    def _check_basic_suspicious_indicators(self, filepath, strings_info, entropy):
        """Check for suspicious indicators without PE parsing"""
        indicators = {
            'packed': False,
            'unusual_sections': [],
            'suspicious_imports': [],
            'high_entropy': entropy > 7.0,
            'suspicious_strings_found': len(strings_info.get('suspicious_strings', [])) > 0,
            'large_file': os.path.getsize(filepath) > 10 * 1024 * 1024,  # 10MB
            'analysis_type': 'basic'
        }
        
        # Check for suspicious file extensions or names
        filename = os.path.basename(filepath).lower()
        suspicious_extensions = ['.scr', '.pif', '.com', '.bat', '.cmd', '.vbs', '.js']
        if any(filename.endswith(ext) for ext in suspicious_extensions):
            indicators['suspicious_extension'] = True
            
        return indicators
