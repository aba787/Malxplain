
class EducationalExplainer:
    def __init__(self):
        self.malware_behaviors = {
            'persistence': {
                'description': 'محاولة البقاء في النظام عبر إعادة التشغيل',
                'indicators': ['registry run keys', 'startup folders', 'services'],
                'explanation': 'الملف يحاول إنشاء آليات للبقاء نشطاً في النظام حتى بعد إعادة التشغيل'
            },
            'data_exfiltration': {
                'description': 'محاولة سرقة البيانات من النظام',
                'indicators': ['file reading', 'network transmission', 'clipboard access'],
                'explanation': 'الملف يحاول الوصول إلى ملفات المستخدم وإرسالها عبر الشبكة'
            },
            'system_infection': {
                'description': 'محاولة إصابة أجزاء أخرى من النظام',
                'indicators': ['file creation', 'process injection', 'dll loading'],
                'explanation': 'الملف يحاول نشر نفسه أو إصابة ملفات أخرى في النظام'
            },
            'evasion': {
                'description': 'محاولة تجنب الكشف',
                'indicators': ['packing', 'encryption', 'anti-debug'],
                'explanation': 'الملف يستخدم تقنيات لإخفاء نشاطه وتجنب برامج الحماية'
            },
            'reconnaissance': {
                'description': 'جمع معلومات عن النظام والشبكة',
                'indicators': ['system info', 'network discovery', 'user enumeration'],
                'explanation': 'الملف يحاول جمع معلومات حول النظام والمستخدمين والشبكة'
            }
        }
        
        self.api_explanations = {
            'CreateProcess': 'إنشاء عمليات جديدة - قد يستخدم لتشغيل برامج ضارة',
            'WriteProcessMemory': 'كتابة في ذاكرة عمليات أخرى - تقنية حقن كود',
            'VirtualAlloc': 'تخصيص ذاكرة - قد يستخدم لتخزين كود ضار',
            'GetProcAddress': 'الحصول على عناوين دوال - تقنية تحميل ديناميكي',
            'LoadLibrary': 'تحميل مكتبات - قد يحمل مكتبات ضارة',
            'RegCreateKey': 'إنشاء مفاتيح تسجيل - قد يستخدم للاستمرارية',
            'InternetOpen': 'فتح اتصال إنترنت - قد يتصل بخوادم ضارة',
            'CreateFile': 'إنشاء/فتح ملفات - قد ينشئ ملفات ضارة',
            'SetWindowsHookEx': 'تثبيت hook - قد يراقب إدخال المستخدم'
        }
        
        self.file_indicators = {
            'high_entropy': 'الملف مشفر أو مضغوط - قد يخفي محتوى ضار',
            'packed': 'الملف مُحزَّم - تقنية شائعة لإخفاء البرامج الضارة',
            'unusual_sections': 'أقسام غير عادية في الملف - قد تحتوي كود ضار',
            'suspicious_strings': 'نصوص مشبوهة - قد تشير لنشاط ضار',
            'large_file': 'حجم ملف كبير - قد يحتوي على بيانات مخفية',
            'no_digital_signature': 'لا يحتوي على توقيع رقمي - مصدر غير موثوق'
        }
    
    def explain_behavior(self, analysis_result):
        """Generate educational explanation for analysis result"""
        explanation = {
            'overall_verdict': self._get_overall_verdict(analysis_result),
            'behavior_analysis': self._analyze_behaviors(analysis_result),
            'technical_details': self._get_technical_details(analysis_result),
            'learning_points': self._get_learning_points(analysis_result),
            'prevention_tips': self._get_prevention_tips(analysis_result)
        }
        
        return explanation
    
    def _get_overall_verdict(self, analysis_result):
        """Get overall verdict with explanation"""
        try:
            prediction = analysis_result.get('prediction', {})
            result = prediction.get('result', 'Unknown')
            confidence = prediction.get('confidence', 0.0)
            
            verdict = {
                'classification': result,
                'confidence_percentage': f"{confidence * 100:.1f}%",
                'explanation': ''
            }
            
            if result == 'Malicious':
                if confidence > 0.8:
                    verdict['explanation'] = '🎓 Educational Demo: The ML model classified this file as potentially malicious with high confidence. In real scenarios, this would indicate suspicious characteristics that warrant further investigation.'
                elif confidence > 0.6:
                    verdict['explanation'] = '🎓 Educational Demo: The model shows moderate confidence in classifying this as suspicious. This demonstrates how uncertainty is handled in cybersecurity analysis.'
                else:
                    verdict['explanation'] = '🎓 Educational Demo: The file shows some characteristics that the model associates with suspicious behavior, but with low confidence. This illustrates the complexity of malware detection.'
            else:
                verdict['explanation'] = '🎓 Educational Demo: The model classified this file as benign. This demonstrates how machine learning can identify safe files based on their characteristics.'
            
            return verdict
            
        except Exception as e:
            return {
                'classification': 'Unknown',
                'confidence_percentage': '0%',
                'explanation': f'حدث خطأ في التحليل: {str(e)}'
            }
    
    def _analyze_behaviors(self, analysis_result):
        """Analyze and explain detected behaviors"""
        behaviors_found = []
        
        try:
            # Check static analysis indicators
            static_result = analysis_result.get('static_analysis', {})
            
            # Check for packing/encryption
            if static_result.get('suspicious_indicators', {}).get('packed'):
                behaviors_found.append({
                    'behavior': 'evasion',
                    'evidence': 'الملف محزّم (packed)',
                    'risk_level': 'متوسط',
                    'explanation': self.malware_behaviors['evasion']['explanation']
                })
            
            # Check entropy
            if static_result.get('entropy', 0) > 7.0:
                behaviors_found.append({
                    'behavior': 'evasion',
                    'evidence': f'إنتروبيا عالية ({static_result.get("entropy", 0):.2f})',
                    'risk_level': 'متوسط',
                    'explanation': 'الملف قد يكون مشفراً أو مضغوطاً لإخفاء محتواه الحقيقي'
                })
            
            # Check suspicious imports
            imports = static_result.get('imports', {})
            suspicious_apis = []
            for dll, functions in imports.items():
                for func in functions:
                    if func in self.api_explanations:
                        suspicious_apis.append(func)
            
            if suspicious_apis:
                behaviors_found.append({
                    'behavior': 'system_infection',
                    'evidence': f'APIs مشبوهة: {", ".join(suspicious_apis[:5])}',
                    'risk_level': 'عالي',
                    'explanation': 'الملف يستورد دوال يمكن استخدامها لأنشطة ضارة'
                })
            
            # Check dynamic analysis
            dynamic_result = analysis_result.get('dynamic_analysis', {})
            behavior_score = dynamic_result.get('behavior_score', 0)
            
            if behavior_score > 50:
                behaviors_found.append({
                    'behavior': 'reconnaissance',
                    'evidence': f'نشاط سلوكي عالي ({behavior_score})',
                    'risk_level': 'عالي',
                    'explanation': 'الملف يُظهر نشاطاً سلوكياً مشبوهاً أثناء التشغيل'
                })
            
            # Check for persistence mechanisms
            registry_changes = dynamic_result.get('behavior', {}).get('registry_changes', {})
            if registry_changes.get('keys_created'):
                for key in registry_changes.get('keys_created', []):
                    if 'Run' in key:
                        behaviors_found.append({
                            'behavior': 'persistence',
                            'evidence': 'إنشاء مفاتيح تسجيل للبدء التلقائي',
                            'risk_level': 'عالي',
                            'explanation': self.malware_behaviors['persistence']['explanation']
                        })
                        break
            
            
            
            # String analysis
            if 'strings' in static_result:
                strings_info = static_result['strings']
                details['string_analysis'] = {
                    'title': 'تحليل النصوص',
                    'description': 'النصوص الموجودة داخل الملف قد تكشف عن وظائفه',
                    'key_points': [
                        f"إجمالي النصوص: {strings_info.get('total_strings', 0)}",
                        f"نصوص مشبوهة: {len(strings_info.get('suspicious_strings', []))}",
                        f"أمثلة: {', '.join(strings_info.get('suspicious_strings', [])[:3])}"
                    ]
                }
            
            return details
            
        except Exception as e:
            return {
                'error': {
                    'title': 'خطأ في التفاصيل التقنية',
                    'description': f'حدث خطأ: {str(e)}',
                    'key_points': []
                }
            }
    
    def _get_learning_points(self, analysis_result):
        """Get educational learning points"""
        learning_points = [
            {
                'topic': 'تحليل الملفات الثابت (Static Analysis)',
                'description': 'فحص الملف دون تشغيله لاستخراج المعلومات الأساسية',
                'importance': 'يساعد في الكشف عن الخصائص الضارة دون المخاطرة بتشغيل البرنامج'
            },
            {
                'topic': 'تحليل السلوك الديناميكي (Dynamic Analysis)', 
                'description': 'مراقبة سلوك البرنامج أثناء التشغيل في بيئة آمنة',
                'importance': 'يكشف عن الأنشطة الفعلية التي يقوم بها البرنامج'
            },
            {
                'topic': 'التعلم الآلي في الأمن السيبراني',
                'description': 'استخدام خوارزميات الذكاء الاصطناعي لتصنيف البرامج',
                'importance': 'يمكن من اكتشاف برامج ضارة جديدة لم تُر من قبل'
            }
        ]
        
        # Add specific learning points based on analysis
        try:
            prediction = analysis_result.get('prediction', {})
            if prediction.get('result') == 'Malicious':
                learning_points.append({
                    'topic': 'مؤشرات البرامج الضارة',
                    'description': 'الخصائص والسلوكيات التي تشير إلى طبيعة البرنامج الضارة',
                    'importance': 'فهم هذه المؤشرات يساعد في التعرف على التهديدات مبكراً'
                })
        except:
            pass
            
        return learning_points
    
    def _get_prevention_tips(self, analysis_result):
        """Get prevention and security tips"""
        tips = [
            'تحديث نظام التشغيل وبرامج الحماية بانتظام',
            'تجنب تحميل الملفات من مصادر غير موثوقة',
            'استخدام حسابات مستخدمين محدودة الصلاحيات',
            'عمل نسخ احتياطية منتظمة للبيانات المهمة',
            'تفعيل جدار الحماية وحماية البريد الإلكتروني'
        ]
        
        # Add specific tips based on analysis results
        try:
            static_result = analysis_result.get('static_analysis', {})
            
            if static_result.get('suspicious_indicators', {}).get('packed'):
                tips.append('كن حذراً جداً من الملفات المحزمة أو المشفرة')
            
            dynamic_result = analysis_result.get('dynamic_analysis', {})
            if dynamic_result.get('behavior_score', 0) > 50:
                tips.append('استخدم بيئات معزولة (sandbox) لاختبار الملفات المشبوهة')
                
        except:
            pass
            
        return tips
    
    def generate_educational_report(self, analysis_result):
        """Generate comprehensive educational report"""
        explanation = self.explain_behavior(analysis_result)
        
        report = {
            'title': 'تقرير تعليمي - تحليل البرامج الضارة',
            'timestamp': analysis_result.get('timestamp', 'غير محدد'),
            'filename': analysis_result.get('filename', 'غير محدد'),
            'sections': {
                'verdict': explanation['overall_verdict'],
                'behaviors': explanation['behavior_analysis'],
                'technical': explanation['technical_details'],
                'learning': explanation['learning_points'],
                'prevention': explanation['prevention_tips']
            }
        }
        
        return report
