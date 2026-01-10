
#!/usr/bin/env python3
"""
إنشاء عينات تعليمية للتدريب والعرض
Educational samples generator for demonstration
"""

import os
import json
import hashlib
import random
from datetime import datetime

def create_benign_samples():
    """إنشاء ملفات آمنة للاختبار"""
    benign_dir = "samples/benign"
    
    # Create simple benign executables (dummy content)
    samples = {
        "windows_calculator.exe": b"MZ\x90\x00" + b"CALC_DEMO" + b"\x00" * 1000,
        "text_editor.exe": b"MZ\x90\x00" + b"NOTEPAD_DEMO" + b"\x00" * 2000,
        "media_player.exe": b"MZ\x90\x00" + b"PLAYER_DEMO" + b"\x00" * 1500,
        "system_tool.dll": b"MZ\x90\x00" + b"SYSTEM_DEMO" + b"\x00" * 800,
        "graphics_lib.dll": b"MZ\x90\x00" + b"GFX_DEMO" + b"\x00" * 1200
    }
    
    for filename, content in samples.items():
        filepath = os.path.join(benign_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(content)
        
        print(f"✅ Created benign sample: {filename}")

def create_malicious_samples():
    """إنشاء عينات تمثل مالوير للتعليم فقط (ليست حقيقية)"""
    malicious_dir = "samples/malicious"
    
    # Create dummy malicious files (safe content)
    dummy_samples = {
        "fake_ransomware.exe": b"MZ\x90\x00" + b"FAKE_RANSOM_DEMO" + b"\x00" * 1000,
        "dummy_trojan.exe": b"MZ\x90\x00" + b"FAKE_TROJAN_DEMO" + b"\x00" * 1800,
        "test_keylogger.exe": b"MZ\x90\x00" + b"FAKE_KEYLOG_DEMO" + b"\x00" * 1200,
        "mock_botnet.dll": b"MZ\x90\x00" + b"FAKE_BOT_DEMO" + b"\x00" * 900
    }
    
    for filename, content in dummy_samples.items():
        filepath = os.path.join(malicious_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(content)
        
        print(f"⚠️ Created malicious demo: {filename}")
    
    # Create behavior reports for educational purposes
    malicious_reports = {
        "advanced_persistent_threat.json": {
            "filename": "apt_demo.exe",
            "analysis_type": "educational_demo",
            "static_analysis": {
                "entropy": 7.8,
                "imports": ["CreateProcess", "WriteProcessMemory", "VirtualAlloc"],
                "suspicious_strings": ["cmd.exe", "powershell", "whoami"],
                "packed": True
            },
            "dynamic_analysis": {
                "behavior_score": 85,
                "network_activity": {
                    "tcp_connections": [{"destination": "malicious-c2.example", "port": 443}],
                    "dns_requests": ["evil-domain.com"]
                },
                "registry_changes": {
                    "keys_created": ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware"]
                },
                "file_operations": {
                    "files_created": ["C:\\temp\\malicious_payload.exe"],
                    "files_deleted": ["C:\\Users\\User\\Documents\\*.doc"]
                }
            },
            "prediction": {
                "result": "Malicious",
                "confidence": 0.92,
                "model": "educational_demo"
            }
        },
        
        "banking_trojan.json": {
            "filename": "banking_demo.exe",
            "analysis_type": "educational_demo",
            "static_analysis": {
                "entropy": 6.9,
                "imports": ["InternetOpen", "HttpSendRequest", "RegCreateKey"],
                "suspicious_strings": ["password", "bank", "credential"],
                "packed": False
            },
            "dynamic_analysis": {
                "behavior_score": 78,
                "network_activity": {
                    "tcp_connections": [{"destination": "phishing-site.example", "port": 80}],
                    "http_requests": [{"url": "http://evil.com/steal", "method": "POST"}]
                },
                "registry_changes": {
                    "keys_created": ["HKCU\\Software\\BankingTrojan"]
                }
            },
            "prediction": {
                "result": "Malicious", 
                "confidence": 0.87,
                "model": "educational_demo"
            }
        }
    }
    
    for filename, report_data in malicious_reports.items():
        filepath = os.path.join(malicious_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"📊 Created behavior report: {filename}")

def create_readme():
    """إنشاء ملف README للعينات"""
    readme_content = """# Educational Samples - عينات تعليمية

هذا المجلد يحتوي على عينات تعليمية لتوضيح مفاهيم تحليل البرامج الضارة.

## benign/ - الملفات الآمنة

ملفات آمنة تماماً للاستخدام في التدريب والعروض التوضيحية:

- `windows_calculator.exe` - محاكي آلة حاسبة آمن
- `text_editor.exe` - محاكي محرر نصوص آمن  
- `media_player.exe` - محاكي مشغل وسائط آمن
- `system_tool.dll` - مكتبة نظام تجريبية آمنة
- `graphics_lib.dll` - مكتبة رسوميات تجريبية آمنة

## malicious/ - العينات التعليمية للبرامج الضارة

⚠️ **تنبيه مهم**: هذه ملفات تعليمية آمنة تماماً وليست برامج ضارة حقيقية!

### الملفات التجريبية:
- `fake_ransomware.exe` - محاكي فدية (آمن للتعليم)
- `dummy_trojan.exe` - محاكي حصان طروادة (آمن للتعليم)
- `test_keylogger.exe` - محاكي مسجل مفاتيح (آمن للتعليم)
- `mock_botnet.dll` - محاكي شبكة بوت (آمن للتعليم)

### تقارير السلوك JSON:
- `advanced_persistent_threat.json` - تقرير تهديد متقدم مستمر
- `banking_trojan.json` - تقرير حصان طروادة مصرفي

## الاستخدام في العرض:

1. **للإظهار الآمن**: ارفع ملف من `benign/` → النتيجة: Safe ✅
2. **للإظهار الضار**: ارفع ملف من `malicious/` → النتيجة: Malicious ⚠️

## الغرض التعليمي:

- فهم كيفية عمل تحليل البرامج الضارة
- تعلم خصائص الملفات الآمنة والضارة
- استكشاف تقنيات التعلم الآلي في الأمن السيبراني
- ممارسة التحليل الثابت والديناميكي

**ملاحظة**: جميع الملفات آمنة للاستخدام في البيئات التعليمية والتدريبية.
"""
    
    with open("samples/README.md", 'w', encoding='utf-8') as f:
        f.write(readme_content)
    
    print("📖 Created samples README.md")

def main():
    print("إنشاء العينات التعليمية...")
    print("=" * 50)
    
    # Create directories
    os.makedirs("samples/benign", exist_ok=True)
    os.makedirs("samples/malicious", exist_ok=True)
    
    # Create samples
    create_benign_samples()
    print()
    create_malicious_samples()
    print()
    create_readme()
    
    print("\n" + "=" * 50)
    print("✅ تم إنشاء جميع العينات التعليمية بنجاح!")
    print("\nيمكنك الآن استخدام الملفات في:")
    print("- samples/benign/ للملفات الآمنة")
    print("- samples/malicious/ للعينات التعليمية")
    print("\n📖 اقرأ samples/README.md للتفاصيل الكاملة")

if __name__ == "__main__":
    main()
