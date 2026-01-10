
# MalXplain - محلل البرامج الضارة التعليمي

أداة تعليمية لفهم كيفية عمل تحليل البرامج الضارة باستخدام التحليل الثابت والديناميكي والتعلم الآلي.

## التثبيت والتشغيل

### 1. تثبيت المتطلبات
```bash
pip install -r requirements.txt
```

### 2. تدريب النماذج
```bash
python train_models.py
```

### 3. تشغيل الخادم
```bash
python main.py
```

الخادم سيعمل على: http://0.0.0.0:5000

## استخدام API

### تحليل ملف
```bash
curl -X POST -F "file=@sample.exe" http://localhost:5000/upload
```

### الحصول على تقرير
```bash
curl http://localhost:5000/report/{analysis_id}
```

## الميزات

- **التحليل الثابت**: استخراج خصائص PE، الاستيرادات، النصوص، والإنتروبيا
- **التحليل الديناميكي**: دعم تقارير Any.Run وMحاكاة السلوك
- **التعلم الآلي**: Random Forest, SVM, Neural Networks
- **واجهة تعليمية**: شرح مبسط لعملية التحليل
- **واجهة ويب**: رفع الملفات وعرض النتائج

## هيكل المشروع

```
├── main.py              # خادم Flask الرئيسي
├── train_models.py      # تدريب النماذج
├── modules/             # وحدات التحليل
│   ├── static_analysis.py
│   ├── dynamic_analysis.py  
│   ├── feature_engineering.py
│   ├── ml_models.py
│   ├── prediction_engine.py
│   └── educational_interface.py
├── templates/           # قوالب HTML
├── tests/              # اختبارات الوحدة
├── models/             # النماذج المدربة
└── reports/            # تقارير التحليل
```

## الأمان

- لا يتم تشغيل الملفات المشبوهة مباشرة
- التحليل الديناميكي يعتمد على التقارير المحفوظة أو المحاكاة
- جميع الملفات المرفوعة تُحفظ في مجلد منعزل

## الاختبار

```bash
python -m pytest tests/
```
