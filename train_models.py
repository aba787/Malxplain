
#!/usr/bin/env python3
"""
MalXplain Model Training Script
تدريب نماذج التعلم الآلي لتحليل البرامج الضارة
"""س

from modules.ml_models import MLPredictor
from modules.feature_engineering import FeatureEngineer
import pandas as pd
import numpy as np

def main():
    print("=" * 60)
    print("MalXplain - تدريب نماذج التعلم الآلي")
    print("=" * 60)
    
    # Initialize components
    ml_predictor = MLPredictor()
    feature_engineer = FeatureEngineer()
    
    print("1. إنشاء بيانات تدريبية تجريبية...")
    
    # Generate sample dataset
    X, y = ml_predictor.generate_sample_dataset(n_samples=2000)
    print(f"   - تم إنشاء {len(X)} عينة تدريبية")
    print(f"   - عدد الميزات: {len(X.columns)}")
    print(f"   - العينات الضارة: {sum(y)} ({sum(y)/len(y)*100:.1f}%)")
    print(f"   - العينات الآمنة: {len(y)-sum(y)} ({(len(y)-sum(y))/len(y)*100:.1f}%)")
    
    print("\n2. تجهيز البيانات...")
    
    # Prepare data
    X_processed, y_processed = feature_engineer.prepare_dataset([X.iloc[i].to_dict() for i in range(len(X))], y)
    
    print("   - تم تنظيف البيانات والتعامل مع القيم المفقودة")
    print("   - تم تحويل البيانات النصية إلى رقمية")
    
    print("\n3. تدريب النماذج...")
    print("-" * 40)
    
    # Train models
    results = ml_predictor.train_models(X_processed, y_processed, test_size=0.2)
    
    print("\n4. تقييم النماذج...")
    print("-" * 40)
    
    # Evaluate models
    ml_predictor.evaluate_models(results)
    
    print("\n5. حفظ أفضل نموذج...")
    
    # Save best model
    ml_predictor.save_best_model('models/malxplain_model.pkl')
    
    print(f"✅ تم حفظ النموذج الأفضل: {ml_predictor.best_model_name}")
    
    print("\n" + "=" * 60)
    print("تم الانتهاء من تدريب النماذج بنجاح!")
    print("يمكنك الآن استخدام النماذج في التحليل")
    print("=" * 60)
    
    # Generate feature importance report
    if hasattr(ml_predictor.best_model, 'feature_importances_'):
        print("\n6. أهم الميزات في التصنيف:")
        print("-" * 30)
        
        feature_names = X.columns.tolist()
        importance = ml_predictor.best_model.feature_importances_
        
        # Sort features by importance
        feature_importance = [(name, imp) for name, imp in zip(feature_names, importance)]
        feature_importance.sort(key=lambda x: x[1], reverse=True)
        
        for i, (feature, importance_score) in enumerate(feature_importance[:10]):
            print(f"{i+1:2d}. {feature:25s} {importance_score:.4f}")
    
    print(f"\nتم حفظ مخطط تقييم النماذج في: model_evaluation.png")

if __name__ == "__main__":
    # Create models directory
    import os
    os.makedirs('models', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)
    
    main()
