
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest, f_classif
import json

class FeatureEngineer:
    def __init__(self):
        self.scaler = StandardScaler()
        self.feature_selector = SelectKBest(f_classif, k=50)
        self.label_encoder = LabelEncoder()
        self.selected_features = None
        
    def extract_features(self, static_analysis, dynamic_analysis):
        """Extract and combine features from static and dynamic analysis"""
        features = {}
        
        # Static features
        static_features = self._extract_static_features(static_analysis)
        features.update(static_features)
        
        # Dynamic features
        if dynamic_analysis:
            dynamic_features = self._extract_dynamic_features(dynamic_analysis)
            features.update(dynamic_features)
            
        return features
    
    def _extract_static_features(self, static_analysis):
        """Extract numerical features from static analysis"""
        features = {}
        
        # File size
        if 'file_info' in static_analysis:
            features['file_size'] = static_analysis['file_info'].get('size', 0)
            
        # PE header features
        if 'pe_headers' in static_analysis:
            headers = static_analysis['pe_headers']
            features['number_of_sections'] = headers.get('number_of_sections', 0)
            features['size_of_optional_header'] = headers.get('size_of_optional_header', 0)
            features['entry_point'] = int(headers.get('entry_point', '0x0'), 16) if headers.get('entry_point') else 0
            
        # Import features
        if 'imports' in static_analysis:
            imports = static_analysis['imports']
            features['number_of_imports'] = len(imports)
            features['number_of_imported_dlls'] = len(imports.keys())
            
            # Count suspicious imports
            suspicious_count = 0
            for dll, functions in imports.items():
                for func in functions:
                    if any(sus in func.lower() for sus in ['process', 'memory', 'registry', 'internet']):
                        suspicious_count += 1
            features['suspicious_imports_count'] = suspicious_count
            
        # String features
        if 'strings' in static_analysis:
            strings_info = static_analysis['strings']
            features['total_strings'] = strings_info.get('total_strings', 0)
            features['suspicious_strings_count'] = len(strings_info.get('suspicious_strings', []))
            
        # Entropy
        features['entropy'] = static_analysis.get('entropy', 0)
        
        # Suspicious indicators
        if 'suspicious_indicators' in static_analysis:
            indicators = static_analysis['suspicious_indicators']
            features['is_packed'] = 1 if indicators.get('packed', False) else 0
            features['unusual_sections_count'] = len(indicators.get('unusual_sections', []))
            features['suspicious_api_count'] = len(indicators.get('suspicious_imports', []))
            features['high_entropy'] = 1 if indicators.get('high_entropy', False) else 0
            
        return features
    
    def _extract_dynamic_features(self, dynamic_analysis):
        """Extract numerical features from dynamic analysis"""
        features = {}
        
        if 'behavior_score' in dynamic_analysis:
            features['behavior_score'] = dynamic_analysis['behavior_score']
            
        if 'behavior' in dynamic_analysis:
            behavior = dynamic_analysis['behavior']
            
            # Network activity features
            if 'network_activity' in behavior:
                net = behavior['network_activity']
                features['tcp_connections_count'] = len(net.get('tcp_connections', []))
                features['dns_requests_count'] = len(net.get('dns_requests', []))
                features['http_requests_count'] = len(net.get('http_requests', []))
                
            # Registry features
            if 'registry_changes' in behavior:
                reg = behavior['registry_changes']
                features['registry_keys_created'] = len(reg.get('keys_created', []))
                features['registry_values_set'] = len(reg.get('values_set', []))
                features['registry_keys_deleted'] = len(reg.get('keys_deleted', []))
                
            # File operation features
            if 'file_operations' in behavior:
                files = behavior['file_operations']
                features['files_created_count'] = len(files.get('files_created', []))
                features['files_deleted_count'] = len(files.get('files_deleted', []))
                features['files_modified_count'] = len(files.get('files_modified', []))
                
            # Process features
            if 'process_creation' in behavior:
                procs = behavior['process_creation']
                features['processes_created_count'] = len(procs.get('processes_created', []))
                features['dlls_loaded_count'] = len(procs.get('dlls_loaded', []))
                
        return features
    
    def prepare_dataset(self, features_list, labels):
        """Prepare dataset for machine learning"""
        # Convert to DataFrame
        df = pd.DataFrame(features_list)
        
        # Handle missing values
        df = df.fillna(0)
        
        # Ensure all features are numeric
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = self.label_encoder.fit_transform(df[col].astype(str))
                
        return df, labels
    
    def scale_features(self, X_train, X_test=None):
        """Scale features using StandardScaler"""
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        if X_test is not None:
            X_test_scaled = self.scaler.transform(X_test)
            return X_train_scaled, X_test_scaled
            
        return X_train_scaled
    
    def select_features(self, X_train, y_train, X_test=None):
        """Select best features"""
        X_train_selected = self.feature_selector.fit_transform(X_train, y_train)
        self.selected_features = self.feature_selector.get_support()
        
        if X_test is not None:
            X_test_selected = self.feature_selector.transform(X_test)
            return X_train_selected, X_test_selected
            
        return X_train_selected
    
    def process_single_sample(self, features):
        """Process a single sample for prediction"""
        # Convert to DataFrame
        df = pd.DataFrame([features])
        
        # Handle missing values
        df = df.fillna(0)
        
        # Scale features
        df_scaled = self.scaler.transform(df)
        
        # Select features if feature selection was applied
        if self.selected_features is not None:
            df_selected = df_scaled[:, self.selected_features]
            return df_selected
            
        return df_scaled
    
    def get_feature_importance(self, model, feature_names):
        """Get feature importance from trained model"""
        if hasattr(model, 'feature_importances_'):
            importance = model.feature_importances_
        elif hasattr(model, 'coef_'):
            importance = np.abs(model.coef_[0])
        else:
            return {}
            
        # Create feature importance dictionary
        feature_importance = {}
        for i, importance_score in enumerate(importance):
            if i < len(feature_names):
                feature_importance[feature_names[i]] = importance_score
                
        # Sort by importance
        sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
        
        return dict(sorted_features[:10])  # Return top 10 features
