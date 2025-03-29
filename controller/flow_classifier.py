import pickle
import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.saving import load_model
import time
import json

class FlowClassifier:
    def __init__(self, 
                 model_path='../ml_model/lstm_model_combined.keras', 
                 scaler_path='../ml_model/scaler.pkl', 
                 features_path='../ml_model/feature_names.pkl'):
        try:
            self.model = load_model(model_path)
            self.model.compile(optimizer='adam', loss='binary_crossentropy', 
                             metrics=['accuracy', 'precision', 'recall', 'AUC'])
            
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            with open(features_path, 'rb') as f:
                self.feature_names = pickle.load(f)
                
            print(f"✅ Loaded {len(self.feature_names)} feature names")
            self.validation_metrics = {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0}
        except Exception as e:
            print(f"❌ Model loading failed: {e}")
            self.model = None
            self.scaler = None
            self.feature_names = []

    def extract_features(self, flow_stats):
        """Extracts the relevant features from flow statistics for ML classification."""
        try:
            features_dict = {feature: 0.0 for feature in self.feature_names}

            # Enhanced feature mappings based on CICIDS2017
            feature_mappings = {
                "Flow Duration": lambda fs: fs.duration_sec + fs.duration_nsec * 1e-9 if hasattr(fs, 'duration_sec') else 0,
                "Total Fwd Packets": lambda fs: getattr(fs, 'packet_count', 0),
                "Total Backward Packets": lambda fs: getattr(fs, 'packet_count_rev', 0),
                "Total Length of Fwd Packets": lambda fs: getattr(fs, 'byte_count', 0),
                "Total Length of Bwd Packets": lambda fs: getattr(fs, 'byte_count_rev', 0),
                "Flow Bytes/s": lambda fs: getattr(fs, 'byte_count', 0) / max(getattr(fs, 'duration_sec', 0.001), 0.001),
                "Flow Packets/s": lambda fs: getattr(fs, 'packet_count', 0) / max(getattr(fs, 'duration_sec', 0.001), 0.001),
                "Flow IAT Mean": lambda fs: getattr(fs, 'iat_mean', 0),
                "Fwd IAT Mean": lambda fs: getattr(fs, 'fwd_iat_mean', 0),
                "Bwd IAT Mean": lambda fs: getattr(fs, 'bwd_iat_mean', 0),
                "Fwd Packet Length Mean": lambda fs: getattr(fs, 'fwd_pkt_len_mean', 0),
                "Bwd Packet Length Mean": lambda fs: getattr(fs, 'bwd_pkt_len_mean', 0),
                "Flow TCP Flags": lambda fs: sum(1 << i for i, flag in enumerate(getattr(fs, 'tcp_flags', [])) if flag),
            }

            for feature, func in feature_mappings.items():
                if feature in self.feature_names:
                    features_dict[feature] = func(flow_stats)

            df = pd.DataFrame([features_dict])[self.feature_names]
            df.replace([np.inf, -np.inf], 0, inplace=True)
            df.fillna(0, inplace=True)

            #print(f"Extracted Features: {df.to_dict(orient='records')}")
            return df
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return None

    def classify_flow(self, flow_stats, anomaly_threshold=0.2):
        """Classifies a network flow as normal or anomalous."""
        if self.model is None or self.scaler is None:
            print("❌ Model or scaler not loaded")
            return False
        
        try:
            features_df = self.extract_features(flow_stats)
            if features_df is None:
                print("❌ Feature extraction failed")
                return False
            
            # Scale the extracted features
            scaled_features = self.scaler.transform(features_df)
            lstm_input = np.reshape(scaled_features, (scaled_features.shape[0], 1, scaled_features.shape[1]))
            prediction = self.model.predict(lstm_input, verbose=0)
            
            #print(f"📊 Prediction Probability: {prediction[0][0]:.4f} | Threshold: {anomaly_threshold}")
            
            is_anomaly = bool(prediction[0][0] > anomaly_threshold)
            
            # Update validation metrics if ground truth is available
            if hasattr(flow_stats, 'ground_truth'):
                self._update_metrics(is_anomaly, flow_stats.ground_truth)
            
            if is_anomaly:
                print("🚨 ALERT: Anomalous Flow Detected!")
                self._log_anomaly(flow_stats, prediction[0][0])
            #else:
                #print("✅ Normal Flow Detected")
            
            return is_anomaly
        except Exception as e:
            print(f"Classification error: {e}")
            return False

    def _update_metrics(self, predicted_anomaly, actual_anomaly):
        """Updates the confusion matrix metrics."""
        if predicted_anomaly and actual_anomaly:
            self.validation_metrics['TP'] += 1
        elif predicted_anomaly and not actual_anomaly:
            self.validation_metrics['FP'] += 1
        elif not predicted_anomaly and actual_anomaly:
            self.validation_metrics['FN'] += 1
        else:
            self.validation_metrics['TN'] += 1

    def _log_anomaly(self, flow_stats, confidence):
        """Logs detailed information about detected anomalies."""
        anomaly_info = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'confidence': float(confidence),  # Convert float32 to Python float
            'flow_info': {
                'src_ip': getattr(flow_stats, 'ipv4_src', 'unknown'),
                'dst_ip': getattr(flow_stats, 'ipv4_dst', 'unknown'),
                'src_port': getattr(flow_stats, 'tcp_src', 'unknown'),
                'dst_port': getattr(flow_stats, 'tcp_dst', 'unknown'),
                'protocol': getattr(flow_stats, 'ip_proto', 'unknown'),
            }
        }
        print(f"🔍 Anomaly Details: {json.dumps(anomaly_info, indent=2)}")

    def get_metrics(self):
        """Returns current validation metrics."""
        metrics = self.validation_metrics.copy()
        total = sum(metrics.values())
        if total > 0:
            metrics['accuracy'] = (metrics['TP'] + metrics['TN']) / total
            metrics['precision'] = metrics['TP'] / (metrics['TP'] + metrics['FP']) if (metrics['TP'] + metrics['FP']) > 0 else 0
            metrics['recall'] = metrics['TP'] / (metrics['TP'] + metrics['FN']) if (metrics['TP'] + metrics['FN']) > 0 else 0
            metrics['f1_score'] = 2 * (metrics['precision'] * metrics['recall']) / (metrics['precision'] + metrics['recall']) if (metrics['precision'] + metrics['recall']) > 0 else 0
        return metrics
