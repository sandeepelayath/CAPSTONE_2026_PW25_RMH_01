from datetime import datetime
import pickle
import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model
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
                               metrics=['accuracy', 'Precision', 'Recall', 'AUC'])
            
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            with open(features_path, 'rb') as f:
                self.feature_names = pickle.load(f)
                
            print(f"✅ Loaded model with {len(self.feature_names)} features")
            self.validation_metrics = {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0}
        except Exception as e:
            print(f"❌ Model loading failed: {e}")
            self.model = None
            self.scaler = None
            self.feature_names = []

    def extract_features(self, flow_stats):
        """Extracts features from flow_stats into a DataFrame row."""
        try:
            features_dict = {feature: 0.0 for feature in self.feature_names}
            
            # Basic metrics
            duration = getattr(flow_stats, 'duration_sec', 0) + getattr(flow_stats, 'duration_nsec', 0) * 1e-9
            packet_count = getattr(flow_stats, 'packet_count', 0)
            byte_count = getattr(flow_stats, 'byte_count', 0)

            flow_bytes_per_sec = byte_count / max(duration, 0.001)
            flow_packets_per_sec = packet_count / max(duration, 0.001)
            avg_packet_size = byte_count / max(packet_count, 1)
            iat_mean = duration / max(packet_count, 2)

            tcp_flags = 0
            if hasattr(flow_stats, 'match') and hasattr(flow_stats.match, 'get'):
                tcp_flags = flow_stats.match.get('tcp_flags', 0)

            # Mappings
            mappings = {
                "Total Length of Fwd Packets": byte_count,
                "Average Packet Size": avg_packet_size,
                "Flow Duration": duration,
                "Flow Packets/s": flow_packets_per_sec,
                "Flow Bytes/s": flow_bytes_per_sec,
                "Flow IAT Mean": iat_mean,
                "Fwd PSH Flags": 1 if (tcp_flags & 0x08) else 0,
                "Bwd PSH Flags": 0,
                "SYN Flag Count": 1 if (tcp_flags & 0x02) else 0,
                "Flow IAT Std": iat_mean * 0.5,
                "Flow IAT Max": iat_mean * 2,
                "Flow IAT Min": iat_mean * 0.1
            }

            for feature in self.feature_names:
                if feature in mappings:
                    features_dict[feature] = mappings[feature]

            df = pd.DataFrame([features_dict])[self.feature_names]
            df.replace([np.inf, -np.inf], 0, inplace=True)
            df.fillna(0, inplace=True)

            return df
        except Exception as e:
            print(f"❌ Feature extraction failed: {e}")
            return None

    def classify_flow(self, flow_stats, anomaly_threshold=0.17):
        """Classifies a network flow as normal or anomalous."""
        if self.model is None or self.scaler is None:
            print("❌ Model or scaler not loaded")
            return False

        try:
            features_df = self.extract_features(flow_stats)
            if features_df is None:
                return False

            scaled = self.scaler.transform(features_df)
            lstm_input = scaled.reshape(scaled.shape[0], 1, scaled.shape[1])  # shape: (1, 1, features)

            prediction = self.model.predict(lstm_input, verbose=0)
            prob = prediction[0][0]
            is_anomaly = prob > anomaly_threshold

            if is_anomaly:
                print("🚨 ALERT: Anomalous Flow Detected!")
                print(f"📊 Prediction Probability: {prob:.4f} | Threshold: {anomaly_threshold}")
                self._log_anomaly(flow_stats, prob)

            return is_anomaly
        except Exception as e:
            print(f"❌ Classification error: {e}")
            return False

    def _log_anomaly(self, flow_stats, confidence):
        try:
            match = flow_stats.match
            match_dict = match.to_jsondict().get('OFPMatch', {})

            flow_info = {
                "protocol": match_dict.get('ip_proto', 'unknown'),
                "src_ip": match_dict.get('ipv4_src', 'unknown'),
                "dst_ip": match_dict.get('ipv4_dst', 'unknown'),
                "src_port": match_dict.get('tcp_src', match_dict.get('udp_src', 'unknown')),
                "dst_port": match_dict.get('tcp_dst', match_dict.get('udp_dst', 'unknown'))
            }

            anomaly_log = {
                "timestamp": str(datetime.now()),
                "confidence": float(confidence),
                "flow_info": flow_info,
                "statistics": {
                    "duration": flow_stats.duration_sec,
                    "packets": flow_stats.packet_count,
                    "bytes": flow_stats.byte_count
                }
            }

            with open("anomaly_log.json", "a") as f:
                json.dump(anomaly_log, f)
                f.write("\n")

            print(f"⚠️ Anomaly Detected in Flow {match}")

            # Now attempt to remove the flow
            #match_obj = parser.OFPMatch(**match_dict)
            #self.remove_flow(self.datapaths.get(flow_stats.datapath_id), match_obj)

        except Exception as e:
            print(f"❌ Error logging anomaly: {e}")



    def get_metrics(self):
        m = self.validation_metrics.copy()
        total = sum(m.values())
        if total > 0:
            m['accuracy'] = (m['TP'] + m['TN']) / total
            m['precision'] = m['TP'] / (m['TP'] + m['FP']) if m['TP'] + m['FP'] > 0 else 0
            m['recall'] = m['TP'] / (m['TP'] + m['FN']) if m['TP'] + m['FN'] > 0 else 0
            m['f1_score'] = 2 * m['precision'] * m['recall'] / (m['precision'] + m['recall']) if m['precision'] + m['recall'] > 0 else 0
        return m
