import pickle
import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model
import random

class FlowClassifier:
    def __init__(self):
        try:
            # Load trained LSTM model
            self.model = load_model('../ml_model/lstm_model.h5')
            
            # Load scaler separately
            with open('../ml_model/scaler.pk1', 'rb') as f:
                self.scaler = pickle.load(f)

            # Load feature names from file
            with open('../ml_model/feature_names.pk1', 'rb') as f:
                self.feature_names = pickle.load(f)
                
            print(f"Loaded {len(self.feature_names)} feature names from file")

        except Exception as e:
            print(f"Warning: Could not load model files. Using dummy classifier. Error: {e}")
            self.model = None
            self.scaler = None
            self.feature_names = []

    def extract_features(self, flow_stats):
        """
        Extracts flow statistics and returns a DataFrame with all required features.
        Many features are estimated as we don't have complete flow statistics.
        """
        try:
            # Extract basic flow statistics from the flow_stats object
            duration = flow_stats.duration_sec + flow_stats.duration_nsec * 1e-9
            packet_count = flow_stats.packet_count
            byte_count = flow_stats.byte_count
            
            # Estimate source/destination ports (assuming this might be available)
            # In a real system, you would extract these from the flow
            dest_port = getattr(flow_stats, 'dst_port', 80)  # Default to 80 if not available
            
            # Calculate derived metrics
            bytes_per_sec = byte_count / duration if duration > 0 else 0
            packets_per_sec = packet_count / duration if duration > 0 else 0
            
            # Estimate packet size statistics
            avg_packet_size = byte_count / packet_count if packet_count > 0 else 0
            # Assume these values for demonstration - in reality, you'd calculate from actual packet data
            min_packet_size = avg_packet_size * 0.5
            max_packet_size = avg_packet_size * 1.5
            packet_size_std = avg_packet_size * 0.2
            
            # Assume it's mostly forward traffic in this simplified model
            fwd_packets = packet_count
            fwd_bytes = byte_count
            bwd_packets = 0
            bwd_bytes = 0
            
            # Inter-arrival time statistics (estimated)
            iat_mean = duration / packet_count if packet_count > 1 else duration
            iat_std = iat_mean * 0.5  # Just an estimation
            iat_max = iat_mean * 2
            iat_min = iat_mean * 0.1
            
            # TCP flag counts (assumed values)
            # In a real implementation, extract these from flow data
            fin_flags = 0
            syn_flags = 1
            rst_flags = 0
            psh_flags = 0
            ack_flags = 1
            urg_flags = 0
            
            # Create a dictionary with all required features
            features_dict = {}
            
            # Set all values to 0 first to ensure we have all features
            for feature in self.feature_names:
                features_dict[feature] = 0
                
            # Update with the values we can calculate
            feature_values = {
                'Destination Port': dest_port,
                'Flow Duration': duration,
                'Total Fwd Packets': fwd_packets,
                'Total Backward Packets': bwd_packets,
                'Total Length of Fwd Packets': fwd_bytes,
                'Total Length of Bwd Packets': bwd_bytes,
                'Fwd Packet Length Max': max_packet_size,
                'Fwd Packet Length Min': min_packet_size,
                'Fwd Packet Length Mean': avg_packet_size,
                'Fwd Packet Length Std': packet_size_std,
                'Flow Bytes/s': bytes_per_sec,
                'Flow Packets/s': packets_per_sec,
                'Flow IAT Mean': iat_mean,
                'Flow IAT Std': iat_std,
                'Flow IAT Max': iat_max,
                'Flow IAT Min': iat_min,
                'Fwd IAT Mean': iat_mean,
                'Fwd IAT Std': iat_std,
                'Fwd IAT Max': iat_max,
                'Fwd IAT Min': iat_min,
                'Min Packet Length': min_packet_size,
                'Max Packet Length': max_packet_size,
                'Packet Length Mean': avg_packet_size,
                'Packet Length Std': packet_size_std,
                'Packet Length Variance': packet_size_std ** 2,
                'FIN Flag Count': fin_flags,
                'SYN Flag Count': syn_flags,
                'RST Flag Count': rst_flags,
                'PSH Flag Count': psh_flags,
                'ACK Flag Count': ack_flags,
                'URG Flag Count': urg_flags,
                'Average Packet Size': avg_packet_size,
                'Avg Fwd Segment Size': avg_packet_size,
                'Fwd Packets/s': packets_per_sec,
                'Subflow Fwd Packets': fwd_packets,
                'Subflow Fwd Bytes': fwd_bytes,
                'Active Mean': duration,
                'Idle Mean': 0
            }
            
            # Update the features dictionary with our calculated values
            features_dict.update(feature_values)
            
            # Create a DataFrame with all features in the correct order
            df = pd.DataFrame([features_dict])
            
            # Ensure we're using the exact feature names and order from training
            df = df[self.feature_names]
            
            # Handle infinity and NaN values
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            df.fillna(0, inplace=True)
            
            return df
            
        except Exception as e:
            print(f"Error extracting flow features: {e}")
            return None

    def classify_flow(self, flow_stats):
        """
        Classifies a given flow. Returns True if it's an anomaly, False otherwise.
        """
        if self.model is None or self.scaler is None:
            print(f"Error in model")
            return False
        
        try:
            # Extract features
            features_df = self.extract_features(flow_stats)
            if features_df is None:
                return False
                
            # Scale features
            scaled_features = self.scaler.transform(features_df)
            
            # Reshape for LSTM input: (samples, time steps, features)
            lstm_input = np.reshape(scaled_features, (scaled_features.shape[0], 1, scaled_features.shape[1]))
            
            # Get prediction from LSTM model
            prediction = self.model.predict(lstm_input, verbose=0)
            print("Prediction:", prediction)
            
            # Convert prediction to boolean (True if probability > 0.5)
            # LSTM with sigmoid activation outputs values between 0 and 1
            is_anomaly = bool(prediction[0][0] > 0.5)
            
            return is_anomaly

        except Exception as e:
            print(f"Error in classification: {e}")
            return random.choice([True, False])  # In case of error, return random value
