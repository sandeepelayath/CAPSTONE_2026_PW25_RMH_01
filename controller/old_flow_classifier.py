import pickle
import pandas as pd
import random 

class FlowClassifier:
    def __init__(self):
        try:
            # Load trained model and scaler
            with open('../ml_model/model.pkl', 'rb') as f:
                self.model, self.scaler = pickle.load(f)

            # Extract correct feature order from the scaler
            self.feature_names = [name.strip() for name in self.scaler.feature_names_in_]
            print("Feature names from model:", self.feature_names)  # Debugging

        except Exception as e:
            print(f"Warning: Could not load model file. Using dummy classifier. Error: {e}")
            self.model = None
            self.scaler = None
            self.feature_names = []

    def extract_features(self, flow_stats):
        """
        Extracts flow statistics and returns a DataFrame with correct feature names and order.
        """
        try:
            # Extract flow statistics
            duration = flow_stats.duration_sec + flow_stats.duration_nsec * 1e-9
            bytes_per_sec = flow_stats.byte_count / duration if duration > 0 else 0
            packets_per_sec = flow_stats.packet_count / duration if duration > 0 else 0

            # Create a dictionary of features with stripped keys
            features_dict = {
                "Flow Duration": duration,
                "Total Fwd Packets": flow_stats.packet_count,
                "Total Backward Packets": 0,  # Assuming no backward packets
                "Total Length of Fwd Packets": flow_stats.byte_count,
                "Total Length of Bwd Packets": 0,  # No backward bytes
                "Flow Bytes/s": bytes_per_sec,
                "Flow Packets/s": packets_per_sec
            }

            # Ensure the correct feature order by selecting based on trained model feature names
            ordered_features = [features_dict[feat] for feat in self.feature_names]

            # Return the features in a DataFrame with the correct order
            return pd.DataFrame([ordered_features], columns=self.feature_names)

        except AttributeError as e:
            print(f"Error extracting flow features: {e}")
            return None

    def classify_flow(self, flow_stats):
        """
        Classifies a given flow. Returns True if it's an anomaly, False otherwise.
        """
        if self.model is None or self.scaler is None:
            return False
        
        try:
            # Extract features and ensure they're correctly ordered and scaled
            features = self.extract_features(flow_stats)
            if features is None:
                return False

            # Transform using the trained scaler (feature names match)
            scaled_features = self.scaler.transform(features)
            prediction = self.model.predict(scaled_features)

            return bool(prediction[0])

        except Exception as e:
            #print(f"Error in classification: {e}")
            #for test purposes
            #print(f"Error in classification")
            return random.choice([True, False])  # In case of error, return random value
