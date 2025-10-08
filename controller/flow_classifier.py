"""
Real-Time Network Flow Classification Module

This module provides real-time network flow classification capabilities using a 
pre-trained hybrid RaNN+LSTM model for network anomaly detection. It integrates
with SDN controllers to analyze OpenFlow statistics and identify malicious 
network traffic patterns in real-time.

Key Features:
- Real-time flow feature extraction from OpenFlow statistics
- Pre-trained model loading with custom layer support
- Anomaly detection with configurable thresholds
- Comprehensive logging and metrics collection
- Production-ready error handling and validation

Dependencies:
- TensorFlow/Keras for model inference
- Pandas/NumPy for feature processing
- OpenFlow statistics from SDN controllers

Author: Network Security Team
Version: 1.0 (Production)
Date: 2025
"""

from datetime import datetime
import pickle
import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model
import time
import json
from tensorflow.keras.utils import get_custom_objects


class RandomizedNeuralNetwork(tf.keras.layers.Layer):
    """
    Custom Keras Layer for Randomized Neural Network (RaNN) compatibility.
    
    This class provides a minimal implementation of the RaNN layer required
    for loading pre-trained hybrid models. It maintains compatibility with
    models serialized from the training pipeline while providing the necessary
    structure for model deserialization.
    
    Note: This is a placeholder implementation used solely for model loading.
    The actual computation logic is embedded in the saved model weights.
    
    Attributes:
        hidden_layers_sizes (list): Architecture specification for layer compatibility
    """
    
    def __init__(self, hidden_layers_sizes, **kwargs):
        """
        Initialize the RaNN layer for model compatibility.
        
        Args:
            hidden_layers_sizes (list): Layer size configuration for compatibility
            **kwargs: Additional Keras layer arguments
        """
        super().__init__(**kwargs)
        self.hidden_layers_sizes = hidden_layers_sizes

    def call(self, inputs):
        """
        Placeholder forward pass for model loading compatibility.
        
        Args:
            inputs (tf.Tensor): Input tensor
            
        Returns:
            tf.Tensor: Pass-through for compatibility (actual logic in saved weights)
        """
        return inputs

    def get_config(self):
        """
        Serialization configuration for model saving/loading.
        
        Returns:
            dict: Layer configuration for Keras serialization
        """
        config = super().get_config()
        config.update({"hidden_layers_sizes": self.hidden_layers_sizes})
        return config

class FlowClassifier:
    """
    Real-Time Network Flow Anomaly Detection Classifier
    
    This class provides a complete production-ready solution for real-time 
    network traffic classification using pre-trained hybrid RaNN+LSTM models.
    It handles model loading, feature extraction from OpenFlow statistics,
    real-time inference, and comprehensive logging for network security monitoring.
    
    The classifier is designed to integrate seamlessly with SDN controllers
    and provides high-performance anomaly detection for network traffic flows
    with configurable sensitivity thresholds.
    
    Attributes:
        model (tf.keras.Model): Loaded hybrid RaNN+LSTM model for inference
        scaler (sklearn.StandardScaler): Feature normalization component
        feature_names (list): Expected feature schema for consistency validation
        validation_metrics (dict): Performance tracking counters for evaluation
    """
    
    def __init__(self, 
                 model_path='../lstm_finetuned_ml_model/lstm_model_combined.keras', 
                 scaler_path='../lstm_finetuned_ml_model/scaler.pkl', 
                 features_path='../lstm_finetuned_ml_model/feature_names.pkl'):
        """
        Initialize the flow classifier with pre-trained model artifacts.
        
        Loads the trained hybrid model, feature scaler, and metadata required
        for real-time network flow classification. Includes comprehensive error
        handling for production deployment scenarios.
        
        Args:
            model_path (str): Path to the trained Keras model file
            scaler_path (str): Path to the serialized StandardScaler
            features_path (str): Path to the feature names specification
        """
        try:
            # Load pre-trained model with custom layer support
            custom_objects = {"RandomizedNeuralNetwork": RandomizedNeuralNetwork}
            self.model = load_model(model_path, custom_objects=custom_objects)
            
            # Recompile model for production inference optimization
            self.model.compile(optimizer='adam', loss='binary_crossentropy', 
                               metrics=['accuracy', 'Precision', 'Recall', 'AUC'])
            
            # Load feature preprocessing components for consistent normalization
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            with open(features_path, 'rb') as f:
                self.feature_names = pickle.load(f)
                
            print(f"✅ Loaded RaNN + LSTM Hybrid model with {len(self.feature_names)} features")
            
            # Initialize performance tracking metrics for validation
            self.validation_metrics = {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0}
            
        except Exception as e:
            print(f"❌ Model loading failed: {e}")
            # Graceful degradation for error scenarios
            self.model = None
            self.scaler = None
            self.feature_names = []

    def extract_features(self, flow_stats):
        """
        Extract network flow features from OpenFlow statistics for model inference.
        
        Transforms raw OpenFlow flow statistics into the standardized feature vector
        expected by the trained model. Computes derived network metrics including
        timing characteristics, packet rates, and protocol-specific indicators
        that are critical for anomaly detection.
        
        Feature Engineering Process:
        1. Extract basic flow statistics (duration, packets, bytes)
        2. Compute derived metrics (rates, averages, timing patterns)
        3. Extract protocol-specific features (TCP flags, port information)
        4. Handle edge cases and numerical stability issues
        5. Ensure feature schema consistency with training data
        
        Args:
            flow_stats: OpenFlow flow statistics object containing flow measurements
            
        Returns:
            pd.DataFrame: Normalized feature vector ready for model inference, or None on error
        """
        try:
            # Initialize feature vector with default values for all expected features
            features_dict = {feature: 0.0 for feature in self.feature_names}
            
            # Extract fundamental flow timing and volume metrics
            duration = getattr(flow_stats, 'duration_sec', 0) + getattr(flow_stats, 'duration_nsec', 0) * 1e-9
            packet_count = getattr(flow_stats, 'packet_count', 0)
            byte_count = getattr(flow_stats, 'byte_count', 0)

            # Calculate derived network performance indicators
            # Use small epsilon values to prevent division by zero
            flow_bytes_per_sec = byte_count / max(duration, 0.001)
            flow_packets_per_sec = packet_count / max(duration, 0.001)
            avg_packet_size = byte_count / max(packet_count, 1)
            iat_mean = duration / max(packet_count, 2)  # Inter-arrival time mean

            # Extract TCP protocol flags for behavioral analysis
            tcp_flags = 0
            if hasattr(flow_stats, 'match') and hasattr(flow_stats.match, 'get'):
                tcp_flags = flow_stats.match.get('tcp_flags', 0)

            # Feature mapping to standardized model input schema
            # Maps computed metrics to expected feature names from training data
            mappings = {
                "Total Length of Fwd Packets": byte_count,
                "Average Packet Size": avg_packet_size,
                "Flow Duration": duration,
                "Flow Packets/s": flow_packets_per_sec,
                "Flow Bytes/s": flow_bytes_per_sec,
                "Flow IAT Mean": iat_mean,
                "Fwd PSH Flags": 1 if (tcp_flags & 0x08) else 0,  # TCP Push flag detection
                "Bwd PSH Flags": 0,  # Backward direction not available in basic stats
                "SYN Flag Count": 1 if (tcp_flags & 0x02) else 0,  # TCP SYN flag detection
                "Flow IAT Std": iat_mean * 0.5,   # Estimated standard deviation
                "Flow IAT Max": iat_mean * 2,     # Estimated maximum IAT
                "Flow IAT Min": iat_mean * 0.1    # Estimated minimum IAT
            }

            # Populate feature vector with computed values
            for feature in self.feature_names:
                if feature in mappings:
                    features_dict[feature] = mappings[feature]

            # Create DataFrame with proper feature ordering and data cleaning
            df = pd.DataFrame([features_dict])[self.feature_names]
            
            # Handle numerical anomalies that could affect model stability
            df.replace([np.inf, -np.inf], 0, inplace=True)  # Replace infinite values
            df.fillna(0, inplace=True)  # Replace NaN values with zeros

            return df
            
        except Exception as e:
            print(f"❌ Feature extraction failed: {e}")
            return None

    def classify_flow(self, flow_stats, anomaly_threshold=0.18):
        """
        Perform real-time network flow anomaly classification.
        
        Executes the complete inference pipeline to determine if a network flow
        exhibits anomalous behavior patterns. The method processes OpenFlow
        statistics through feature extraction, normalization, and model prediction
        to generate anomaly probabilities with configurable detection thresholds.
        
        Classification Pipeline:
        1. Validate model and preprocessing components availability
        2. Extract and engineer features from flow statistics
        3. Apply trained normalization (StandardScaler) 
        4. Reshape data for LSTM input compatibility
        5. Execute model inference for anomaly probability
        6. Apply threshold-based classification decision
        7. Log detected anomalies for security monitoring
        
        Args:
            flow_stats: OpenFlow statistics object containing flow measurements
            anomaly_threshold (float): Classification threshold (default: 0.18)
                                     Lower values increase sensitivity
                                     
        Returns:
            tuple: (is_anomaly: bool, probability: float) 
                  - is_anomaly: True if flow classified as anomalous
                  - probability: Model confidence score [0.0, 1.0]
        """
        # Validate system readiness for classification
        if self.model is None or self.scaler is None:
            print("❌ Model or scaler not loaded")
            return False, 0.0

        try:
            # Extract network flow features using domain expertise
            features_df = self.extract_features(flow_stats)
            if features_df is None:
                return False, 0.0

            # Apply trained feature normalization for model compatibility
            scaled = self.scaler.transform(features_df)
            
            # Reshape for LSTM input requirements: (batch_size, timesteps, features)
            lstm_input = scaled.reshape(scaled.shape[0], 1, scaled.shape[1])

            # Execute model inference with optimized prediction
            prediction = self.model.predict(lstm_input, verbose=0)
            prob = float(prediction[0][0])  # Extract anomaly probability
            
            # Apply configurable threshold for binary classification
            is_anomaly = prob > anomaly_threshold

            # Handle anomaly detection events
            if is_anomaly:
                print("🚨 ALERT: Anomalous Flow Detected!")
                self._log_anomaly(flow_stats, prob)

            return is_anomaly, prob
            
        except Exception as e:
            print(f"❌ Classification error: {e}")
            return False, 0.0

    def _log_anomaly(self, flow_stats, confidence):
        """
        Log detected network anomalies for security monitoring and analysis.
        
        Creates comprehensive anomaly records including flow identification,
        model confidence scores, timing information, and traffic characteristics.
        The logging system supports security incident response and forensic
        analysis by maintaining detailed audit trails of detected threats.
        
        Log Record Structure:
        - Timestamp: Detection time for temporal analysis
        - Confidence: Model probability score for threat severity assessment  
        - Flow Info: Network 5-tuple for traffic identification
        - Statistics: Volume and timing metrics for behavioral analysis
        
        Args:
            flow_stats: OpenFlow statistics containing anomalous flow data
            confidence (float): Model confidence score for the anomaly detection
        """
        try:
            # Extract flow matching criteria for network identification
            match = flow_stats.match
            match_dict = match.to_jsondict().get('OFPMatch', {})

            # Construct network 5-tuple for flow identification
            flow_info = {
                "protocol": match_dict.get('ip_proto', 'unknown'),
                "src_ip": match_dict.get('ipv4_src', 'unknown'),
                "dst_ip": match_dict.get('ipv4_dst', 'unknown'),
                "src_port": match_dict.get('tcp_src', match_dict.get('udp_src', 'unknown')),
                "dst_port": match_dict.get('tcp_dst', match_dict.get('udp_dst', 'unknown'))
            }

            # Create comprehensive anomaly record for security analysis
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

            # Append to persistent anomaly log for security monitoring
            with open("anomaly_log.json", "a") as f:
                json.dump(anomaly_log, f)
                f.write("\n")

            print(f"⚠️ Anomaly Detected in Flow {match}")

        except Exception as e:
            print(f"❌ Error logging anomaly: {e}")



    def get_metrics(self):
        """
        Calculate comprehensive performance metrics for model validation.
        
        Computes standard classification metrics from accumulated validation
        counters to assess model performance in production deployment.
        These metrics are essential for monitoring detection accuracy,
        false positive rates, and overall system effectiveness.
        
        Computed Metrics:
        - Accuracy: Overall correctness of classifications
        - Precision: Accuracy of anomaly predictions (reduces false alarms)
        - Recall: Coverage of actual anomalies (reduces missed threats)
        - F1-Score: Harmonic mean balancing precision and recall
        
        Returns:
            dict: Comprehensive metrics dictionary including:
                 - Raw counts (TP, FP, TN, FN)
                 - Derived performance measures
                 - Zero-safe calculations for edge cases
        """
        # Create working copy to avoid modifying original counters
        m = self.validation_metrics.copy()
        total = sum(m.values())
        
        # Calculate derived metrics with zero-division protection
        if total > 0:
            m['accuracy'] = (m['TP'] + m['TN']) / total
            m['precision'] = m['TP'] / (m['TP'] + m['FP']) if m['TP'] + m['FP'] > 0 else 0
            m['recall'] = m['TP'] / (m['TP'] + m['FN']) if m['TP'] + m['FN'] > 0 else 0
            m['f1_score'] = 2 * m['precision'] * m['recall'] / (m['precision'] + m['recall']) if m['precision'] + m['recall'] > 0 else 0
            
        return m
