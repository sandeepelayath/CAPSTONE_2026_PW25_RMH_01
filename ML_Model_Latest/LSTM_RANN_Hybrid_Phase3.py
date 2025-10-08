"""
Network Traffic Anomaly Detection using Hybrid RaNN+LSTM Architecture

This module implements a hybrid neural network combining Randomized Neural Networks (RaNN) 
and Long Short-Term Memory (LSTM) networks for detecting anomalous network traffic patterns.
The system includes hyperparameter tuning capabilities using Keras Tuner.

Key Features:
- Randomized Neural Network layer with fixed random weights for feature extraction
- LSTM layers for temporal pattern recognition
- Hyperparameter optimization using Hyperband algorithm
- Comprehensive evaluation with visualization

Author: Network Security Team
Version: 1.0
Date: 2025
"""

import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Dense, LSTM, Dropout, Input, Concatenate
import glob
import keras_tuner as kt

class RandomizedNeuralNetwork(tf.keras.layers.Layer):
    """
    Randomized Neural Network (RaNN) Layer Implementation
    
    This custom Keras layer implements a Randomized Neural Network where weights are 
    randomly initialized and kept fixed (non-trainable) throughout training. This 
    approach provides computational efficiency while maintaining feature extraction 
    capabilities through random projections.
    
    The RaNN layer serves as a feature transformation component that maps input 
    features to a higher-dimensional space using fixed random weights, following 
    the principles of reservoir computing and extreme learning machines.
    
    Attributes:
        hidden_layers_sizes (list): Sizes of hidden layers in the randomized network
        activation (str): Activation function ('relu' or 'tanh')
        random_layers (list): List of (weight, bias) tuples for each layer
    """
    
    def __init__(self, hidden_layers_sizes=[256, 128], activation='relu', **kwargs):
        """
        Initialize the Randomized Neural Network layer.
        
        Args:
            hidden_layers_sizes (list): Number of units in each hidden layer
            activation (str): Activation function to use ('relu' or 'tanh')
            **kwargs: Additional keyword arguments for the base Layer class
        """
        super(RandomizedNeuralNetwork, self).__init__(**kwargs)
        self.hidden_layers_sizes = hidden_layers_sizes
        self.activation = activation
        self.random_layers = []
        
    def build(self, input_shape):
        """
        Build the layer by creating random weight matrices and bias vectors.
        
        This method creates fixed random weights using Xavier/He initialization 
        principles. The weights are marked as non-trainable to maintain the 
        randomized nature of the network.
        
        Args:
            input_shape (tuple): Shape of the input tensor
        """
        input_dim = input_shape[-1]
        
        for units in self.hidden_layers_sizes:
            # Initialize weights using scaled normal distribution for stability
            w_init = np.random.normal(0, 1/np.sqrt(input_dim), (input_dim, units))
            b_init = np.random.normal(0, 1/np.sqrt(input_dim), (units,))
            
            # Create non-trainable TensorFlow variables for fixed random weights
            w = tf.Variable(w_init, trainable=False, dtype=tf.float32)
            b = tf.Variable(b_init, trainable=False, dtype=tf.float32)
            
            self.random_layers.append((w, b))
            input_dim = units

    def call(self, inputs):
        """
        Forward pass through the randomized neural network.
        
        Processes input through each random layer, applying linear transformation 
        followed by activation function. Handles both 2D and 3D input tensors 
        for compatibility with LSTM layers.
        
        Args:
            inputs (tf.Tensor): Input tensor of shape (batch_size, features) or 
                               (batch_size, timesteps, features)
        
        Returns:
            tf.Tensor: Transformed features with same batch dimension as input
        """
        # Handle 3D input tensors (batch_size, timesteps, features) by reshaping
        if len(inputs.shape) == 3:
            batch_size, timesteps, features = tf.shape(inputs)[0], tf.shape(inputs)[1], tf.shape(inputs)[2]
            x = tf.reshape(inputs, [-1, features])
        else:
            x = inputs

        # Forward propagation through random layers
        for w, b in self.random_layers:
            x = tf.matmul(x, w) + b
            if self.activation == 'relu':
                x = tf.nn.relu(x)
            elif self.activation == 'tanh':
                x = tf.nn.tanh(x)

        # Restore original tensor structure for 3D inputs
        if len(inputs.shape) == 3:
            x = tf.reshape(x, [batch_size, timesteps, self.hidden_layers_sizes[-1]])
        
        return x

def build_hybrid_rnn_lstm_model(input_shape, rnn_sizes=[256, 128], lstm_sizes=[128, 64]):
    """
    Construct a hybrid neural network combining Randomized Neural Network and LSTM layers.
    
    This function creates a dual-path architecture where:
    1. RaNN Path: Applies fixed random feature transformations followed by LSTM processing
    2. LSTM Path: Direct sequential processing of input features
    3. Fusion Layer: Concatenates outputs from both paths for final classification
    
    The hybrid approach leverages the computational efficiency of randomized networks 
    while maintaining the temporal modeling capabilities of LSTMs for network traffic 
    anomaly detection.
    
    Args:
        input_shape (tuple): Shape of input data (timesteps, features)
        rnn_sizes (list): Layer sizes for the randomized neural network path
        lstm_sizes (list): Layer sizes for the LSTM path
    
    Returns:
        tf.keras.Model: Compiled hybrid model ready for training
    """
    inputs = Input(shape=input_shape)
    
    # Randomized Neural Network Processing Path
    # Applies fixed random transformations to extract diverse feature representations
    rnn = RandomizedNeuralNetwork(hidden_layers_sizes=rnn_sizes)(inputs)
    rnn = Dropout(0.3)(rnn)  # Regularization to prevent overfitting
    rnn = LSTM(lstm_sizes[-1])(rnn)  # Temporal sequence processing
    rnn = Dropout(0.3)(rnn)
    
    # Long Short-Term Memory Processing Path  
    # Direct sequential processing for temporal pattern recognition
    lstm = LSTM(lstm_sizes[0], return_sequences=True)(inputs)
    lstm = Dropout(0.3)(lstm)
    lstm = LSTM(lstm_sizes[1])(lstm)  # Final LSTM layer for sequence summarization
    lstm = Dropout(0.3)(lstm)
    
    # Feature Fusion Layer
    # Combines representations from both processing paths
    combined = Concatenate()([rnn, lstm])
    
    # Classification Head
    # Dense layers for final binary classification (normal vs. anomalous traffic)
    x = Dense(64, activation='relu')(combined)
    x = Dropout(0.3)(x)
    outputs = Dense(1, activation='sigmoid')(x)  # Binary classification output
    
    # Model Assembly and Compilation
    model = Model(inputs=inputs, outputs=outputs)
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss='binary_crossentropy',  # Suitable for binary classification
        metrics=['accuracy']
    )
    
    return model

def build_hybrid_rnn_lstm_model_tuner(hp, input_features):
    """
    Build a hybrid model with automated hyperparameter optimization using Keras Tuner.
    
    This function creates a tunable version of the hybrid RaNN+LSTM model where 
    architecture parameters are automatically optimized using the Hyperband algorithm.
    The tuner explores different combinations of layer sizes, dropout rates, and 
    learning rates to find the optimal configuration.
    
    Hyperparameter Search Spaces:
    - RaNN layer sizes: 64-512 units (step=64)
    - LSTM layer sizes: 64-256 units (step=64)  
    - Dropout rates: 0.1-0.5 (step=0.1)
    - Dense layer units: 32-128 (step=32)
    - Learning rate: 1e-4 to 1e-2 (log scale)
    
    Args:
        hp (keras_tuner.HyperParameters): Hyperparameter object for optimization
        input_features (int): Number of input features in the dataset
    
    Returns:
        tf.keras.Model: Compiled model with tunable hyperparameters
    """
    input_shape = (1, input_features)
    inputs = Input(shape=input_shape)
    
    # Randomized Neural Network Path with Tunable Architecture
    rnn_sizes = [hp.Int(f'rnn_size_{i}', min_value=64, max_value=512, step=64) for i in range(2)]
    rnn = RandomizedNeuralNetwork(hidden_layers_sizes=rnn_sizes)(inputs)
    rnn = Dropout(hp.Float('rnn_dropout', min_value=0.1, max_value=0.5, step=0.1))(rnn)
    rnn = LSTM(hp.Int('rnn_lstm_size', min_value=64, max_value=256, step=64))(rnn)
    rnn = Dropout(hp.Float('rnn_lstm_dropout', min_value=0.1, max_value=0.5, step=0.1))(rnn)
    
    # LSTM Path with Tunable Architecture
    lstm_sizes = [hp.Int(f'lstm_size_{i}', min_value=64, max_value=256, step=64) for i in range(2)]
    lstm = LSTM(lstm_sizes[0], return_sequences=True)(inputs)
    lstm = Dropout(hp.Float('lstm_dropout_1', min_value=0.1, max_value=0.5, step=0.1))(lstm)
    lstm = LSTM(lstm_sizes[1])(lstm)
    lstm = Dropout(hp.Float('lstm_dropout_2', min_value=0.1, max_value=0.5, step=0.1))(lstm)
    
    # Feature Fusion and Classification Head
    combined = Concatenate()([rnn, lstm])
    x = Dense(hp.Int('dense_units', min_value=32, max_value=128, step=32), activation='relu')(combined)
    x = Dropout(hp.Float('dense_dropout', min_value=0.1, max_value=0.5, step=0.1))(x)
    outputs = Dense(1, activation='sigmoid')(x)
    
    # Model Compilation with Tunable Learning Rate
    model = Model(inputs=inputs, outputs=outputs)
    model.compile(
        optimizer=tf.keras.optimizers.Adam(
            learning_rate=hp.Float('learning_rate', min_value=1e-4, max_value=1e-2, sampling='log')
        ),
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    
    return model

def main():
    """
    Main execution function for network traffic anomaly detection model training.
    
    This function orchestrates the complete machine learning pipeline including:
    1. Data loading and preprocessing from CICIDS2017 dataset
    2. Feature engineering and data normalization  
    3. Hyperparameter optimization using Keras Tuner
    4. Model training with optimal parameters
    5. Performance evaluation and visualization
    
    The pipeline is designed to handle network traffic data in PCAP_ISCX CSV format
    and performs binary classification to distinguish between benign and malicious traffic.
    """
    print("Current working directory:", os.getcwd())

    # ==================== DATA LOADING AND PREPROCESSING ====================
    print("Loading and preprocessing data...")
    
    # Locate CICIDS2017 dataset files
    data_dir = './data'
    all_files = glob.glob(os.path.join(data_dir, '*.pcap_ISCX.csv'))
    
    # Fallback: Search in subdirectories if no files found in main directory
    if not all_files:
        print("Checking subdirectories...")
        all_files = glob.glob(os.path.join(data_dir, '**/*.pcap_ISCX'), recursive=True)
    
    print(f"Found {len(all_files)} files")
    
    # Load and consolidate multiple data files
    dfs = []
    files_to_process = all_files[:2]  # Process first 2 files for computational efficiency
    
    for file in files_to_process:
        print(f"Processing {file}...")
        try:
            df = pd.read_csv(file)
            df = df.dropna()  # Remove rows with missing values
            
            # Handle infinite values in numeric columns
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            if len(numeric_cols) > 0:
                df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
                # Replace NaN with large finite values to preserve data distribution
                df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].max() * 1000)
            dfs.append(df)
        except Exception as e:
            print(f"Error processing {file}: {e}")
    
    if not dfs:
        print("No data was loaded. Please check your files.")
        return
    
    # Consolidate all loaded dataframes
    full_df = pd.concat(dfs, ignore_index=True)
    
    # ==================== FEATURE ENGINEERING ====================
    
    # Standardize label column naming across different dataset versions
    if 'Label' in full_df.columns:
        full_df.rename(columns={'Label': 'label'}, inplace=True)
    elif 'label' not in full_df.columns and ' Label' in full_df.columns:
        full_df.rename(columns={' Label': 'label'}, inplace=True)
    
    # Move label column to the end for consistent processing
    label_col = full_df.pop('label')
    full_df['label'] = label_col
    
    # Binary label encoding: 0 for benign traffic, 1 for attack traffic
    full_df['label'] = full_df['label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    
    # Separate features and labels
    numeric_cols = full_df.select_dtypes(include=[np.number]).columns.tolist()
    numeric_cols.remove('label')  # Exclude target variable from features
    
    X = full_df[numeric_cols]  # Feature matrix
    y = full_df['label']       # Target labels
    
    # ==================== DATA SPLITTING AND NORMALIZATION ====================
    
    # Stratified train-test split to maintain class distribution
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    X_train, X_val, y_train, y_val = train_test_split(X_train, y_train, test_size=0.2, random_state=42, stratify=y_train)
    
    # Feature scaling using StandardScaler for neural network optimization
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)
    
    # Reshape data for LSTM compatibility (samples, timesteps, features)
    # Using timesteps=1 since we're treating each sample as a single time step
    X_train_reshaped = X_train_scaled.reshape(X_train_scaled.shape[0], 1, X_train_scaled.shape[1])
    X_val_reshaped = X_val_scaled.reshape(X_val_scaled.shape[0], 1, X_val_scaled.shape[1])
    X_test_reshaped = X_test_scaled.reshape(X_test_scaled.shape[0], 1, X_test_scaled.shape[1])
    
    input_features = X_train_reshaped.shape[2]
    print(f"Input features: {input_features}")
    
    # ==================== HYPERPARAMETER OPTIMIZATION ====================
    
    print("Starting hyperparameter tuning...")
    
    # Configure Hyperband tuner for efficient hyperparameter search
    # Hyperband uses successive halving to allocate more resources to promising configurations
    tuner = kt.Hyperband(
        lambda hp: build_hybrid_rnn_lstm_model_tuner(hp, input_features),
        objective='val_accuracy',  # Optimization objective
        max_epochs=10,             # Maximum training epochs per trial
        factor=3,                  # Halving factor for successive halving
        directory='hyperparameter_tuning',
        project_name='rnn_lstm_hybrid'
    )
    
    # Early stopping callback to prevent overfitting and reduce training time
    early_stopping = tf.keras.callbacks.EarlyStopping(
        monitor='val_loss',      # Monitor validation loss for early stopping
        patience=3,              # Stop if no improvement for 3 epochs
        restore_best_weights=True # Restore weights from best epoch
    )
    
    # Execute hyperparameter search
    tuner.search(
        X_train_reshaped, y_train,
        epochs=10,
        validation_data=(X_val_reshaped, y_val),
        callbacks=[early_stopping]
    )
    
    # ==================== MODEL BUILDING WITH OPTIMAL HYPERPARAMETERS ====================
    
    # Retrieve and display the best hyperparameter configuration
    best_hps = tuner.get_best_hyperparameters(num_trials=1)[0]
    print("Best hyperparameters:")
    print(best_hps.values)
    
    # Build final model using optimal hyperparameters
    model = tuner.hypermodel.build(best_hps)
    model.summary()
    
    # ==================== MODEL TRAINING ====================
    
    # Train the optimized model using the best hyperparameters
    history = model.fit(
        X_train_reshaped, y_train,
        epochs=10,
        batch_size=64,
        validation_data=(X_val_reshaped, y_val),
        callbacks=[early_stopping]
    )
    
    # ==================== MODEL EVALUATION ====================
    
    print("Evaluating model...")
    
    # Generate predictions on test set
    y_pred_prob = model.predict(X_test_reshaped)  # Probability predictions
    y_pred = (y_pred_prob > 0.5).astype(int).reshape(-1)  # Binary predictions using 0.5 threshold
    
    # Display comprehensive classification metrics
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # ==================== PERFORMANCE VISUALIZATION ====================
    
    # Training History Visualization
    plt.figure(figsize=(12, 4))
    
    # Loss progression plot
    plt.subplot(1, 2, 1)
    plt.plot(history.history['loss'], label='Training Loss')
    plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.legend()
    plt.title('Training and Validation Loss')
    
    # Accuracy progression plot  
    plt.subplot(1, 2, 2)
    plt.plot(history.history['accuracy'], label='Training Accuracy')
    plt.plot(history.history['val_accuracy'], label='Validation Accuracy')
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy')
    plt.legend()
    plt.title('Training and Validation Accuracy')
    
    plt.tight_layout()
    plt.show()
    
    # Confusion Matrix Heatmap
    plt.figure(figsize=(8, 6))
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Normal', 'Attack'],
                yticklabels=['Normal', 'Attack'])
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix')
    plt.show()

if __name__ == "__main__":
    main()


