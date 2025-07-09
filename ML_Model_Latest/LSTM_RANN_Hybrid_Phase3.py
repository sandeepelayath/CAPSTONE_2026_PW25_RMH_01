# # Network Traffic Anomaly Detection with RaNN+LSTM

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

# %%
class RandomizedNeuralNetwork(tf.keras.layers.Layer):
    def __init__(self, hidden_layers_sizes=[256, 128], activation='relu', **kwargs):
        super(RandomizedNeuralNetwork, self).__init__(**kwargs)
        self.hidden_layers_sizes = hidden_layers_sizes
        self.activation = activation
        self.random_layers = []
        
    def build(self, input_shape):
        # Get the feature dimension (last dimension)
        input_dim = input_shape[-1]
        
        # Create random hidden layers
        for units in self.hidden_layers_sizes:
            # Create fixed random weights
            w_init = np.random.normal(0, 1/np.sqrt(input_dim), (input_dim, units))
            b_init = np.random.normal(0, 1/np.sqrt(input_dim), (units,))
            
            # Convert to non-trainable tensorflow variables
            w = tf.Variable(w_init, trainable=False, dtype=tf.float32)
            b = tf.Variable(b_init, trainable=False, dtype=tf.float32)
            
            self.random_layers.append((w, b))
            input_dim = units

    def call(self, inputs):
        # Reshape input to 2D if it's 3D (batch_size, timesteps, features)
        if len(inputs.shape) == 3:
            batch_size, timesteps, features = tf.shape(inputs)[0], tf.shape(inputs)[1], tf.shape(inputs)[2]
            x = tf.reshape(inputs, [-1, features])
        else:
            x = inputs

        # Pass through each random layer
        for w, b in self.random_layers:
            x = tf.matmul(x, w) + b
            if self.activation == 'relu':
                x = tf.nn.relu(x)
            elif self.activation == 'tanh':
                x = tf.nn.tanh(x)

        # Reshape back to 3D if input was 3D
        if len(inputs.shape) == 3:
            x = tf.reshape(x, [batch_size, timesteps, self.hidden_layers_sizes[-1]])
        
        return x

def build_hybrid_rnn_lstm_model(input_shape, rnn_sizes=[256, 128], lstm_sizes=[128, 64]):
    """
    Build a hybrid model that combines RNN and LSTM with matching dimensions
    """
    # Input layer
    inputs = Input(shape=input_shape)
    
    # RNN path
    rnn = RandomizedNeuralNetwork(hidden_layers_sizes=rnn_sizes)(inputs)
    rnn = Dropout(0.3)(rnn)
    # Add a final LSTM to match dimensions with LSTM path
    rnn = LSTM(lstm_sizes[-1])(rnn)
    rnn = Dropout(0.3)(rnn)
    
    # LSTM path
    lstm = LSTM(lstm_sizes[0], return_sequences=True)(inputs)
    lstm = Dropout(0.3)(lstm)
    lstm = LSTM(lstm_sizes[1])(lstm)
    lstm = Dropout(0.3)(lstm)
    
    # Now both rnn and lstm have shape (batch_size, lstm_sizes[-1])
    combined = Concatenate()([rnn, lstm])
    
    # Final dense layers
    x = Dense(64, activation='relu')(combined)
    x = Dropout(0.3)(x)
    outputs = Dense(1, activation='sigmoid')(x)
    
    # Create model
    model = Model(inputs=inputs, outputs=outputs)
    
    # Compile
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    
    return model

def build_hybrid_rnn_lstm_model_tuner(hp, input_features):
    """
    Build a hybrid model with hyperparameter tuning using keras_tuner.
    """
    # Input layer
    input_shape = (1, input_features)  # Use the actual number of features
    inputs = Input(shape=input_shape)
    
    # RNN path
    rnn_sizes = [hp.Int(f'rnn_size_{i}', min_value=64, max_value=512, step=64) for i in range(2)]
    rnn = RandomizedNeuralNetwork(hidden_layers_sizes=rnn_sizes)(inputs)
    rnn = Dropout(hp.Float('rnn_dropout', min_value=0.1, max_value=0.5, step=0.1))(rnn)
    rnn = LSTM(hp.Int('rnn_lstm_size', min_value=64, max_value=256, step=64))(rnn)
    rnn = Dropout(hp.Float('rnn_lstm_dropout', min_value=0.1, max_value=0.5, step=0.1))(rnn)
    
    # LSTM path
    lstm_sizes = [hp.Int(f'lstm_size_{i}', min_value=64, max_value=256, step=64) for i in range(2)]
    lstm = LSTM(lstm_sizes[0], return_sequences=True)(inputs)
    lstm = Dropout(hp.Float('lstm_dropout_1', min_value=0.1, max_value=0.5, step=0.1))(lstm)
    lstm = LSTM(lstm_sizes[1])(lstm)
    lstm = Dropout(hp.Float('lstm_dropout_2', min_value=0.1, max_value=0.5, step=0.1))(lstm)
    
    # Combine paths
    combined = Concatenate()([rnn, lstm])
    
    # Final dense layers
    x = Dense(hp.Int('dense_units', min_value=32, max_value=128, step=32), activation='relu')(combined)
    x = Dropout(hp.Float('dense_dropout', min_value=0.1, max_value=0.5, step=0.1))(x)
    outputs = Dense(1, activation='sigmoid')(x)
    
    # Create model
    model = Model(inputs=inputs, outputs=outputs)
    
    # Compile
    model.compile(
        optimizer=tf.keras.optimizers.Adam(
            learning_rate=hp.Float('learning_rate', min_value=1e-4, max_value=1e-2, sampling='log')
        ),
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    
    return model

# %%
def main():
    print("Current working directory:", os.getcwd())

    # Data loading and preprocessing (keeping your existing code)
    print("Loading and preprocessing data...")
    data_dir = './data'
    all_files = glob.glob(os.path.join(data_dir, '*.pcap_ISCX.csv'))
    
    if not all_files:
        print("Checking subdirectories...")
        all_files = glob.glob(os.path.join(data_dir, '**/*.pcap_ISCX'), recursive=True)
    
    print(f"Found {len(all_files)} files")
    
    # Load and process files (same as your code)
    dfs = []
    files_to_process = all_files[:2]
    
    for file in files_to_process:
        print(f"Processing {file}...")
        try:
            df = pd.read_csv(file)
            df = df.dropna()
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            if len(numeric_cols) > 0:
                df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
                df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].max() * 1000)
            dfs.append(df)
        except Exception as e:
            print(f"Error processing {file}: {e}")
    
    if not dfs:
        print("No data was loaded. Please check your files.")
        return
    
    full_df = pd.concat(dfs, ignore_index=True)
    
    # Prepare features and labels (same as your code)
    if 'Label' in full_df.columns:
        full_df.rename(columns={'Label': 'label'}, inplace=True)
    elif 'label' not in full_df.columns and ' Label' in full_df.columns:
        full_df.rename(columns={' Label': 'label'}, inplace=True)
    
    label_col = full_df.pop('label')
    full_df['label'] = label_col
    full_df['label'] = full_df['label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    
    numeric_cols = full_df.select_dtypes(include=[np.number]).columns.tolist()
    numeric_cols.remove('label')
    
    X = full_df[numeric_cols]
    y = full_df['label']
    
    # Split and scale data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    X_train, X_val, y_train, y_val = train_test_split(X_train, y_train, test_size=0.2, random_state=42, stratify=y_train)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)
    
    # Reshape data for LSTM
    X_train_reshaped = X_train_scaled.reshape(X_train_scaled.shape[0], 1, X_train_scaled.shape[1])
    X_val_reshaped = X_val_scaled.reshape(X_val_scaled.shape[0], 1, X_val_scaled.shape[1])
    X_test_reshaped = X_test_scaled.reshape(X_test_scaled.shape[0], 1, X_test_scaled.shape[1])
    
    input_features = X_train_reshaped.shape[2]  # Get the actual number of features
    print(f"Input features: {input_features}")  # Debugging log
    
    # Hyperparameter tuning
    print("Starting hyperparameter tuning...")
    tuner = kt.Hyperband(
        lambda hp: build_hybrid_rnn_lstm_model_tuner(hp, input_features),
        objective='val_accuracy',
        max_epochs=10,
        factor=3,
        directory='hyperparameter_tuning',
        project_name='rnn_lstm_hybrid'
    )
    
    early_stopping = tf.keras.callbacks.EarlyStopping(
        monitor='val_loss',
        patience=3,
        restore_best_weights=True
    )
    
    tuner.search(
        X_train_reshaped, y_train,
        epochs=10,
        validation_data=(X_val_reshaped, y_val),
        callbacks=[early_stopping]
    )
    
    # Get the best model
    best_hps = tuner.get_best_hyperparameters(num_trials=1)[0]
    print("Best hyperparameters:")
    print(best_hps.values)
    
    model = tuner.hypermodel.build(best_hps)
    model.summary()
    
    # Train the best model
    history = model.fit(
        X_train_reshaped, y_train,
        epochs=10,
        batch_size=64,
        validation_data=(X_val_reshaped, y_val),
        callbacks=[early_stopping]
    )
    
    # Evaluation and plotting (same as your code)
    print("Evaluating model...")
    y_pred_prob = model.predict(X_test_reshaped)
    y_pred = (y_pred_prob > 0.5).astype(int).reshape(-1)
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Training plots
    plt.figure(figsize=(12, 4))
    
    plt.subplot(1, 2, 1)
    plt.plot(history.history['loss'], label='Training Loss')
    plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.legend()
    plt.title('Training and Validation Loss')
    
    plt.subplot(1, 2, 2)
    plt.plot(history.history['accuracy'], label='Training Accuracy')
    plt.plot(history.history['val_accuracy'], label='Validation Accuracy')
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy')
    plt.legend()
    plt.title('Training and Validation Accuracy')
    
    plt.tight_layout()
    plt.show()
    
    # Confusion Matrix
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


