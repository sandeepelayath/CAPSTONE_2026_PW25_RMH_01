# %% [markdown]
# # Network Traffic Anomaly Detection with LSTM
# 

# %%

# %%
import os
import glob
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Dropout, Input
from sklearn.metrics import accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix
import pickle
from sklearn.metrics import accuracy_score, classification_report
from sklearn.metrics import precision_recall_curve
from sklearn.model_selection import ParameterSampler
from scipy.stats import randint, uniform
import gc
import psutil

#print("TensorFlow version:", tf.__version__)
#print("Built with GPU support:", tf.test.is_built_with_cuda())
#print("Available devices:", tf.config.list_physical_devices())

# %%
# Set random seed for reproducibility
np.random.seed(42)
tf.random.set_seed(42)

print("Loading CIC-IDS2017 data...")

# Function to load and preprocess CIC-IDS2017 data
def load_cicids_data(data_dir='./data'):
    all_files = glob.glob(os.path.join(data_dir, '*.pcap_ISCX.csv'))
    
    if len(all_files) == 0:
        print("No CIC-IDS2017 .pcap_ISCX files found.")
        return None

    files_to_process = all_files[:2]  # Prevent memory overload
    dfs = []

    for file in files_to_process:
        print(f"Processing {file}...")
        df = pd.read_csv(file)
        df = df.dropna()

        # Replace infinities with large values
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        for col in numeric_cols:
            max_val = df[col].max()
            df[col] = df[col].fillna(max_val * 1000 if not pd.isna(max_val) else 0)

        dfs.append(df)

    # Combine and standardize
    full_df = pd.concat(dfs, ignore_index=True)
    full_df.columns = full_df.columns.str.strip()  # Clean column names

    if 'Label' in full_df.columns:
        full_df.rename(columns={'Label': 'label'}, inplace=True)
    elif ' Label' in full_df.columns:
        full_df.rename(columns={' Label': 'label'}, inplace=True)

    full_df['label'] = full_df['label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

    return full_df

# Load dataset
cicids_df = load_cicids_data()

# Selected features
common_features = [
    'Total Length of Fwd Packets', 'Average Packet Size', 'Flow Duration', 
    'Flow Packets/s', 'Flow Bytes/s', 'Fwd PSH Flags', 'Bwd PSH Flags', 
    'SYN Flag Count', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'label'
]
print(f"Updated common features: {common_features}")

# Strip columns again just to be sure
cicids_df.columns = cicids_df.columns.str.strip()

# Subset and clean
combined_df = cicids_df[common_features]
combined_df = combined_df.fillna(0)

# Extract features & labels
X = combined_df.drop(columns=['label'])
y = combined_df['label']
print(f"Final dataset shape: {X.shape}")

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Save the scaler
with open("scaler_combined.pkl", "wb") as f:
    pickle.dump(scaler, f)

# --- NEW: Convert to sequences for LSTM ---
sequence_length = 5  # Reduced from 10 to 5

X_seq = []
y_seq = []

for i in range(len(X_scaled) - sequence_length):
    X_seq.append(X_scaled[i:i + sequence_length])
    y_seq.append(y.iloc[i + sequence_length])  # Use the label *after* the sequence

X_seq = np.array(X_seq)
y_seq = np.array(y_seq)

print(f"Sequence shape: {X_seq.shape}, Labels: {y_seq.shape}")

# Split sequence data
X_train_seq, X_test_seq, y_train_seq, y_test_seq = train_test_split(
    X_seq, y_seq, test_size=0.2, random_state=42, stratify=y_seq
)
X_train_seq, X_val_seq, y_train_seq, y_val_seq = train_test_split(
    X_train_seq, y_train_seq, test_size=0.2, random_state=42, stratify=y_train_seq
)

# Reduce dataset size for faster experimentation
X_train_seq, _, y_train_seq, _ = train_test_split(
    X_train_seq, y_train_seq, test_size=0.5, random_state=42
)

# Final dataset shapes for model
print("Train shape:", X_train_seq.shape)
print("Val shape:", X_val_seq.shape)
print("Test shape:", X_test_seq.shape)


# %%
# Define the hyperparameter search space
param_distributions = {
    'lstm_units_1': randint(32, 64),  # Reduce range for first LSTM layer
    'lstm_units_2': randint(16, 32),  # Reduce range for second LSTM layer
    'dropout_rate': uniform(0.1, 0.4),  # Keep dropout range
    'batch_size': randint(4, 8),  # Reduce batch size range
    'learning_rate': uniform(0.0001, 0.005)  # Keep learning rate range
}

# Enable mixed precision training using the updated API
from tensorflow.keras.mixed_precision import set_global_policy
set_global_policy('mixed_float16')
print("✅ Enabled mixed precision training.")

# Function to build and compile the model
def build_model(lstm_units_1, lstm_units_2, dropout_rate, learning_rate):
    model = Sequential([
        Input(shape=(X_train_seq.shape[1], X_train_seq.shape[2])),  # Use Input layer
        LSTM(lstm_units_1, activation='relu', return_sequences=True),
        Dropout(dropout_rate),
        LSTM(lstm_units_2, activation='relu'),
        Dropout(dropout_rate),
        Dense(32, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    optimizer = tf.keras.optimizers.Adam(learning_rate=learning_rate)
    model.compile(optimizer=optimizer, loss='binary_crossentropy', metrics=['accuracy'])
    return model

# Monitor memory usage during training
def log_memory_usage():
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    print(f"Memory usage: {memory_info.rss / (1024 ** 2):.2f} MB")

# Random Search
n_iter = 10  # NUmber of iteraionsfor random search
random_search = ParameterSampler(param_distributions, n_iter=n_iter, random_state=42)

best_params = None
best_val_accuracy = 0

for params in random_search:
    print(f"Testing combination: {params}")
    
    # Extract batch_size and remove it from params before passing to build_model
    batch_size = params.pop('batch_size')
    model = build_model(**params)
    
    # Train the model
    print("Starting model training...")

    history = model.fit(
        X_train_seq, y_train_seq,
        epochs=10,
        batch_size=batch_size,  # Use the extracted batch_size here
        validation_data=(X_val_seq, y_val_seq),
        verbose=1  # Suppress detailed output
    )
    
    # Evaluate on validation set
    val_accuracy = max(history.history['val_accuracy'])
    print(f"Validation accuracy: {val_accuracy:.4f}")
    
    # Update best parameters if current combination is better
    if val_accuracy > best_val_accuracy:
        best_val_accuracy = val_accuracy
        best_params = params
        best_params['batch_size'] = batch_size  # Add batch_size back to best_params

print(f"Best parameters: {best_params}")
print(f"Best validation accuracy: {best_val_accuracy:.4f}")


# %%
print("Training Data Class Distribution:")
print(pd.Series(y_train_seq).value_counts())  # Count of normal (0) and attack (1) samples



# %%
print("Training the model...")

early_stopping = tf.keras.callbacks.EarlyStopping(
    monitor='val_loss', patience=3, restore_best_weights=True
)

# Custom callback to print progress after each epoch
class ProgressCallback(tf.keras.callbacks.Callback):
    def on_epoch_end(self, epoch, logs=None):
        print(f"Epoch {epoch + 1} completed. Loss: {logs['loss']:.4f}, Accuracy: {logs['accuracy']:.4f}, Val Loss: {logs['val_loss']:.4f}, Val Accuracy: {logs['val_accuracy']:.4f}")

# Custom callback to print progress after each batch
class BatchProgressCallback(tf.keras.callbacks.Callback):
    def on_train_batch_end(self, batch, logs=None):
        print(f"Batch {batch + 1} completed. Loss: {logs['loss']:.4f}, Accuracy: {logs['accuracy']:.4f}")

# Use the best parameters from random search
# Extract batch_size from best_params and remove it before passing to build_model
batch_size = best_params.pop('batch_size')  # Remove batch_size from best_params
model = build_model(**best_params)  # Pass only the relevant parameters to build_model

# Enforce CPU-only execution
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"  # Disable GPU
os.environ["TF_XLA_FLAGS"] = "--tf_xla_enable_xla_devices=0"  # Disable XLA compilation
print("⚠️ Enforcing CPU-only execution. GPU is disabled.")

# Verify TensorFlow device configuration
physical_devices = tf.config.list_physical_devices()
print(f"Available devices: {physical_devices}")
if not any(device.device_type == 'GPU' for device in physical_devices):
    print("✅ Confirmed: Running on CPU.")
else:
    print("⚠️ Warning: GPU devices are still detected.")

# Use TensorFlow's tf.data API for efficient data loading
def create_tf_dataset(X, y, batch_size):
    dataset = tf.data.Dataset.from_tensor_slices((X, y))
    dataset = dataset.shuffle(buffer_size=10000).batch(batch_size).prefetch(tf.data.AUTOTUNE)
    return dataset

# Replace direct usage of NumPy arrays with tf.data datasets
train_dataset = create_tf_dataset(X_train_seq, y_train_seq, batch_size)
val_dataset = create_tf_dataset(X_val_seq, y_val_seq, batch_size)
test_dataset = create_tf_dataset(X_test_seq, y_test_seq, batch_size)

# Log memory usage before training
log_memory_usage()

# Update model training to include batch-level progress tracking
history = model.fit(
    train_dataset,
    epochs=10,
    validation_data=val_dataset,
    callbacks=[early_stopping, ProgressCallback(), BatchProgressCallback()],  # Add batch-level callback
    verbose=1  # Show progress during training
)

# Log memory usage after training
log_memory_usage()

# Clear unused variables to free memory
def clear_memory():
    gc.collect()
    tf.keras.backend.clear_session()
    print("✅ Cleared unused variables and freed memory.")

clear_memory()  # Free memory after training


# %%
# Save the model
model.save("../ml_model/lstm_model_combined.keras")  # Preferred format

# Evaluate on test set
print("Evaluating on test set...")
y_pred_prob = model.predict(test_dataset)

precision, recall, thresholds = precision_recall_curve(y_val_seq, model.predict(val_dataset))
optimal_idx = np.argmax(2 * (precision * recall) / (precision + recall + 1e-9))  # F1
best_threshold = thresholds[optimal_idx]
print("Best threshold based on F1:", best_threshold)

y_pred = (y_pred_prob > best_threshold).astype(int).reshape(-1)
y_test_seq = np.array(y_test_seq).reshape(-1)  # Make sure y_test is also flat
accuracy = accuracy_score(y_test_seq, y_pred)
print(f"Test accuracy: {accuracy:.4f}")

# Save feature names
with open("feature_names_combined.pkl", "wb") as f:
    pickle.dump(X.columns.tolist(), f)

print("Model and scaler saved successfully! 🚀")


# %%
# Make sure lengths match
min_len = min(len(y_test_seq), len(y_pred))
y_test_seq = y_test_seq[:min_len]
y_pred = y_pred[:min_len]

# Plot confusion matrix
plt.figure(figsize=(8, 6))
cm = confusion_matrix(y_test_seq, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=['Normal', 'Attack'], 
            yticklabels=['Normal', 'Attack'])
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.show()


# %%
# 11. Save the model and related artifacts
model.save('../ml_model/lstm_model_combined.keras')
print("✅ Model saved as 'lstm_model_combined.keras'")

with open('../ml_model/scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)

with open('../ml_model/feature_names.pkl', 'wb') as f:
    pickle.dump(X.columns.tolist(), f)

# 12. Test on new data (simulated here with a sample from test set)
print("\n🧪 Testing on sample data...")

# Take a small sample from test set to simulate new data
sample_size = 100
sample_indices = np.random.choice(X_test_seq.shape[0], sample_size, replace=False)
X_sample_seq = X_test_seq[sample_indices]
y_sample = y_test_seq[sample_indices]  # ✅ Fixed: use numpy-style indexing

# Predict
y_sample_pred_prob = model.predict(X_sample_seq)
y_sample_pred = (y_sample_pred_prob > best_threshold).astype(int).reshape(-1)

print(f"Sample test accuracy: {accuracy_score(y_sample, y_sample_pred):.4f}")
print("\nSample Classification Report:")
unique_classes = np.unique(y_sample_pred)  # Get unique classes in predictions
if len(unique_classes) == 1:
    # Handle case where only one class is present in predictions
    print(f"Only one class ({unique_classes[0]}) present in predictions. Skipping detailed classification report.")
else:
    # Generate classification report with both classes
    print(classification_report(y_sample, y_sample_pred, target_names=["Normal", "Attack"]))

# 13. Test prediction for a known attack sample from validation set
attack_indices = np.where(y_val_seq == 1)[0]
if len(attack_indices) > 0:
    sample = X_val_seq[attack_indices[0]]
    pred = model.predict(sample[np.newaxis, :, :])
    print(f"Prediction for known attack (probability): {pred[0][0]:.4f}")
else:
    print("No attack samples found in validation set for demonstration.")


# %%
# 11. Save the model and supporting files
model.save('../ml_model/lstm_model_combined.keras') 
print("✅ Model saved as 'lstm_model_combined.keras'")

with open('../ml_model/scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)

with open('../ml_model/feature_names.pkl', 'wb') as f:
    pickle.dump(X.columns.tolist(), f)

# 12. Test on new data (simulated here with a sample from test set)
print("\n🧪 Testing on sample data...")

# Take a small random sample from the test set
sample_size = 100
sample_indices = np.random.choice(X_test_seq.shape[0], sample_size, replace=False)
X_sample_seq = X_test_seq[sample_indices]
y_sample = y_test_seq[sample_indices]  # ✅ FIXED: Use NumPy-style indexing

# Predict probabilities and apply threshold
y_sample_pred_prob = model.predict(X_sample_seq)
y_sample_pred = (y_sample_pred_prob > best_threshold).astype(int).reshape(-1)

# Evaluate on sample
print(f"Sample test accuracy: {accuracy_score(y_sample, y_sample_pred):.4f}")
print("\nSample Classification Report:")
unique_classes = np.unique(y_sample_pred)  # Get unique classes in predictions
if len(unique_classes) == 1:
    # Handle case where only one class is present in predictions
    print(f"Only one class ({unique_classes[0]}) present in predictions. Skipping detailed classification report.")
else:
    # Generate classification report with both classes
    print(classification_report(y_sample, y_sample_pred, target_names=["Normal", "Attack"]))

# 13. Predict a known attack sample from validation set
attack_indices = np.where(y_val_seq == 1)[0]
if attack_indices.size > 0:
    sample = X_val_seq[attack_indices[0]]
    pred = model.predict(sample[np.newaxis, :, :])
    print(f"Prediction for known attack (probability): {pred[0][0]:.4f}")
else:
    print("⚠️ No attack samples found in validation set.")


# %%
# 13. Function to be integrated in SDN Application plane
def predict_on_new_data(new_data_path):
    """
    Predict anomalies on new network traffic data
    
    Parameters:
    new_data_path: Path to the CSV file containing new network traffic data
    
    Returns:
    Predictions (0 for normal, 1 for attack)
    """
    # Load new data
    new_df = pd.read_csv(new_data_path, low_memory=False)
    
    # Preprocess
    new_df = new_df.dropna()
    new_df = new_df.replace([np.inf, -np.inf], np.nan)
    new_df = new_df.fillna(new_df.max() * 1000)
    
    # Extract features
    new_X = new_df[numeric_cols]
    
    # Scale
    new_X_scaled = scaler.transform(new_X)
    
    # Reshape for LSTM
    new_X_reshaped = new_X_scaled.reshape(new_X_scaled.shape[0], 1, new_X_scaled.shape[1])
    
    # Predict
    new_pred_prob = model.predict(new_X_reshaped)
    
    new_pred = (new_pred_prob > best_threshold).astype(int).reshape(-1)
    
    return new_pred

# Example usage in SDN controller to test
# new_predictions = predict_on_new_data("path_to_new_traffic_data.csv")
# print(f"Number of normal traffic flows: {(new_predictions == 0).sum()}")
# print(f"Number of detected attacks: {(new_predictions == 1).sum()}")

# Add memory-efficient practices
import tensorflow as tf
from tensorflow.keras import backend as K

# Check for GPU availability and handle CUDA initialization errors
physical_devices = tf.config.list_physical_devices('GPU')
if not physical_devices:
    print("⚠️ No GPU detected. Running on CPU.")
else:
    try:
        for device in physical_devices:
            tf.config.experimental.set_memory_growth(device, True)
        print("✅ Enabled memory growth for GPUs.")
    except RuntimeError as e:
        print(f"⚠️ Could not set memory growth: {e}. Ensure CUDA and cuDNN are properly installed.")

# Clear Keras session to free memory after training
K.clear_session()

print("\nNotebook execution complete!")



