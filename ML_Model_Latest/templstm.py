import os
import glob
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Dropout
from sklearn.metrics import accuracy_score

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

    # Load the first 2 files (to prevent excessive memory usage)
    files_to_process = all_files[:2]
    dfs = []

    for file in files_to_process:
        print(f"Processing {file}...")
        df = pd.read_csv(file)
        df = df.dropna()

        # Convert infinity values to NaN, then replace with max * 1000
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        for col in numeric_cols:
            max_val = df[col].max()
            df[col] = df[col].fillna(max_val * 1000 if not pd.isna(max_val) else 0)

        dfs.append(df)

    # Combine all files
    full_df = pd.concat(dfs, ignore_index=True)
    
    # Ensure the 'label' column is properly formatted
    if 'Label' in full_df.columns:
        full_df.rename(columns={'Label': 'label'}, inplace=True)
    elif ' Label' in full_df.columns:
        full_df.rename(columns={' Label': 'label'}, inplace=True)

    # Convert labels to binary (Benign = 0, Attack = 1)
    full_df['label'] = full_df['label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

    return full_df

# Load CIC-IDS2017 dataset
cicids_df = load_cicids_data()

print("Loading Mininet Flow Data...")

# Load Mininet flow data
mininet_df = pd.read_csv("mininet_flow_data_1741755799.csv")

# Drop unnecessary columns
mininet_df = mininet_df.drop(columns=['switch', 'timestamp', 'collection_time'])

# Convert labels
mininet_df['label'] = mininet_df['label'].map({'BENIGN': 0, 'ATTACK': 1})

# Ensure feature alignment between CIC-IDS2017 and Mininet
if cicids_df is not None:
    # Get common features
    common_features = list(set(cicids_df.columns) & set(mininet_df.columns))
    print(f"Using {len(common_features)} common features:", common_features)

    # Filter datasets to have the same feature set
    cicids_df = cicids_df[common_features]
    mininet_df = mininet_df[common_features]

    # Merge both datasets
    combined_df = pd.concat([cicids_df, mininet_df], ignore_index=True)
else:
    print("⚠️ CIC-IDS2017 data not loaded. Using Mininet data only!")
    combined_df = mininet_df

print(f"Final dataset shape: {combined_df.shape}")

# Extract features & labels
X = combined_df.drop(columns=['label'])
y = combined_df['label']

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
X_train, X_val, y_train, y_val = train_test_split(X_train, y_train, test_size=0.2, random_state=42, stratify=y_train)

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

# Save the scaler
with open("scaler_combined.pk1", "wb") as f:
    pickle.dump(scaler, f)

# Reshape for LSTM
X_train_reshaped = X_train_scaled.reshape(X_train_scaled.shape[0], 1, X_train_scaled.shape[1])
X_val_reshaped = X_val_scaled.reshape(X_val_scaled.shape[0], 1, X_val_scaled.shape[1])
X_test_reshaped = X_test_scaled.reshape(X_test_scaled.shape[0], 1, X_test_scaled.shape[1])

# Build LSTM model
print("Building LSTM model...")

model = Sequential([
    LSTM(128, activation='relu', input_shape=(1, X_train_scaled.shape[1]), return_sequences=True),
    Dropout(0.2),
    LSTM(64, activation='relu'),
    Dropout(0.2),
    Dense(32, activation='relu'),
    Dense(1, activation='sigmoid')
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
model.summary()

# Train the model
print("Training the model...")

early_stopping = tf.keras.callbacks.EarlyStopping(
    monitor='val_loss', patience=3, restore_best_weights=True
)

history = model.fit(
    X_train_reshaped, y_train,
    epochs=10,
    batch_size=64,
    validation_data=(X_val_reshaped, y_val),
    callbacks=[early_stopping]
)

# Save the model
model.save("lstm_model_combined.h5")

# Evaluate on test set
print("Evaluating on test set...")
y_pred_prob = model.predict(X_test_reshaped)
y_pred = (y_pred_prob > 0.5).astype(int).reshape(-1)

accuracy = accuracy_score(y_test, y_pred)
print(f"Test accuracy: {accuracy:.4f}")

# Save feature names
with open("feature_names_combined.pk1", "wb") as f:
    pickle.dump(X.columns.tolist(), f)

print("Model and scaler saved successfully! 🚀")
