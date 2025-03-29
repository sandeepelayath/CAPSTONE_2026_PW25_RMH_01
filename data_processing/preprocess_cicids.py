# data_processing/preprocess_cicids.py
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
from sklearn.feature_selection import SelectKBest, f_classif

def validate_data(df):
    """Validates and cleans the input data."""
    print("Validating data...")
    
    # Check for missing values
    missing_values = df.isnull().sum()
    print(f"Missing values:\n{missing_values[missing_values > 0]}")
    
    # Check for infinite values
    inf_values = np.isinf(df.select_dtypes(include=np.number)).sum()
    print(f"Infinite values:\n{inf_values[inf_values > 0]}")
    
    # Remove duplicates
    initial_rows = len(df)
    df = df.drop_duplicates()
    print(f"Removed {initial_rows - len(df)} duplicate rows")
    
    # Check for invalid values
    numeric_cols = df.select_dtypes(include=np.number).columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    
    return df

def select_features(X, y, n_features=20):
    """Selects the most important features using statistical tests."""
    selector = SelectKBest(score_func=f_classif, k=n_features)
    X_selected = selector.fit_transform(X, y)
    selected_features = X.columns[selector.get_support()].tolist()
    
    print("Selected features:", selected_features)
    return X_selected, selected_features

def load_and_preprocess_data(file_path, test_size=0.2, random_state=42):
    print("Loading dataset from:", file_path)
    # Load CICIDS2017 dataset
    df = pd.read_csv(file_path)
    
    # Validate and clean data
    df = validate_data(df)
    
    # Select relevant features with correct column names from your dataset
    selected_features = [
        ' Flow Duration',
        ' Total Fwd Packets',
        ' Total Backward Packets',
        'Total Length of Fwd Packets',
        ' Total Length of Bwd Packets',
        'Flow Bytes/s',
        ' Flow Packets/s',
        ' Flow IAT Mean',
        ' Flow IAT Std',
        ' Flow IAT Max',
        ' Flow IAT Min',
        ' Fwd IAT Mean',
        ' Fwd IAT Std',
        ' Bwd IAT Mean',
        ' Bwd IAT Std',
        ' Fwd PSH Flags',
        ' Bwd PSH Flags',
        ' Fwd URG Flags',
        ' Bwd URG Flags',
        ' Fwd Header Length',
        ' Bwd Header Length',
        ' Fwd Packets/s',
        ' Bwd Packets/s',
        ' Packet Length Mean',
        ' Packet Length Std',
        ' Label'
    ]
    
    print("Selecting features:", selected_features)
    df = df[selected_features]
    
    # Convert label to binary (0 for benign, 1 for attack)
    print("Converting labels to binary...")
    df[' Label'] = df[' Label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
    
    # Handle missing values and infinities
    print("Handling missing values and infinities...")
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.fillna(df.mean())
    
    # Split features and labels
    X = df.drop(' Label', axis=1)
    y = df[' Label']
    
    # Feature selection
    X_selected, selected_feature_names = select_features(X, y)
    
    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X_selected, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    # Handle class imbalance using SMOTE
    print("Applying SMOTE to handle class imbalance...")
    smote = SMOTE(random_state=random_state)
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
    
    # Scale features
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_resampled)
    X_test_scaled = scaler.transform(X_test)
    
    # Print class distribution
    print("\nClass distribution:")
    print("Original:", pd.Series(y).value_counts(normalize=True))
    print("After SMOTE:", pd.Series(y_train_resampled).value_counts(normalize=True))
    
    print("Data preprocessing completed.")
    return (X_train_scaled, X_test_scaled, y_train_resampled, y_test, 
            scaler, selected_feature_names)