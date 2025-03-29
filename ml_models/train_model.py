import pickle
import sys
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

# Add the parent directory to system path to import from data_processing
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data_processing.preprocess_cicids import load_and_preprocess_data

def train_model():
    print("Starting model training process...")
    
    # Load and preprocess data
    try:
        X, y, scaler = load_and_preprocess_data('./cids2017.csv')
    except Exception as e:
        print(f"Error loading data: {str(e)}")
        return
    
    print("Data loaded successfully. Starting train-test split...")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    print(f"Training set size: {X_train.shape}, Test set size: {X_test.shape}")
    
    # Train Random Forest model
    print("Training Random Forest model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate model
    print("Evaluating model performance...")
    y_pred = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save model and scaler
    print("Saving model and scaler...")
    with open('model.pkl', 'wb') as f:
        pickle.dump((model, scaler), f)
    print("Model and scaler saved to 'model.pkl'")

if __name__ == '__main__':
    train_model()

