import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from preprocess import load_data

def train_and_save_model():
    print("🔹 Training model...")
    X_train, X_test, y_train, y_test, protocol_encoder, service_encoder, flag_encoder, scaler = load_data("data/KDDTrain+.txt", "data/KDDTest+.txt")

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("✅ Model Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    joblib.dump(model, "models/nids_model.pkl")
    joblib.dump(protocol_encoder, "models/encoder_protocol.pkl")
    joblib.dump(service_encoder, "models/encoder_service.pkl")
    joblib.dump(flag_encoder, "models/encoder_flag.pkl")
    joblib.dump(scaler, "models/scaler.pkl")

    print("✅ Model and preprocessors saved to models/")

if __name__ == "__main__":
    train_and_save_model()