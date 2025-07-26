import joblib
import numpy as np

def load_model():
    return joblib.load("models/nids_model.pkl")

def predict(features):
    model = load_model()
    features = np.array(features).reshape(1, -1)
    pred = model.predict(features)[0]
    return "🚨 Attack" if pred == 1 else "✅ Normal"
