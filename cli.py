import joblib

def main():
    print("🔹 Network Intrusion Detection CLI 🔹")
    # Load model and encoders/scaler
    model = joblib.load("models/nids_model.pkl")
    protocol_encoder = joblib.load("models/encoder_protocol.pkl")
    service_encoder = joblib.load("models/encoder_service.pkl")
    flag_encoder = joblib.load("models/encoder_flag.pkl")
    scaler = joblib.load("models/scaler.pkl")

    input_str = input("Enter 41 comma-separated feature values (protocol_type, service, flag should be categorical names):\n> ")
    features = input_str.strip().split(',')

    # Columns order except label and difficulty:
    cols = [
        "duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment",
        "urgent","hot","num_failed_logins","logged_in","num_compromised","root_shell","su_attempted",
        "num_root","num_file_creations","num_shells","num_access_files","num_outbound_cmds",
        "is_host_login","is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
        "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate",
        "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
        "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate"
    ]

    if len(features) != len(cols):
        print(f"❌ Error: Expected {len(cols)} features but got {len(features)}")
        return

    # Convert categorical string to encoded int
    features[1] = protocol_encoder.transform([features[1]])[0]
    features[2] = service_encoder.transform([features[2]])[0]
    features[3] = flag_encoder.transform([features[3]])[0]

    # Convert rest to float
    for i in [0] + list(range(4, len(features))):
        features[i] = float(features[i])

    # Scale features
    features_scaled = scaler.transform([features])

    # Predict
    pred = model.predict(features_scaled)[0]
    print("\n🔍 Prediction:", "🚨 Attack" if pred == 1 else "✅ Normal")

if __name__ == "__main__":
    main()
