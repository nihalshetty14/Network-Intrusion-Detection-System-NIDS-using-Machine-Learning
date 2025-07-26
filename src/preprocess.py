import pandas as pd
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment",
    "urgent","hot","num_failed_logins","logged_in","num_compromised","root_shell","su_attempted",
    "num_root","num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "label",
    "difficulty"
]

def load_data(train_path, test_path):
    train_df = pd.read_csv(train_path, names=columns)
    test_df = pd.read_csv(test_path, names=columns)

    train_df.drop(columns=["difficulty"], inplace=True)
    test_df.drop(columns=["difficulty"], inplace=True)

    combined_df = pd.concat([train_df, test_df], axis=0)

    categorical_cols = ["protocol_type", "service", "flag"]

    protocol_encoder = LabelEncoder()
    service_encoder = LabelEncoder()
    flag_encoder = LabelEncoder()

    combined_df["protocol_type"] = protocol_encoder.fit_transform(combined_df["protocol_type"])
    combined_df["service"] = service_encoder.fit_transform(combined_df["service"])
    combined_df["flag"] = flag_encoder.fit_transform(combined_df["flag"])

    train_df["protocol_type"] = protocol_encoder.transform(train_df["protocol_type"])
    train_df["service"] = service_encoder.transform(train_df["service"])
    train_df["flag"] = flag_encoder.transform(train_df["flag"])

    test_df["protocol_type"] = protocol_encoder.transform(test_df["protocol_type"])
    test_df["service"] = service_encoder.transform(test_df["service"])
    test_df["flag"] = flag_encoder.transform(test_df["flag"])

    train_df["label"] = train_df["label"].apply(lambda x: 0 if x == "normal" else 1)
    test_df["label"] = test_df["label"].apply(lambda x: 0 if x == "normal" else 1)

    X_train = train_df.drop("label", axis=1)
    X_test = test_df.drop("label", axis=1)
    y_train = train_df["label"]
    y_test = test_df["label"]

    scaler = MinMaxScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    return X_train, X_test, y_train, y_test, protocol_encoder, service_encoder, flag_encoder, scaler
