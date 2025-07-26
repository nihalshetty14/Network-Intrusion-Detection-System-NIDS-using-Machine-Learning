from scapy.all import rdpcap
import pandas as pd
import socket
import joblib

def get_service(port):
    try:
        return socket.getservbyport(port)
    except:
        return "other"

def extract_features(pcap_file):
    packets = rdpcap(pcap_file)
    flows = {}

    for pkt in packets:
        if pkt.haslayer("IP"):
            proto = pkt["IP"].proto
            src = pkt["IP"].src
            dst = pkt["IP"].dst

            sport = pkt.sport if pkt.haslayer("TCP") or pkt.haslayer("UDP") else 0
            dport = pkt.dport if pkt.haslayer("TCP") or pkt.haslayer("UDP") else 0

            flow_key = (src, dst, sport, dport, proto)

            if flow_key not in flows:
                flows[flow_key] = {
                    "duration": 0,
                    "protocol_type": "tcp" if proto == 6 else "udp" if proto == 17 else "icmp",
                    "service": get_service(dport) if dport != 0 else "other",
                    "flag": "SF",  # Placeholder flag, customize as needed
                    "src_bytes": 0,
                    "dst_bytes": 0,
                    "land": 0,
                    "wrong_fragment": 0,
                    "urgent": 0,
                    "hot": 0,
                    "num_failed_logins": 0,
                    "logged_in": 0,
                    "num_compromised": 0,
                    "root_shell": 0,
                    "su_attempted": 0,
                    "num_root": 0,
                    "num_file_creations": 0,
                    "num_shells": 0,
                    "num_access_files": 0,
                    "num_outbound_cmds": 0,
                    "is_host_login": 0,
                    "is_guest_login": 0,
                    "count": 0,
                    "srv_count": 0,
                    "serror_rate": 0,
                    "srv_serror_rate": 0,
                    "rerror_rate": 0,
                    "srv_rerror_rate": 0,
                    "same_srv_rate": 0,
                    "diff_srv_rate": 0,
                    "srv_diff_host_rate": 0,
                    "dst_host_count": 0,
                    "dst_host_srv_count": 0,
                    "dst_host_same_srv_rate": 0,
                    "dst_host_diff_srv_rate": 0,
                    "dst_host_same_src_port_rate": 0,
                    "dst_host_srv_diff_host_rate": 0,
                    "dst_host_serror_rate": 0,
                    "dst_host_srv_serror_rate": 0,
                    "dst_host_rerror_rate": 0,
                    "dst_host_srv_rerror_rate": 0,
                }

            flows[flow_key]["src_bytes"] += len(pkt)
            flows[flow_key]["count"] += 1

    df = pd.DataFrame(flows.values())
    return df

def preprocess_pcap_df(df):
    # Load encoders and scaler
    protocol_encoder = joblib.load("models/encoder_protocol.pkl")
    service_encoder = joblib.load("models/encoder_service.pkl")
    flag_encoder = joblib.load("models/encoder_flag.pkl")
    scaler = joblib.load("models/scaler.pkl")

    # Encode categorical columns
    df["protocol_type"] = protocol_encoder.transform(df["protocol_type"])
    df["service"] = df["service"].apply(lambda x: x if x in service_encoder.classes_ else "other")
    df["service"] = service_encoder.transform(df["service"])
    df["flag"] = df["flag"].apply(lambda x: x if x in flag_encoder.classes_ else "SF")
    df["flag"] = flag_encoder.transform(df["flag"])

    # Scale numerical columns
    X = scaler.transform(df)

    return X

def main():
    print("🔹 Starting Network Intrusion Detection from PCAP 🔹")
    df = extract_features("capture.pcapng")
    print(f"✅ Extracted {len(df)} flows")

    X = preprocess_pcap_df(df)

    model = joblib.load("models/nids_model.pkl")
    preds = model.predict(X)

    for i, pred in enumerate(preds, start=1):
        print(f"Flow {i}: {'🚨 Attack' if pred == 1 else 'Normal'}")

if __name__ == "__main__":
    main()
