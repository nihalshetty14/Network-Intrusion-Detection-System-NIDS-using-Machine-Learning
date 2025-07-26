from scapy.all import rdpcap
import pandas as pd
import socket

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
            proto = pkt.proto
            src = pkt["IP"].src
            dst = pkt["IP"].dst

            if pkt.haslayer("TCP") or pkt.haslayer("UDP"):
                sport = pkt.sport
                dport = pkt.dport
            else:
                sport = 0
                dport = 0

            flow_key = (src, dst, sport, dport, proto)

            if flow_key not in flows:
                flows[flow_key] = {
                    "duration": 0,
                    "protocol_type": "tcp" if proto == 6 else "udp" if proto == 17 else "icmp",
                    "service": get_service(dport) if dport != 0 else "other",
                    "src_bytes": 0,
                    "dst_bytes": 0,
                    "count": 0,
                    "srv_count": 0
                }

            flows[flow_key]["src_bytes"] += len(pkt)
            flows[flow_key]["count"] += 1

    df = pd.DataFrame(flows.values())
    return df

if __name__ == "__main__":
    features_df = extract_features("capture.pcapng")
    print(features_df.head())
    features_df.to_csv("extracted_features.csv", index=False)
    print("✅ Features saved to extracted_features.csv")
