import os
import pandas as pd
from nfstream import NFStreamer
from flow_classifier_pcap import FlowClassifier

# === CONFIG ===
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"  # Disable GPU

PCAP_DIR = "/tmp/pcap_files"
PCAP_LIST = [f"h{i}.pcap" for i in range(1, 7)]
CSV_OUTPUT = "predicted_flows.csv"
DEBUG_FLOW_LIMIT = 1000  # Set to None to process all flows

# === Init Classifier ===
classifier = FlowClassifier(
    model_path="../ml_model/lstm_model_combined.keras",      # .keras path is correct
    scaler_path="../ml_model/scaler.pkl",
    features_path="../ml_model/feature_names.pkl"
)

# === Collect and Classify Flows ===
results = []

for pcap in PCAP_LIST:
    path = os.path.join(PCAP_DIR, pcap)
    if not os.path.exists(path):
        print(f"❌ Missing PCAP: {path}")
        continue

    print(f"📥 Processing {pcap}")
    streamer = NFStreamer(
        source=path,
        decode_tunnels=False,
        statistical_analysis=True
    )

    for i, flow in enumerate(streamer):
        if DEBUG_FLOW_LIMIT and i >= DEBUG_FLOW_LIMIT:
            print(f"⚠️ Reached debug limit of {DEBUG_FLOW_LIMIT} flows.")
            break

        try:
            is_anomaly = classifier.classify_flow(flow)
            record = {
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                "duration_ms": flow.bidirectional_duration_ms,
                "bytes": flow.bidirectional_bytes,
                "packets": flow.bidirectional_packets,
                "host": pcap.replace(".pcap", ""),
                "prediction": int(is_anomaly)
            }
            results.append(record)
        except AttributeError as e:
            print(f"⚠️ Skipping flow due to missing attribute: {e}")
        except Exception as e:
            print(f"⚠️ Unexpected error during flow classification: {e}")

# === Save Results ===
df = pd.DataFrame(results)
df.to_csv(CSV_OUTPUT, index=False)
print(f"✅ Saved predictions to {CSV_OUTPUT}")
