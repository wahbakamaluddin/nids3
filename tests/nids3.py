from scapy.all import *
from collections import defaultdict, deque
import numpy as np
import threading
import time
import joblib

# -------------------------------
# Configuration
# -------------------------------
IDLE_TIMEOUT = 30          # seconds before a flow is considered idle
PACKET_THRESHOLD = 20      # packets before partial evaluation
CLEANUP_INTERVAL = 10      # seconds between cleanup checks
INTERFACE = 'en0'          # network interface for sniffing

# -------------------------------
# ML Model (load or placeholder)
# -------------------------------
try:
    model = joblib.load('model.pkl')  # Replace with your trained model
    print("[INFO] ML model loaded successfully.")
except:
    model = None
    print("[WARNING] No model found. Using heuristic-based anomaly detector.")

def anomaly_detector(features):
    if model:
        # Convert dictionary to array in the model’s expected order
        X = np.array([list(features.values())]).astype(float)
        prediction = model.predict(X)[0]
        return prediction
    else:
        # Simple heuristic for testing
        if features['Flow Bytes/s'] > 1e6 or features['Flow Packets/s'] > 1000:
            return "Suspicious"
        else:
            return "Normal"

# -------------------------------
# Flow storage structure
# -------------------------------
flow_stats = defaultdict(lambda: {
    'start_time': None,
    'end_time': None,
    'last_detection_time': None,
    'fwd_packets': 0,
    'bwd_packets': 0,
    'fwd_bytes': 0,
    'bwd_bytes': 0,
    'fwd_packet_sizes': deque(maxlen=100),
    'bwd_packet_sizes': deque(maxlen=100),
    'packet_sizes': deque(maxlen=100),
    'fwd_iat': deque(maxlen=100),
    'bwd_iat': deque(maxlen=100),
    'flow_iat': deque(maxlen=100),
    'psh_flags': 0,
    'fin_flags': 0,
    'ack_flags': 0,
    'fwd_header_bytes': 0,
    'bwd_header_bytes': 0,
    'fwd_win_bytes': None,
    'bwd_win_bytes': None,
    'min_seg_size_forward': float('inf'),
    'fwd_data_packets': 0,
    'active_times': deque(maxlen=100),
    'idle_times': deque(maxlen=100),
    'last_packet_time': None,
    'last_fwd_packet_time': None,
    'last_bwd_packet_time': None,
    'features': defaultdict(float)
})

# -------------------------------
# Feature extractor
# -------------------------------
def feature_extractor(flow_key):
    flow = flow_stats[flow_key]

    if not flow['start_time'] or not flow['last_packet_time']:
        return

    duration = flow['last_packet_time'] - flow['start_time']
    if duration <= 0:
        duration = 0.001

    # Destination port
    parts = flow_key.split('-')
    try:
        dst_part = parts[0].split(':')[1] if ':' in parts[0] else parts[1].split(':')[1]
        flow['features']['Destination Port'] = int(dst_part)
    except:
        flow['features']['Destination Port'] = 0

    # Basic flow features
    flow['features']['Flow Duration'] = duration * 1000
    flow['features']['Flow Bytes/s'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / duration
    flow['features']['Flow Packets/s'] = (flow['fwd_packets'] + flow['bwd_packets']) / duration

    # Forward direction
    flow['features']['Total Fwd Packets'] = flow['fwd_packets']
    flow['features']['Total Length of Fwd Packets'] = flow['fwd_bytes']
    flow['features']['Fwd Packet Length Min'] = min(flow['fwd_packet_sizes']) if flow['fwd_packet_sizes'] else 0
    flow['features']['Fwd Packet Length Max'] = max(flow['fwd_packet_sizes']) if flow['fwd_packet_sizes'] else 0
    flow['features']['Fwd Packet Length Mean'] = np.mean(flow['fwd_packet_sizes']) if flow['fwd_packet_sizes'] else 0
    flow['features']['Fwd Packet Length Std'] = np.std(flow['fwd_packet_sizes']) if len(flow['fwd_packet_sizes']) > 1 else 0
    flow['features']['Fwd Header Length'] = flow['fwd_header_bytes']

    # Backward direction
    flow['features']['Bwd Packet Length Min'] = min(flow['bwd_packet_sizes']) if flow['bwd_packet_sizes'] else 0
    flow['features']['Bwd Packet Length Max'] = max(flow['bwd_packet_sizes']) if flow['bwd_packet_sizes'] else 0
    flow['features']['Bwd Packet Length Mean'] = np.mean(flow['bwd_packet_sizes']) if flow['bwd_packet_sizes'] else 0
    flow['features']['Bwd Packet Length Std'] = np.std(flow['bwd_packet_sizes']) if len(flow['bwd_packet_sizes']) > 1 else 0
    flow['features']['Bwd Header Length'] = flow['bwd_header_bytes']

    # Packet length
    flow['features']['Min Packet Length'] = min(flow['packet_sizes']) if flow['packet_sizes'] else 0
    flow['features']['Max Packet Length'] = max(flow['packet_sizes']) if flow['packet_sizes'] else 0
    flow['features']['Packet Length Mean'] = np.mean(flow['packet_sizes']) if flow['packet_sizes'] else 0
    flow['features']['Packet Length Std'] = np.std(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0
    flow['features']['Packet Length Variance'] = np.var(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0

    # Average packet size
    total_packets = flow['fwd_packets'] + flow['bwd_packets']
    flow['features']['Average Packet Size'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / total_packets if total_packets > 0 else 0

    # IAT features
    if flow['flow_iat']:
        flow['features']['Flow IAT Mean'] = np.mean(flow['flow_iat'])
        flow['features']['Flow IAT Std'] = np.std(flow['flow_iat'])
        flow['features']['Flow IAT Max'] = max(flow['flow_iat'])
        flow['features']['Flow IAT Min'] = min(flow['flow_iat'])

# -------------------------------
# Packet parser
# -------------------------------
def packet_parser(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Identify transport protocol
    if TCP in packet:
        proto = 'TCP'
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        header_length = len(packet[TCP])
        window_size = getattr(packet[TCP], 'window', 0)
    elif UDP in packet:
        proto = 'UDP'
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        header_length = len(packet[UDP])
        window_size = 0
    else:
        return

    packet_size = len(packet)
    current_time = time.time()

    forward_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
    backward_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"

    if forward_key in flow_stats:
        flow_key = forward_key
        is_forward = True
    elif backward_key in flow_stats:
        flow_key = backward_key
        is_forward = False
    else:
        flow_key = forward_key
        is_forward = True

    flow = flow_stats[flow_key]

    if flow['start_time'] is None:
        flow['start_time'] = current_time
    flow['last_packet_time'] = current_time

    if is_forward:
        flow['fwd_packets'] += 1
        flow['fwd_bytes'] += packet_size
        flow['packet_sizes'].append(packet_size)
        flow['fwd_packet_sizes'].append(packet_size)
        flow['fwd_header_bytes'] += header_length
        if flow['fwd_win_bytes'] is None and window_size > 0:
            flow['fwd_win_bytes'] = window_size
        if flow['last_fwd_packet_time']:
            flow['fwd_iat'].append(current_time - flow['last_fwd_packet_time'])
        flow['last_fwd_packet_time'] = current_time
    else:
        flow['bwd_packets'] += 1
        flow['bwd_bytes'] += packet_size
        flow['packet_sizes'].append(packet_size)
        flow['bwd_packet_sizes'].append(packet_size)
        flow['bwd_header_bytes'] += header_length
        if flow['bwd_win_bytes'] is None and window_size > 0:
            flow['bwd_win_bytes'] = window_size
        if flow['last_bwd_packet_time']:
            flow['bwd_iat'].append(current_time - flow['last_bwd_packet_time'])
        flow['last_bwd_packet_time'] = current_time

    feature_extractor(flow_key)

    total_packets = flow['fwd_packets'] + flow['bwd_packets']
    idle_time = current_time - flow['last_packet_time'] if flow['last_packet_time'] else 0

    # Feed to ML model if threshold reached or idle too long
    if total_packets >= PACKET_THRESHOLD or idle_time > IDLE_TIMEOUT:
        prediction = anomaly_detector(flow['features'])
        print(f"[ALERT] Flow {flow_key} -> {prediction}")

        if idle_time > IDLE_TIMEOUT:
            del flow_stats[flow_key]
        else:
            flow['fwd_packets'] = 0
            flow['bwd_packets'] = 0

# -------------------------------
# Cleanup thread
# -------------------------------
def cleanup_flows():
    while True:
        current_time = time.time()
        for flow_key in list(flow_stats.keys()):
            flow = flow_stats[flow_key]
            if flow['last_packet_time'] and (current_time - flow['last_packet_time']) > IDLE_TIMEOUT:
                print(f"[CLEANUP] Flow {flow_key} idle for {IDLE_TIMEOUT}s — evaluating & removing.")
                prediction = anomaly_detector(flow['features'])
                print(f"[ALERT] Flow {flow_key} -> {prediction}")
                del flow_stats[flow_key]
        time.sleep(CLEANUP_INTERVAL)

# -------------------------------
# Packet capture
# -------------------------------
def packet_capturer():
    sniff(iface=INTERFACE, prn=packet_parser, store=False)

# -------------------------------
# Main entry
# -------------------------------
if __name__ == "__main__":
    print("[INFO] Starting NIDS...")
    threading.Thread(target=cleanup_flows, daemon=True).start()
    packet_capturer()
