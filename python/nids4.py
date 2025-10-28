from scapy.all import *
from collections import defaultdict, deque
import numpy as np
import time
import threading
import joblib  # For model loading (optional)

# ====================================================
# CONFIGURATION
# ====================================================
FLOW_TIMEOUT = 60                # seconds to keep inactive flow
INACTIVITY_THRESHOLD = 1.0       # threshold to define idle/active periods
FEATURE_EXTRACT_INTERVAL = 1.0   # seconds between feature extractions
INTERFACE = "en0"                # network interface

# Load model (optional)
model = joblib.load("/Users/wahba/Library/Mobile Documents/com~apple~CloudDocs/others/nids3/models/xgb.joblib")

# Model-required features (order matters)
required_features = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total',
    'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length',
    'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'Average Packet Size',
    'Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Max', 'Idle Min', 'Attack Type'
]

# ====================================================
# FLOW STRUCTURE
# ====================================================
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
    'fwd_psh_flags': 0,
    'fwd_urg_flags': 0,
    'fin_flags': 0,
    'syn_flags': 0,
    'rst_flags': 0,
    'psh_flags': 0,
    'ack_flags': 0,
    'urg_flags': 0,
    'ece_flags': 0,
    'fwd_header_bytes': 0,
    'bwd_header_bytes': 0,
    'fwd_win_bytes': None,
    'bwd_win_bytes': None,
    'active_times': deque(maxlen=100),
    'idle_times': deque(maxlen=100),
    'last_packet_time': None,
    'last_fwd_packet_time': None,
    'last_bwd_packet_time': None,
    'min_seg_size_forward': float('inf'),
    'active': False,
    'active_start': None,
    'idle_start': None,
    'fwd_data_packets': 0,
    'features': {feature: 0 for feature in required_features}
})

# ====================================================
# FEATURE EXTRACTION
# ====================================================
def feature_extractor(flow_key):
    flow = flow_stats[flow_key]
    current_time = time.time()

    # Update end time
    flow['end_time'] = current_time
    duration = flow['end_time'] - flow['start_time']
    if duration <= 0:
        duration = 0.001

    # Parse destination port
    parts = flow_key.split('-')
    try:
        dst_part = parts[0].split(':')[1] if ':' in parts[0] else parts[1].split(':')[1]
        flow['features']['Destination Port'] = int(dst_part)
    except:
        flow['features']['Destination Port'] = 0

    # Flow duration and rates
    flow['features']['Flow Duration'] = duration
    flow['features']['Flow Bytes/s'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / duration
    flow['features']['Flow Packets/s'] = (flow['fwd_packets'] + flow['bwd_packets']) / duration

    # Forward features
    fwd_sizes = flow['fwd_packet_sizes']
    flow['features']['Total Fwd Packets'] = flow['fwd_packets']
    flow['features']['Total Length of Fwd Packets'] = flow['fwd_bytes']
    flow['features']['Fwd Packet Length Min'] = min(fwd_sizes) if fwd_sizes else 0
    flow['features']['Fwd Packet Length Max'] = max(fwd_sizes) if fwd_sizes else 0
    flow['features']['Fwd Packet Length Mean'] = np.mean(fwd_sizes) if fwd_sizes else 0
    flow['features']['Fwd Packet Length Std'] = np.std(fwd_sizes) if len(fwd_sizes) > 1 else 0
    flow['features']['Fwd Packets/s'] = flow['fwd_packets'] / duration
    flow['features']['Fwd Header Length'] = flow['fwd_header_bytes']

    # Backward features
    bwd_sizes = flow['bwd_packet_sizes']
    flow['features']['Bwd Packets/s'] = flow['bwd_packets'] / duration
    flow['features']['Bwd Packet Length Min'] = min(bwd_sizes) if bwd_sizes else 0
    flow['features']['Bwd Packet Length Max'] = max(bwd_sizes) if bwd_sizes else 0
    flow['features']['Bwd Packet Length Mean'] = np.mean(bwd_sizes) if bwd_sizes else 0
    flow['features']['Bwd Packet Length Std'] = np.std(bwd_sizes) if len(bwd_sizes) > 1 else 0
    flow['features']['Bwd Header Length'] = flow['bwd_header_bytes']

    # Packet length stats
    pkt_sizes = flow['packet_sizes']
    flow['features']['Min Packet Length'] = min(pkt_sizes) if pkt_sizes else 0
    flow['features']['Max Packet Length'] = max(pkt_sizes) if pkt_sizes else 0
    flow['features']['Packet Length Mean'] = np.mean(pkt_sizes) if pkt_sizes else 0
    flow['features']['Packet Length Std'] = np.std(pkt_sizes) if len(pkt_sizes) > 1 else 0
    flow['features']['Packet Length Variance'] = np.var(pkt_sizes) if len(pkt_sizes) > 1 else 0

    # Average packet size
    total_pkts = flow['fwd_packets'] + flow['bwd_packets']
    flow['features']['Average Packet Size'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / total_pkts if total_pkts > 0 else 0

    # IAT stats
    if flow['flow_iat']:
        flow['features']['Flow IAT Mean'] = np.mean(flow['flow_iat'])
        flow['features']['Flow IAT Std'] = np.std(flow['flow_iat'])
        flow['features']['Flow IAT Max'] = max(flow['flow_iat'])
        flow['features']['Flow IAT Min'] = min(flow['flow_iat'])

    # Forward IAT
    if flow['fwd_iat']:
        flow['features']['Fwd IAT Total'] = sum(flow['fwd_iat'])
        flow['features']['Fwd IAT Mean'] = np.mean(flow['fwd_iat'])
        flow['features']['Fwd IAT Std'] = np.std(flow['fwd_iat'])
        flow['features']['Fwd IAT Max'] = max(flow['fwd_iat'])
        flow['features']['Fwd IAT Min'] = min(flow['fwd_iat'])

    # Backward IAT
    if flow['bwd_iat']:
        flow['features']['Bwd IAT Total'] = sum(flow['bwd_iat'])
        flow['features']['Bwd IAT Mean'] = np.mean(flow['bwd_iat'])
        flow['features']['Bwd IAT Std'] = np.std(flow['bwd_iat'])
        flow['features']['Bwd IAT Max'] = max(flow['bwd_iat'])
        flow['features']['Bwd IAT Min'] = min(flow['bwd_iat'])

    # Flags
    flow['features']['FIN Flag Count'] = flow['fin_flags']
    flow['features']['PSH Flag Count'] = flow['psh_flags']
    flow['features']['ACK Flag Count'] = flow['ack_flags']

    # Window
    flow['features']['Init_Win_bytes_forward'] = flow['fwd_win_bytes'] or 0
    flow['features']['Init_Win_bytes_backward'] = flow['bwd_win_bytes'] or 0

    # Active/Idle stats
    if flow['active_times']:
        flow['features']['Active Mean'] = np.mean(flow['active_times'])
        flow['features']['Active Max'] = max(flow['active_times'])
        flow['features']['Active Min'] = min(flow['active_times'])

    if flow['idle_times']:
        flow['features']['Idle Mean'] = np.mean(flow['idle_times'])
        flow['features']['Idle Max'] = max(flow['idle_times'])
        flow['features']['Idle Min'] = min(flow['idle_times'])

    # Extra
    flow['features']['min_seg_size_forward'] = flow['min_seg_size_forward'] if flow['min_seg_size_forward'] != float('inf') else 0
    flow['features']['act_data_pkt_fwd'] = flow['fwd_data_packets']
    flow['features']['Subflow Fwd Bytes'] = flow['fwd_bytes']

    # Placeholder Attack Type
    flow['features']['Attack Type'] = "Benign"

    anomaly_detector(flow)

    # Optionally call anomaly detector
    # prediction = anomaly_detector(flow)

    # print(f"[+] Extracted {flow_key}: {flow['features']['Flow Bytes/s']:.2f} B/s")s

# ====================================================
# ANOMALY DETECTOR (Optional)
# ====================================================
def anomaly_detector(flow):
    X = np.array([flow['features'][feature] for feature in required_features[:-1]]).reshape(1, -1)
    pred = model.predict(X)
    print(X, pred)
    # return pred[0]

# ====================================================
# PACKET PARSER
# ====================================================
def packet_parser(packet):
    if IP not in packet:
        return

    src_ip, dst_ip = packet[IP].src, packet[IP].dst
    protocol, src_port, dst_port, header_len, window_size = None, None, None, 0, 0

    if TCP in packet:
        protocol = 'TCP'
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
        header_len = len(packet[TCP])
        window_size = getattr(packet[TCP], 'window', 0)
    elif UDP in packet:
        protocol = 'UDP'
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport
        header_len = len(packet[UDP])
    else:
        return

    current_time = time.time()
    packet_size = len(packet)
    forward_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    backward_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

    # Determine flow direction
    if forward_key in flow_stats:
        flow_key, is_forward = forward_key, True
    elif backward_key in flow_stats:
        flow_key, is_forward = backward_key, False
    else:
        flow_key, is_forward = forward_key, True

    flow = flow_stats[flow_key]

    # Initialize flow
    if flow['start_time'] is None:
        flow['start_time'] = current_time
        flow['end_time'] = current_time
        flow['active_start'] = current_time
        flow['active'] = True

    # Update active/idle tracking
    if flow['last_packet_time']:
        delta = current_time - flow['last_packet_time']
        if delta > INACTIVITY_THRESHOLD:
            if flow['active']:
                flow['active_times'].append(current_time - flow['active_start'])
                flow['active'] = False
                flow['idle_start'] = current_time
        else:
            if not flow['active']:
                flow['idle_times'].append(current_time - flow['idle_start'])
                flow['active'] = True
                flow['active_start'] = current_time

    flow['last_packet_time'] = current_time
    flow['end_time'] = current_time

    # Forward direction
    if is_forward:
        flow['fwd_packets'] += 1
        flow['fwd_bytes'] += packet_size
        flow['packet_sizes'].append(packet_size)
        flow['fwd_packet_sizes'].append(packet_size)
        flow['fwd_header_bytes'] += header_len

        # Flags and MSS
        if TCP in packet:
            flags = packet[TCP].flags
            if flags & 0x01: flow['fin_flags'] += 1
            if flags & 0x02: flow['syn_flags'] += 1
            if flags & 0x04: flow['rst_flags'] += 1
            if flags & 0x08: flow['psh_flags'] += 1
            if flags & 0x10: flow['ack_flags'] += 1
            if flags & 0x20: flow['urg_flags'] += 1
            if flags & 0x40: flow['ece_flags'] += 1
            for opt in packet[TCP].options:
                if opt[0] == 'MSS' and opt[1] < flow['min_seg_size_forward']:
                    flow['min_seg_size_forward'] = opt[1]

        if flow['fwd_win_bytes'] is None and window_size > 0:
            flow['fwd_win_bytes'] = window_size
        if TCP in packet and len(packet[TCP].payload) > 0:
            flow['fwd_data_packets'] += 1
        if flow['last_fwd_packet_time']:
            flow['fwd_iat'].append(current_time - flow['last_fwd_packet_time'])
        flow['last_fwd_packet_time'] = current_time

    # Backward direction
    else:
        flow['bwd_packets'] += 1
        flow['bwd_bytes'] += packet_size
        flow['packet_sizes'].append(packet_size)
        flow['bwd_packet_sizes'].append(packet_size)
        flow['bwd_header_bytes'] += header_len
        if flow['bwd_win_bytes'] is None and window_size > 0:
            flow['bwd_win_bytes'] = window_size
        if flow['last_bwd_packet_time']:
            flow['bwd_iat'].append(current_time - flow['last_bwd_packet_time'])
        flow['last_bwd_packet_time'] = current_time

    # Periodic feature extraction
    if (flow['last_detection_time'] is None) or (current_time - flow['last_detection_time'] > FEATURE_EXTRACT_INTERVAL):
        feature_extractor(flow_key)
        flow['last_detection_time'] = current_time

# ====================================================
# CLEANUP THREAD
# ====================================================
def cleanup_flows():
    while True:
        now = time.time()
        for key in list(flow_stats.keys()):
            if flow_stats[key]['end_time'] and now - flow_stats[key]['end_time'] > FLOW_TIMEOUT:
                del flow_stats[key]
        time.sleep(10)

# ====================================================
# MAIN CAPTURE FUNCTION
# ====================================================
def packet_capturer():
    threading.Thread(target=cleanup_flows, daemon=True).start()
    print(f"[*] Capturing packets on {INTERFACE}...")
    sniff(iface=INTERFACE, prn=packet_parser, store=False)

# ====================================================
# ENTRY POINT
# ====================================================
if __name__ == "__main__":
    packet_capturer()
