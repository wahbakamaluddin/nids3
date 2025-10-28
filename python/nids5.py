import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import *
from collections import defaultdict, deque
import numpy as np
import time
import threading
import joblib
import psutil
import pandas as pd

# ====================================================
# CONFIGURATION
# ====================================================
FLOW_TIMEOUT = 60
INACTIVITY_THRESHOLD = 1.0
FEATURE_EXTRACT_INTERVAL = 1.0
INTERFACE = "en0"

model = joblib.load("/Users/wahba/Library/Mobile Documents/com~apple~CloudDocs/others/nids3/models/xgb.joblib")

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
# FLOW STORAGE
# ====================================================
flow_stats = defaultdict(lambda: {
    'start_time': None, 'end_time': None, 'last_detection_time': None,
    'fwd_packets': 0, 'bwd_packets': 0, 'fwd_bytes': 0, 'bwd_bytes': 0,
    'fwd_packet_sizes': deque(maxlen=100), 'bwd_packet_sizes': deque(maxlen=100),
    'packet_sizes': deque(maxlen=100), 'fwd_iat': deque(maxlen=100),
    'bwd_iat': deque(maxlen=100), 'flow_iat': deque(maxlen=100),
    'fin_flags': 0, 'psh_flags': 0, 'ack_flags': 0,
    'fwd_header_bytes': 0, 'bwd_header_bytes': 0,
    'fwd_win_bytes': None, 'bwd_win_bytes': None,
    'active_times': deque(maxlen=100), 'idle_times': deque(maxlen=100),
    'last_packet_time': None, 'last_fwd_packet_time': None, 'last_bwd_packet_time': None,
    'min_seg_size_forward': float('inf'),
    'active': False, 'active_start': None, 'idle_start': None,
    'fwd_data_packets': 0,
    'features': {feature: 0 for feature in required_features}
})

# ====================================================
# ANOMALY DETECTION
# ====================================================
def anomaly_detector(flow):
    X = pd.DataFrame(
        [[flow['features'][feature] for feature in required_features[:-1]]],
        columns=required_features[:-1]
    )
    # X = np.array([flow['features'][feature] for feature in required_features[:-1]]).reshape(1, -1)
    # Use a high-resolution monotonic clock for elapsed timing
    start_time = time.perf_counter()
    pred = model.predict(X)
    total_time = time.perf_counter() - start_time
    # convert to milliseconds for reporting
    total_time_ms = total_time * 1000.0
    return pred[0], total_time_ms

# ====================================================
# FEATURE EXTRACTOR
# ====================================================
def feature_extractor(flow_key, log_widget):
    flow = flow_stats[flow_key]
    # Use perf_counter for elapsed measurements (monotonic, high-res)
    current_time = time.perf_counter()
    flow['end_time'] = current_time
    # Ensure start_time was recorded using perf_counter as well
    duration = max(current_time - flow['start_time'], 0.001) if flow['start_time'] is not None else 0.001

    # Simplified subset for clarity
    flow['features']['Flow Duration'] = duration
    flow['features']['Flow Bytes/s'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / duration
    flow['features']['Flow Packets/s'] = (flow['fwd_packets'] + flow['bwd_packets']) / duration
    flow['features']['Total Fwd Packets'] = flow['fwd_packets']
    flow['features']['Total Length of Fwd Packets'] = flow['fwd_bytes']
    flow['features']['Attack Type'] = "Benign"

    # Predict
    prediction, time_taken_ms = anomaly_detector(flow)

    # Update GUI log (show prediction latency in ms)
    log_widget.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] Flow {flow_key} → {prediction} - {time_taken_ms:.3f} ms\n")
    log_widget.see(tk.END)

# ====================================================
# PACKET PARSER
# ====================================================
def packet_parser(packet, log_widget):
    if IP not in packet:
        return
    src_ip, dst_ip = packet[IP].src, packet[IP].dst
    if TCP in packet:
        protocol = 'TCP'
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        protocol = 'UDP'
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport
    else:
        return

    # record times using perf_counter for elapsed calculations
    current_time = time.perf_counter()
    key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    flow = flow_stats[key]
    if flow['start_time'] is None:
        flow['start_time'] = current_time

    flow['fwd_packets'] += 1
    flow['fwd_bytes'] += len(packet)
    flow['end_time'] = current_time

    if flow['last_detection_time'] is None or (current_time - flow['last_detection_time'] > FEATURE_EXTRACT_INTERVAL):
        feature_extractor(key, log_widget)
        flow['last_detection_time'] = current_time

# ====================================================
# CAPTURE THREAD
# ====================================================
capturing = False

def capture_packets(log_widget):
    global capturing
    capturing = True
    log_widget.insert(tk.END, "[*] Started capturing packets...\n")
    sniff(iface=INTERFACE, prn=lambda pkt: packet_parser(pkt, log_widget), store=False, stop_filter=lambda _: not capturing)
    log_widget.insert(tk.END, "[!] Capture stopped.\n")

def stop_capture():
    global capturing
    capturing = False

# ====================================================
# GUI SETUP
# ====================================================
def start_gui():
    process = psutil.Process()  # This process (the NIDS itself)

    def update_process_usage():
        while True:
            try:
                # CPU usage (%) of this process only
                cpu_usage = process.cpu_percent(interval=1)

                # Memory usage (in MB and %)
                mem_info = process.memory_info()
                mem_usage_mb = mem_info.rss / (1024 * 1024)
                mem_percent = process.memory_percent()

                # Battery / Power info
                battery = psutil.sensors_battery()
                if battery:
                    power_text = f"Battery: {battery.percent:.0f}% ({'Plugged In' if battery.power_plugged else 'On Battery'})"
                else:
                    power_text = "Power: N/A"

                # Update GUI labels
                cpu_label.config(text=f"CPU: {cpu_usage:.1f}%")
                mem_label.config(text=f"Memory: {mem_usage_mb:.1f} MB ({mem_percent:.1f}%)")
                power_label.config(text=power_text)
            except Exception as e:
                cpu_label.config(text=f"CPU: Error")
                mem_label.config(text=f"Memory: Error")
                power_label.config(text="Power: Error")

            time.sleep(2)

    root = tk.Tk()
    root.title("Lightweight NIDS Monitor")
    root.geometry("650x450")

    ttk.Label(root, text="Lightweight NIDS Monitor", font=("Segoe UI", 14, "bold")).pack(pady=5)

    ttk.Label(root, text="Network Interface:").pack(pady=3)
    interface_entry = ttk.Entry(root)
    interface_entry.insert(0, INTERFACE)
    interface_entry.pack()

    # === Process Usage Section ===
    sys_frame = ttk.Frame(root)
    sys_frame.pack(pady=5)

    cpu_label = ttk.Label(sys_frame, text="CPU: --%", font=("Consolas", 10))
    cpu_label.pack(side=tk.LEFT, padx=10)

    mem_label = ttk.Label(sys_frame, text="Memory: --%", font=("Consolas", 10))
    mem_label.pack(side=tk.LEFT, padx=10)

    power_label = ttk.Label(sys_frame, text="Power: --", font=("Consolas", 10))
    power_label.pack(side=tk.LEFT, padx=10)

    # === Log widget ===
    log_widget = tk.Text(root, height=18, bg="black", fg="lime", insertbackground="white")
    log_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # === Buttons ===
    button_frame = ttk.Frame(root)
    button_frame.pack(pady=10)

    start_btn = ttk.Button(
        button_frame,
        text="Start Capture",
        command=lambda: threading.Thread(target=capture_packets, args=(log_widget,), daemon=True).start()
    )
    start_btn.pack(side=tk.LEFT, padx=5)

    stop_btn = ttk.Button(button_frame, text="Stop Capture", command=stop_capture)
    stop_btn.pack(side=tk.LEFT, padx=5)

    exit_btn = ttk.Button(button_frame, text="Exit", command=root.destroy)
    exit_btn.pack(side=tk.LEFT, padx=5)

    # Start process usage monitor thread
    threading.Thread(target=update_process_usage, daemon=True).start()

    root.mainloop()

# ====================================================
# MAIN
# ====================================================
if __name__ == "__main__":
    start_gui()
