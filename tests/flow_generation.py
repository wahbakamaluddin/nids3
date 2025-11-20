from scapy.all import sniff, IP, TCP, UDP
import numpy as np
import pandas as pd
from collections import defaultdict, deque
import time


TIME_WINDOW = 60
ACTIVITY_TIMEOUT = 5
CLEANUP_INTERVAL = 120
exported_rows = []

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
            'last_active_time': None,
            'last_idle_time': None,
            'active_start': None,
            'idle_start': None,
            'last_packet_time': None,
            'last_fwd_packet_time': None,
            'last_bwd_packet_time': None,
            'min_seg_size_forward': float('inf'),
            'active': False,
            'fwd_data_packets': 0,
        })

def packet_handler(packet):
            
        # Time window for flow aggregation (in seconds)
        time_window = TIME_WINDOW
        # Activity timeout (in seconds)
        activity_timeout = ACTIVITY_TIMEOUT

        """Process a single packet and update flow statistics"""
        if IP not in packet:
            return
        
        # total_packets_processed += 1
        
        # Extract IP addresses
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Determine protocol and ports
        if TCP in packet:
            protocol = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            header_length = len(packet[TCP])
            
            # Extract window size
            if hasattr(packet[TCP], 'window'):
                window_size = packet[TCP].window
            else:
                window_size = 0
                
        elif UDP in packet:
            protocol = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            header_length = len(packet[UDP])
            window_size = 0
        
        else:
            # Skip non-TCP/UDP packets
            return
        
        # Create directional flow keys (src->dst and dst->src)
        forward_key = f"{ip_src}:{src_port}-{ip_dst}:{dst_port}-{protocol}"
        backward_key = f"{ip_dst}:{dst_port}-{ip_src}:{src_port}-{protocol}"
        
        # Determine flow direction
        packet_size = len(packet)
        current_time = time.time()
        is_forward = True
        
        # Check if this is part of an existing flow
        if forward_key in flow_stats:
            flow_key = forward_key
        elif backward_key in flow_stats:
            flow_key = backward_key
            is_forward = False
        else:
            # New flow, use forward key
            flow_key = forward_key
        
        # Get flow statistics
        flow = flow_stats[flow_key]
        
        # Initialize flow if this is the first packet
        if flow['start_time'] is None:
            flow['start_time'] = current_time
            flow['active_start'] = current_time
            flow['active'] = True
        
        # Update flow end time
        flow['end_time'] = current_time
        
        # Calculate and store inter-arrival time
        if flow['last_packet_time'] is not None:
            iat = current_time - flow['last_packet_time']
            flow['flow_iat'].append(iat)
            
            # Check if it is needed to update active/idle times
            if iat > activity_timeout:
                if flow['active_start'] is not None:
                    active_time = flow['last_packet_time'] - flow['active_start']
                    flow['active_times'].append(active_time)
                    flow['active_start'] = None
                    flow['idle_start'] = flow['last_packet_time']
                
                if flow['idle_start'] is not None:
                    idle_time = current_time - flow['idle_start']
                    flow['idle_times'].append(idle_time)
                    flow['idle_start'] = None
                
                flow['active_start'] = current_time
                flow['active'] = True
            
        flow['last_packet_time'] = current_time
        
        # Update direction-specific statistics
        if is_forward:
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += packet_size
            flow['packet_sizes'].append(packet_size)
            flow['fwd_packet_sizes'].append(packet_size)
            
            if protocol == 'TCP':
                if packet[TCP].flags & 0x08:  # PSH flag
                    flow['fwd_psh_flags'] += 1
                    flow['psh_flags'] += 1
                
                if packet[TCP].flags & 0x20:  # URG flag
                    flow['fwd_urg_flags'] += 1
                    flow['urg_flags'] += 1
                
                if hasattr(packet[TCP], 'flags'):
                    if packet[TCP].flags & 0x01:  # FIN flag
                        flow['fin_flags'] += 1
                    if packet[TCP].flags & 0x02:  # SYN flag
                        flow['syn_flags'] += 1
                    if packet[TCP].flags & 0x04:  # RST flag
                        flow['rst_flags'] += 1
                    if packet[TCP].flags & 0x10:  # ACK flag
                        flow['ack_flags'] += 1
                    if packet[TCP].flags & 0x40:  # ECE flag
                        flow['ece_flags'] += 1
                
                # Update min_seg_size_forward
                if hasattr(packet[TCP], 'options'):
                    mss = next((x[1] for x in packet[TCP].options if x[0] == 'MSS'), None)
                    if mss is not None and mss < flow['min_seg_size_forward']:
                        flow['min_seg_size_forward'] = mss
            
            flow['fwd_header_bytes'] += header_length
            
            # Store initial window size
            if flow['fwd_win_bytes'] is None and window_size > 0:
                flow['fwd_win_bytes'] = window_size
            
            # Check if this is a data packet
            if TCP in packet and len(packet[TCP].payload) > 0:
                flow['fwd_data_packets'] += 1
            
            # Update IAT for forward packets
            if flow['last_fwd_packet_time'] is not None:
                flow['fwd_iat'].append(current_time - flow['last_fwd_packet_time'])
            flow['last_fwd_packet_time'] = current_time
            
        else:
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += packet_size
            flow['packet_sizes'].append(packet_size)
            flow['bwd_packet_sizes'].append(packet_size)
            flow['bwd_header_bytes'] += header_length
            
            # Store initial window size
            if flow['bwd_win_bytes'] is None and window_size > 0:
                flow['bwd_win_bytes'] = window_size
            
            # Update IAT for backward packets
            if flow['last_bwd_packet_time'] is not None:
                flow['bwd_iat'].append(current_time - flow['last_bwd_packet_time'])
            flow['last_bwd_packet_time'] = current_time
        
        print(f"Received {flow_key}")

        # Check if it is time to detect anomalies
        if flow['last_detection_time'] is None \
            and current_time - flow['start_time'] >= time_window \
            and flow['fwd_packets'] + flow['bwd_packets'] >= 3:
            # First detection after time window
            detect_anomalies(flow_key)
        
        elif flow['last_detection_time'] is not None \
            and current_time - flow['last_detection_time'] >= time_window \
            and flow['fwd_packets'] + flow['bwd_packets'] >= 3:
            # Subsequent detections based on last detection time
            detect_anomalies(flow_key)

def extract_features(flow_key):
        flow = flow_stats[flow_key]

       # Calculate flow duration
        duration = flow['end_time'] - flow['start_time']
        if duration <= 0:  # Avoid division by zero
            duration = 0.001
        
        # Initialize features dictionary
        features = {}
        
        # Get destination port from flow key
        parts = flow_key.split('-')
        if len(parts) >= 2:
            try:
                dst_part = parts[0].split(':')[1] if ':' in parts[0] else parts[1].split(':')[1]
                features['Destination Port'] = int(dst_part)
            except:
                features['Destination Port'] = 0
        else:
            features['Destination Port'] = 0
            
        # Basic flow features
        features['Flow Duration'] = duration * 1000  # Convert to milliseconds
        features['Flow Bytes/s'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / duration
        features['Flow Packets/s'] = (flow['fwd_packets'] + flow['bwd_packets']) / duration
        
        # Forward packet features
        features['Total Fwd Packets'] = flow['fwd_packets']
        features['Total Length of Fwd Packets'] = flow['fwd_bytes']
        features['Fwd Packet Length Min'] = min(flow['fwd_packet_sizes']) if flow['fwd_packet_sizes'] else 0
        features['Fwd Packet Length Max'] = max(flow['fwd_packet_sizes']) if flow['fwd_packet_sizes'] else 0
        features['Fwd Packet Length Mean'] = np.mean(flow['fwd_packet_sizes']) if flow['fwd_packet_sizes'] else 0
        features['Fwd Packet Length Std'] = np.std(flow['fwd_packet_sizes']) if len(flow['fwd_packet_sizes']) > 1 else 0
        features['Fwd Packets/s'] = flow['fwd_packets'] / duration
        features['Fwd Header Length'] = flow['fwd_header_bytes']
        
        # Backward packet features
        features['Bwd Packets/s'] = flow['bwd_packets'] / duration
        features['Bwd Packet Length Min'] = min(flow['bwd_packet_sizes']) if flow['bwd_packet_sizes'] else 0
        features['Bwd Packet Length Max'] = max(flow['bwd_packet_sizes']) if flow['bwd_packet_sizes'] else 0
        features['Bwd Packet Length Mean'] = np.mean(flow['bwd_packet_sizes']) if flow['bwd_packet_sizes'] else 0
        features['Bwd Packet Length Std'] = np.std(flow['bwd_packet_sizes']) if len(flow['bwd_packet_sizes']) > 1 else 0
        features['Bwd Header Length'] = flow['bwd_header_bytes']
        
        # Packet length features
        features['Min Packet Length'] = min(flow['packet_sizes']) if flow['packet_sizes'] else 0
        features['Max Packet Length'] = max(flow['packet_sizes']) if flow['packet_sizes'] else 0
        features['Packet Length Mean'] = np.mean(flow['packet_sizes']) if flow['packet_sizes'] else 0
        features['Packet Length Std'] = np.std(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0
        features['Packet Length Variance'] = np.var(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0
        
        # Average packet size
        total_packets = flow['fwd_packets'] + flow['bwd_packets']
        if total_packets > 0:
            features['Average Packet Size'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / total_packets
        else:
            features['Average Packet Size'] = 0
        
        # IAT (Inter Arrival Time) features
        if flow['flow_iat']:
            features['Flow IAT Mean'] = np.mean(flow['flow_iat'])
            features['Flow IAT Std'] = np.std(flow['flow_iat']) if len(flow['flow_iat']) > 1 else 0
            features['Flow IAT Max'] = max(flow['flow_iat'])
            features['Flow IAT Min'] = min(flow['flow_iat'])
        else:
            features['Flow IAT Mean'] = 0
            features['Flow IAT Std'] = 0
            features['Flow IAT Max'] = 0
            features['Flow IAT Min'] = 0
        
        # Forward IAT
        if flow['fwd_iat']:
            features['Fwd IAT Total'] = sum(flow['fwd_iat'])
            features['Fwd IAT Mean'] = np.mean(flow['fwd_iat'])
            features['Fwd IAT Std'] = np.std(flow['fwd_iat']) if len(flow['fwd_iat']) > 1 else 0
            features['Fwd IAT Max'] = max(flow['fwd_iat'])
            features['Fwd IAT Min'] = min(flow['fwd_iat'])
        else:
            features['Fwd IAT Total'] = 0
            features['Fwd IAT Mean'] = 0
            features['Fwd IAT Std'] = 0
            features['Fwd IAT Max'] = 0
            features['Fwd IAT Min'] = 0
        
        # Backward IAT
        if flow['bwd_iat']:
            features['Bwd IAT Total'] = sum(flow['bwd_iat'])
            features['Bwd IAT Mean'] = np.mean(flow['bwd_iat'])
            features['Bwd IAT Std'] = np.std(flow['bwd_iat']) if len(flow['bwd_iat']) > 1 else 0
            features['Bwd IAT Max'] = max(flow['bwd_iat'])
            features['Bwd IAT Min'] = min(flow['bwd_iat'])
        else:
            features['Bwd IAT Total'] = 0
            features['Bwd IAT Mean'] = 0
            features['Bwd IAT Std'] = 0
            features['Bwd IAT Max'] = 0
            features['Bwd IAT Min'] = 0
        
        # Flag counts
        features['PSH Flag Count'] = flow['psh_flags']
        features['FIN Flag Count'] = flow['fin_flags']
        features['ACK Flag Count'] = flow['ack_flags']
        
        # Window features
        features['Init_Win_bytes_forward'] = flow['fwd_win_bytes'] if flow['fwd_win_bytes'] is not None else 0
        features['Init_Win_bytes_backward'] = flow['bwd_win_bytes'] if flow['bwd_win_bytes'] is not None else 0
        
        # Active and idle time statistics
        if flow['active_times']:
            features['Active Mean'] = np.mean(flow['active_times'])
            features['Active Max'] = max(flow['active_times'])
            features['Active Min'] = min(flow['active_times'])
        else:
            features['Active Mean'] = 0
            features['Active Max'] = 0
            features['Active Min'] = 0
        
        if flow['idle_times']:
            features['Idle Mean'] = np.mean(flow['idle_times'])
            features['Idle Max'] = max(flow['idle_times'])
            features['Idle Min'] = min(flow['idle_times'])
        else:
            features['Idle Mean'] = 0
            features['Idle Max'] = 0
            features['Idle Min'] = 0
        
        # Additional features
        features['min_seg_size_forward'] = flow['min_seg_size_forward'] if flow['min_seg_size_forward'] != float('inf') else 0
        features['act_data_pkt_fwd'] = flow['fwd_data_packets']
        
        # Calculate Subflow statistics
        features['Subflow Fwd Bytes'] = flow['fwd_bytes']
            
        return features

def detect_anomalies(flow_key):
    global exported_rows
    features = extract_features(flow_key)

    print(f"Extracted features for flow {flow_key}")

    exported_rows.append(features)
    flow_stats[flow_key]['last_detection_time'] = time.time()

    if len(exported_rows) %50 == 0:
        save_to_csv()

def save_to_csv(output_file="/home/wahba/Documents/nids3/tests/flow/flow_tuesday_flow_generation.csv"):
    global exported_rows

    df = pd.DataFrame(exported_rows)
    df.to_csv(output_file, index=False)
    print(f"Saved {len(exported_rows)} rows to {output_file}")

sniff(iface="dummy0", filter="tcp or udp", prn=packet_handler, store=0)