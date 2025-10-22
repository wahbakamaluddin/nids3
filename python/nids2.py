'''
Features required by model:

Index(['Destination Port', 'Flow Duration', 'Total Fwd Packets',
       'Total Length of Fwd Packets', 'Fwd Packet Length Max',
       'Fwd Packet Length Min', 'Fwd Packet Length Mean',
       'Fwd Packet Length Std', 'Bwd Packet Length Max',
       'Bwd Packet Length Min', 'Bwd Packet Length Mean',
       'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
       'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
       'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
       'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
       'Bwd IAT Max', 'Bwd IAT Min', 'Fwd Header Length', 'Bwd Header Length',
       'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length',
       'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
       'Packet Length Variance', 'FIN Flag Count', 'PSH Flag Count',
       'ACK Flag Count', 'Average Packet Size', 'Subflow Fwd Bytes',
       'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
       'min_seg_size_forward', 'Active Mean', 'Active Max', 'Active Min',
       'Idle Mean', 'Idle Max', 'Idle Min', 'Attack Type'],
      dtype='object')

'''

from scapy.all import *
import numpy as np

# Declare a dictionary to store flow statistcs
# defaultdict() will add a new entry based on provided value if the key being called is not defined
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
        'features': {
            'Destination Port':0,
            'Flow Duration':0,
            'Flow Bytes/s':0,
            'Flow Packets/s':0,
            'Total Fwd Packets':0,
            'Total Length of Fwd Packets':0,
            'Fwd Packet Length Min':0,
            'Fwd Packet Length Max':0,
            'Fwd Packet Length Mean':0,
            'Fwd Packet Length Std':0,
            'Fwd Packets/s':0,
            'Bwd Packets/s': 0,
            'Min Packet Length': 0,
            'Max Packet Length': 0, 
            'Packet Length Mean': 0, 
            'Packet Length Std': 0,
            'Packet Length Variance': 0,
            'FIN Flag Count': 0, 
            'PSH Flag Count': 0,
            'ACK Flag Count': 0, 
            'Average Packet Size': 0,
            'Subflow Fwd Bytes': 0,
            'Init_Win_bytes_forward': 0,
            'Init_Win_bytes_backward': 0,
            'act_data_pkt_fwd': 0,
            'min_seg_size_forward': 0,
            'Active Mean': 0, 
            'Active Max': 0,
            'Active Min': 0,
            'Idle Mean': 0, 
            'Idle Max': 0, 
            'Idle Min': 0, 
        }
        })

def anomaly_detector(flow):
    ff

def feature_extractor(flow_key):
    flow = flow_stats[flow_key]

    # Calculate flow duration
    duration = flow['end_time'] - flow['start_time']
    if duration <= 0:  # Avoid division by zero
        duration = 0.001
        
    # Get destination port from flow key
    parts = flow_key.split('-')
    if len(parts) >= 2:
        try:
            dst_part = parts[0].split(':')[1] if ':' in parts[0] else parts[1].split(':')[1]
            flow['features']['Destination Port'] = int(dst_part)
        except:
            flow['features']['Destination Port'] = 0
    else:
        flow['features']['Destination Port'] = 0

    # Basic flow flow['features']
        flow['features']['Flow Duration'] = duration * 1000  # Convert to milliseconds
        flow['features']['Flow Bytes/s'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / duration
        flow['features']['Flow Packets/s'] = (flow['fwd_packets'] + flow['bwd_packets']) / duration
        
        # Forward packet flow['features']
        flow['features']['Total Fwd Packets'] = flow['fwd_packets']
        flow['features']['Total Length of Fwd Packets'] = flow['fwd_bytes']
        flow['features']['Fwd Packet Length Min'] = min(flow['fwd_packet_sizes']) if flow['fwd_packet_sizes'] else 0
        flow['features']['Fwd Packet Length Max'] = max(flow['fwd_packet_sizes']) if flow['fwd_packet_sizes'] else 0
        flow['features']['Fwd Packet Length Mean'] = np.mean(flow['fwd_packet_sizes']) if flow['fwd_packet_sizes'] else 0
        flow['features']['Fwd Packet Length Std'] = np.std(flow['fwd_packet_sizes']) if len(flow['fwd_packet_sizes']) > 1 else 0
        flow['features']['Fwd Packets/s'] = flow['fwd_packets'] / duration
        flow['features']['Fwd Header Length'] = flow['fwd_header_bytes']
        
        # Backward packet flow['features']
        flow['features']['Bwd Packets/s'] = flow['bwd_packets'] / duration
        flow['features']['Bwd Packet Length Min'] = min(flow['bwd_packet_sizes']) if flow['bwd_packet_sizes'] else 0
        flow['features']['Bwd Packet Length Max'] = max(flow['bwd_packet_sizes']) if flow['bwd_packet_sizes'] else 0
        flow['features']['Bwd Packet Length Mean'] = np.mean(flow['bwd_packet_sizes']) if flow['bwd_packet_sizes'] else 0
        flow['features']['Bwd Packet Length Std'] = np.std(flow['bwd_packet_sizes']) if len(flow['bwd_packet_sizes']) > 1 else 0
        flow['features']['Bwd Header Length'] = flow['bwd_header_bytes']
        
        # Packet length flow['features']
        flow['features']['Min Packet Length'] = min(flow['packet_sizes']) if flow['packet_sizes'] else 0
        flow['features']['Max Packet Length'] = max(flow['packet_sizes']) if flow['packet_sizes'] else 0
        flow['features']['Packet Length Mean'] = np.mean(flow['packet_sizes']) if flow['packet_sizes'] else 0
        flow['features']['Packet Length Std'] = np.std(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0
        flow['features']['Packet Length Variance'] = np.var(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0
        
        # Average packet size
        total_packets = flow['fwd_packets'] + flow['bwd_packets']
        if total_packets > 0:
            flow['features']['Average Packet Size'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / total_packets
        else:
            flow['features']['Average Packet Size'] = 0
        
        # IAT (Inter Arrival Time) flow['features']
        if flow['flow_iat']:
            flow['features']['Flow IAT Mean'] = np.mean(flow['flow_iat'])
            flow['features']['Flow IAT Std'] = np.std(flow['flow_iat']) if len(flow['flow_iat']) > 1 else 0
            flow['features']['Flow IAT Max'] = max(flow['flow_iat'])
            flow['features']['Flow IAT Min'] = min(flow['flow_iat'])
        else:
            flow['features']['Flow IAT Mean'] = 0
            flow['features']['Flow IAT Std'] = 0
            flow['features']['Flow IAT Max'] = 0
            flow['features']['Flow IAT Min'] = 0
        
        # Forward IAT
        if flow['fwd_iat']:
            flow['features']['Fwd IAT Total'] = sum(flow['fwd_iat'])
            flow['features']['Fwd IAT Mean'] = np.mean(flow['fwd_iat'])
            flow['features']['Fwd IAT Std'] = np.std(flow['fwd_iat']) if len(flow['fwd_iat']) > 1 else 0
            flow['features']['Fwd IAT Max'] = max(flow['fwd_iat'])
            flow['features']['Fwd IAT Min'] = min(flow['fwd_iat'])
        else:
            flow['features']['Fwd IAT Total'] = 0
            flow['features']['Fwd IAT Mean'] = 0
            flow['features']['Fwd IAT Std'] = 0
            flow['features']['Fwd IAT Max'] = 0
            flow['features']['Fwd IAT Min'] = 0
        
        # Backward IAT
        if flow['bwd_iat']:
            flow['features']['Bwd IAT Total'] = sum(flow['bwd_iat'])
            flow['features']['Bwd IAT Mean'] = np.mean(flow['bwd_iat'])
            flow['features']['Bwd IAT Std'] = np.std(flow['bwd_iat']) if len(flow['bwd_iat']) > 1 else 0
            flow['features']['Bwd IAT Max'] = max(flow['bwd_iat'])
            flow['features']['Bwd IAT Min'] = min(flow['bwd_iat'])
        else:
            flow['features']['Bwd IAT Total'] = 0
            flow['features']['Bwd IAT Mean'] = 0
            flow['features']['Bwd IAT Std'] = 0
            flow['features']['Bwd IAT Max'] = 0
            flow['features']['Bwd IAT Min'] = 0
        
        # Flag counts
        flow['features']['PSH Flag Count'] = flow['psh_flags']
        flow['features']['FIN Flag Count'] = flow['fin_flags']
        flow['features']['ACK Flag Count'] = flow['ack_flags']
        
        # Window flow['features']
        flow['features']['Init_Win_bytes_forward'] = flow['fwd_win_bytes'] if flow['fwd_win_bytes'] is not None else 0
        flow['features']['Init_Win_bytes_backward'] = flow['bwd_win_bytes'] if flow['bwd_win_bytes'] is not None else 0
        
        # Active and idle time statistics
        if flow['active_times']:
            flow['features']['Active Mean'] = np.mean(flow['active_times'])
            flow['features']['Active Max'] = max(flow['active_times'])
            flow['features']['Active Min'] = min(flow['active_times'])
        else:
            flow['features']['Active Mean'] = 0
            flow['features']['Active Max'] = 0
            flow['features']['Active Min'] = 0
        
        if flow['idle_times']:
            flow['features']['Idle Mean'] = np.mean(flow['idle_times'])
            flow['features']['Idle Max'] = max(flow['idle_times'])
            flow['features']['Idle Min'] = min(flow['idle_times'])
        else:
            flow['features']['Idle Mean'] = 0
            flow['features']['Idle Max'] = 0
            flow['features']['Idle Min'] = 0
        
        # Additional flow['features']
        flow['features']['min_seg_size_forward'] = flow['min_seg_size_forward'] if flow['min_seg_size_forward'] != float('inf') else 0
        flow['features']['act_data_pkt_fwd'] = flow['fwd_data_packets']
        
        # Calculate Subflow statistics
        flow['features']['Subflow Fwd Bytes'] = flow['fwd_bytes']
    
    print(flow_key, flow['features'])
    # return flow['features']    

def packet_parser(packet):

    if IP not in packet:
        return
    # Extract network flow identifier components:
    
    # Extract source IP and destination IP
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

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
        return
    
    # Get packet_length and current time
    packet_size = len(packet)
    current_time = time.time()
    
    # Generate flow identifier (key) as 5-tuple network flow
    forward_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}" # src = initator, dst = responder
    backward_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

    # Check if this packet belongs to an existing flow (either direction)
    if forward_key in flow_stats:
        flow_key = forward_key
        is_forward = True
    elif backward_key in flow_stats:
        flow_key = backward_key
        is_forward = False
    else:
        # New flow - use forward key as canonical identifier
        flow_key = forward_key
        is_forward = True

    # Get flow statistics
    flow = flow_stats[flow_key]

    # Initialize flow if this is the first paket
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
            
    flow['last_packet_time'] = current_time

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

    # If packet is backward (is_forward = False)       
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

    feature_extractor(flow_key)
    
def packet_capturer():
    sniff(iface='en0', prn=packet_parser) # prn is the fallback function for each captured packets

print(f"Value of __name__: {__name__}")

if __name__ == "__main__":
    packet_capturer()