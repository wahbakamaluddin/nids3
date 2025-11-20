import psutil
import threading
import time
from collections import defaultdict, deque

import joblib
import numpy as np
import pandas as pd
from scapy.all import IP, TCP, UDP, sniff

REQUIRED_FEATURES = [
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
    'Idle Mean', 'Idle Max', 'Idle Min'
]
# Declare a dictionary to store flow statistcs
# defaultdict() will add a new entry based on provided value if the key being called is not defined
FLOW_STATS = defaultdict(lambda: {
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
})

class NIDSEngine:
    """Network Intrusion Detection System engine for real-time traffic analysis."""

    def __init__(
            self, 
            interface='en0', 
            model_path='/Users/wahba/Library/Mobile Documents/com~apple~CloudDocs/others/nids3/models/xgb.joblib', 
            on_log=None, 
            on_throughput=None,
            on_resource_usage=None,
            flow_timeout=60,
            inactivity_threshold=1.0,
            feature_extract_interval=1.0
        ):
            """Initialize NIDS engine.
            
            Args:
                interface: Network interface to monitor
                model_path: Path to trained ML model
                on_log: Callback for log messages
                on_throughput: Callback for throughput updates
                flow_timeout: Seconds before cleaning up inactive flows
                inactivity_threshold: Seconds to consider flow idle
                feature_extract_interval: Seconds between feature extraction
            
            Raises:
                FileNotFoundError: If model_path does not exist
                Exception: If model loading fails
            """
            
            self.interface = interface
            self.model = joblib.load(model_path)
            self.on_log = on_log or (lambda msg: print(msg))
            self.on_throughput = on_throughput or (lambda throughput=0: None)
            self.on_resource_usage = on_resource_usage or (lambda cpu=0, mem=0: None)
            self.flow_timeout = flow_timeout
            self.inactivity_threshold = inactivity_threshold
            self.feature_extract_interval = feature_extract_interval
            self.flow_stats = FLOW_STATS
            self.required_features = REQUIRED_FEATURES
            
            self.capturing = False
            self.packet_count = 0
            self.prev_count = 0
    
    def start(self):
        """Start the NIDS packet capture and monitoring threads.
    
        Initializes three background threads:
        - Flow cleanup (removes stale flows)
        - Packet capture (main packet processing)
        - Throughput monitoring (performance tracking)
        - Resrouce usage monitoring (resoruce usage monitoring)
        """
        self.capturing = True
        threading.Thread(target=self._packet_capturer, daemon=True).start()
        threading.Thread(target=self._cleanup_flows, daemon=True).start()
        threading.Thread(target=self._throughput_monitor, daemon=True).start()
        threading.Thread(target=self._resource_usage_monitor, daemon=True).start()

    def stop(self):
        """Stop all NIDS operations and background threads.
            
        Sets capturing flag to False, which stops packet capture
        and monitoring threads on their next iteration.
        """
        self.capturing = False

    def _anomaly_detector(self, flow_key, features):
        """Detect network anomalies using trained ML model.

        Converts extracted features to DataFrame format and runs inference
        with the trained model to classify network flow behavior.
        
        Args:
            flow_key (str): Unique identifier for the network flow
            features (dict): Dictionary of extracted flow features
            
        Logs:
            Prediction results with timestamp and processing time
            Errors if model inference fails
            
        Note:
            Uses high-resolution timer to measure prediction latency
        """
        X = pd.DataFrame(
            [[features[feature] for feature in self.required_features]],
            columns=self.required_features
        )

        try:
            X = pd.DataFrame(
                [[features[feature] for feature in self.required_features]],
                columns=self.required_features
            )
            
            # start_time = time.perf_counter()
            # pred = self.model.predict(X)
            # total_time_ms = (time.perf_counter() - start_time) * 1000
            
            start_time = time.time()
            prediction_probabilities = self.model.predict_proba(X)
            prediction_label = self.model.classes_[prediction_probabilities.argmax()]
            prediction_confidence = prediction_probabilities.max()
            total_time_ms = (time.time() - start_time) * 1000


            # msg = f"[{time.strftime('%H:%M:%S')}] Flow {flow_key} → {pred[0]} ({total_time_ms:.2f} ms)"
            # self.on_log(msg)
            self.on_log(flow_key, prediction_label, prediction_confidence, total_time_ms)
            
        except Exception as e:
            self.on_log(f"Detection error for {flow_key}: {str(e)}")

    def _feature_extractor(self, flow_key):
        """Extract machine learning features from network flow statistics.
            
            Calculates 50+ statistical features including timing, packet sizes,
            protocol flags, and flow characteristics required by the ML model.
            
            Args:
                flow_key (str): Unique identifier for the network flow
                
            Returns:
                dict: Complete feature dictionary ready for model inference
                
            Note:
                Handles edge cases for empty statistics and division by zero
                Converts deques to lists once for efficient computation
            """
        flow = self.flow_stats[flow_key]
        features = {}

        duration = flow['end_time'] - flow['start_time']
        if duration <= 0:
            duration = 0.001

        # Parse destination port
        parts = flow_key.split('-')
        try:
            dst_part = parts[0].split(':')[1] if ':' in parts[0] else parts[1].split(':')[1]
            features['Destination Port'] = int(dst_part)
        except:
            features['Destination Port'] = 0

        # Flow duration and rates
        features['Flow Duration'] = duration
        features['Flow Bytes/s'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / duration
        features['Flow Packets/s'] = (flow['fwd_packets'] + flow['bwd_packets']) / duration

        # Forward features
        fwd_sizes = flow['fwd_packet_sizes']
        features['Total Fwd Packets'] = flow['fwd_packets']
        features['Total Length of Fwd Packets'] = flow['fwd_bytes']
        features['Fwd Packet Length Min'] = min(fwd_sizes) if fwd_sizes else 0
        features['Fwd Packet Length Max'] = max(fwd_sizes) if fwd_sizes else 0
        features['Fwd Packet Length Mean'] = np.mean(fwd_sizes) if fwd_sizes else 0
        features['Fwd Packet Length Std'] = np.std(fwd_sizes) if len(fwd_sizes) > 1 else 0
        features['Fwd Packets/s'] = flow['fwd_packets'] / duration
        features['Fwd Header Length'] = flow['fwd_header_bytes']

        # Backward features
        bwd_sizes = flow['bwd_packet_sizes']
        features['Bwd Packets/s'] = flow['bwd_packets'] / duration
        features['Bwd Packet Length Min'] = min(bwd_sizes) if bwd_sizes else 0
        features['Bwd Packet Length Max'] = max(bwd_sizes) if bwd_sizes else 0
        features['Bwd Packet Length Mean'] = np.mean(bwd_sizes) if bwd_sizes else 0
        features['Bwd Packet Length Std'] = np.std(bwd_sizes) if len(bwd_sizes) > 1 else 0
        features['Bwd Header Length'] = flow['bwd_header_bytes']

        # Packet length stats
        pkt_sizes = flow['packet_sizes']
        features['Min Packet Length'] = min(pkt_sizes) if pkt_sizes else 0
        features['Max Packet Length'] = max(pkt_sizes) if pkt_sizes else 0
        features['Packet Length Mean'] = np.mean(pkt_sizes) if pkt_sizes else 0
        features['Packet Length Std'] = np.std(pkt_sizes) if len(pkt_sizes) > 1 else 0
        features['Packet Length Variance'] = np.var(pkt_sizes) if len(pkt_sizes) > 1 else 0

        # Average packet size
        total_pkts = flow['fwd_packets'] + flow['bwd_packets']
        features['Average Packet Size'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / total_pkts if total_pkts > 0 else 0

        # IAT stats - convert deque to list once for multiple operations
        flow_iat_list = list(flow['flow_iat'])
        features['Flow IAT Mean'] = np.mean(flow_iat_list) if flow_iat_list else 0
        features['Flow IAT Std'] = np.std(flow_iat_list) if len(flow_iat_list) > 1 else 0
        features['Flow IAT Max'] = max(flow_iat_list) if flow_iat_list else 0
        features['Flow IAT Min'] = min(flow_iat_list) if flow_iat_list else 0

        # Forward IAT
        fwd_iat_list = list(flow['fwd_iat'])
        features['Fwd IAT Total'] = sum(fwd_iat_list) if fwd_iat_list else 0
        features['Fwd IAT Mean'] = np.mean(fwd_iat_list) if fwd_iat_list else 0
        features['Fwd IAT Std'] = np.std(fwd_iat_list) if len(fwd_iat_list) > 1 else 0
        features['Fwd IAT Max'] = max(fwd_iat_list) if fwd_iat_list else 0
        features['Fwd IAT Min'] = min(fwd_iat_list) if fwd_iat_list else 0

        # Backward IAT
        bwd_iat_list = list(flow['bwd_iat'])
        features['Bwd IAT Total'] = sum(bwd_iat_list) if bwd_iat_list else 0
        features['Bwd IAT Mean'] = np.mean(bwd_iat_list) if bwd_iat_list else 0
        features['Bwd IAT Std'] = np.std(bwd_iat_list) if len(bwd_iat_list) > 1 else 0
        features['Bwd IAT Max'] = max(bwd_iat_list) if bwd_iat_list else 0
        features['Bwd IAT Min'] = min(bwd_iat_list) if bwd_iat_list else 0

        # Flags
        features['FIN Flag Count'] = flow['fin_flags']
        features['PSH Flag Count'] = flow['psh_flags']
        features['ACK Flag Count'] = flow['ack_flags']

        # Window
        features['Init_Win_bytes_forward'] = flow['fwd_win_bytes'] or 0
        features['Init_Win_bytes_backward'] = flow['bwd_win_bytes'] or 0

        # Active/Idle stats
        active_list = list(flow['active_times'])
        features['Active Mean'] = np.mean(active_list) if active_list else 0
        features['Active Max'] = max(active_list) if active_list else 0
        features['Active Min'] = min(active_list) if active_list else 0

        idle_list = list(flow['idle_times'])
        features['Idle Mean'] = np.mean(idle_list) if idle_list else 0
        features['Idle Max'] = max(idle_list) if idle_list else 0
        features['Idle Min'] = min(idle_list) if idle_list else 0

        # Extra
        features['min_seg_size_forward'] = flow['min_seg_size_forward'] if flow['min_seg_size_forward'] != float('inf') else 0
        features['act_data_pkt_fwd'] = flow['fwd_data_packets']
        features['Subflow Fwd Bytes'] = flow['fwd_bytes']
            
        self._anomaly_detector(flow_key, features)

    def _packet_parser(self, packet):
        """Parse individual network packets and update flow statistics.
        
        Processes IP packets with TCP/UDP protocols, extracts flow identifiers,
        updates bidirectional counters, and manages flow state transitions.
        
        Args:
            packet: Scapy packet object containing raw network data
            
        Updates:
            - Flow timing information (IAT, duration)
            - Packet counters and byte totals
            - TCP flags and protocol features
            - Active/idle state transitions
            
        Note:
            Only processes IP packets; skips other protocols
            Creates new flows automatically for unseen connections
        """
        if IP not in packet:
            return
        self.packet_count += 1
        # Extract network flow identifier components:
        
        # Extract source IP and destination IP
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            protocol = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            header_length = len(packet[TCP])
            window_size = packet[TCP].window if hasattr(packet[TCP], 'window') else 0

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
        # 1 communication will produce 1 entry in flow_stats
        forward_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}" # src = initator, dst = responder
        backward_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

        # Check if this packet belongs to an existing flow (either direction)
        if forward_key in self.flow_stats:
            flow_key = forward_key
            is_forward = True
        elif backward_key in self.flow_stats:
            flow_key = backward_key
            is_forward = False
        else:
            # New flow - use forward key as canonical identifier
            flow_key = forward_key
            is_forward = True

        # Get flow statistics
        flow = self.flow_stats[flow_key]
        
        # Calculate and store inter-arrival time
        if flow['last_packet_time'] is not None:
            iat = current_time - flow['last_packet_time']
            flow['flow_iat'].append(iat)

        # Update timing information
        flow['last_packet_time'] = current_time 
        flow['end_time'] = current_time  # Always update end_time

        if flow['last_packet_time'] is not None and flow['flow_iat']:
            last_iat = flow['flow_iat'][-1]  # Use the most recent IAT
            
            if flow['active']:
                if last_iat > self.inactivity_threshold:
                    # Transition to idle
                    if flow['active_start'] is not None:
                        active_duration = current_time - flow['active_start']
                        flow['active_times'].append(active_duration)
                    flow['active'] = False
                    flow['idle_start'] = current_time
            else:
                if last_iat <= self.inactivity_threshold:
                    # Transition to active  
                    if flow['idle_start'] is not None:
                        idle_duration = current_time - flow['idle_start']
                        flow['idle_times'].append(idle_duration)
                    flow['active'] = True
                    flow['active_start'] = current_time

        # Initialize flow if this is the first packet
        if flow['start_time'] is None:
            flow['start_time'] = current_time
            flow['active_start'] = current_time
            flow['active'] = True
            
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
                if len(packet[TCP].payload) > 0:
                    flow['fwd_data_packets'] += 1

                # Update min_seg_size_forward
                if hasattr(packet[TCP], 'options'):
                    mss = next((x[1] for x in packet[TCP].options if x[0] == 'MSS'), None)
                    if mss is not None and mss < flow['min_seg_size_forward']:
                        flow['min_seg_size_forward'] = mss
            
            flow['fwd_header_bytes'] += header_length
            
            # Store initial window size
            if flow['fwd_win_bytes'] is None and window_size > 0:
                flow['fwd_win_bytes'] = window_size
            
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

        # call _feature_extractor()
        if (flow['last_detection_time'] is None) or (current_time - flow['last_detection_time'] > self.feature_extract_interval):
                self._feature_extractor(flow_key)
                flow['last_detection_time'] = current_time

    def _packet_capturer(self):
        """Main packet capture loop using Scapy sniff function.
        
        Continuously captures packets from the specified network interface
        and passes them to the packet parser for processing.
        
        Stops gracefully when capturing flag is set to False.
        
        Note:
            Runs in separate thread to avoid blocking main execution
            Uses store=False to minimize memory usage
        """
        sniff(iface=self.interface, prn=self._packet_parser, store=False, stop_filter=lambda _: not self.capturing) # prn is the fallback function for each captured packets

    def _cleanup_flows(self):
        """Periodically remove inactive flows to prevent memory leaks.
        
        Scans all active flows every 10 seconds and removes those that
        have exceeded the flow timeout period without activity.
        
        Note:
            Runs continuously in background thread
            Prevents unbounded memory growth from long-running flows
        """
        while True:
            now = time.time()
            for key in list(self.flow_stats.keys()):
                if self.flow_stats[key]['end_time'] and now - self.flow_stats[key]['end_time'] > self.flow_timeout:
                    del self.flow_stats[key]
            time.sleep(10)

    def _throughput_monitor(self):
        """Monitor and report packet processing throughput.
        
        Calculates packets processed per second by comparing packet counts
        at 1-second intervals and reports via callback function.
        
        Note:
            Runs in separate thread with 1-second sampling interval
            Provides real-time performance monitoring
        """
        while True:
            time.sleep(1)
            current_count = self.packet_count
            throughput = current_count - self.prev_count  # packets processed in the last second
            self.prev_count = current_count
            self.on_throughput(throughput)

    def _resource_usage_monitor(self):
        """Minimal resource monitoring with reduced overhead"""
        process = psutil.Process()
        
        while self.capturing:
            try:
                # Use longer interval to reduce overhead
                time.sleep(2)
                
                # Sample CPU over shorter interval to reduce active time
                cpu_usage = process.cpu_percent(interval=0.05)
                
                # Get memory (this is very fast)
                memory_info = process.memory_info()
                memory_usage_mb = memory_info.rss / (1024 * 1024)
                
                if self.on_resource_usage:
                    self.on_resource_usage(cpu_usage, memory_usage_mb)
                    
            except Exception:
                # Silent fail to avoid log overhead
                pass
        
if __name__ == "__main__":

    def log(flow_key, prediction_label, prediction_confidence, total_time_ms):
        print(f"[{time.strftime('%H:%M:%S')}] Flow {flow_key} → {prediction_label} {prediction_confidence} ({total_time_ms:.2f} ms)]")

    def throughput(throughput):
        print(f"throughput: {throughput}")

    def resource(cpu_usage, memory_usage):
        print(f"cpu: {cpu_usage} memory: {memory_usage}")

    interface = "en0"
    model_path = "/Users/wahba/Library/Mobile Documents/com~apple~CloudDocs/others/nids3/models/xgb.joblib"

    nids = NIDSEngine(interface=interface, model_path=model_path, on_log=log, on_throughput=throughput, on_resource_usage=resource)
    nids.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        nids.stop()
