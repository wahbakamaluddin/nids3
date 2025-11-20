import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os

# Load datasets
df1 = pd.read_csv('../data/cicflowmeter.csv')
df2 = pd.read_csv('../data/other_dataset.csv')


# Cleaning column names

col_names = {col: col.strip() for col in df1.columns}
df1.rename(columns=col_names, inplace=True)
col_names = {col: col.strip() for col in df2.columns}
df2.rename(columns=col_names, inplace=True)

# Standardizing column names
final_cols_df1 = {
    'Source IP': 'Source IP',
    'Destination IP': 'Destination IP',
    'Protocol': 'Protocol',
    'Source Port': 'Source Port',
    'Destination Port': 'Destination Port',
    'Flow Duration': 'Flow Duration',
    'Total Fwd Packets': 'Total Fwd Packets',
    'Total Length of Fwd Packets': 'Total Length of Fwd Packets',
    'Fwd Packet Length Max': 'Fwd Packet Length Max',
    'Fwd Packet Length Min': 'Fwd Packet Length Min',
    'Fwd Packet Length Mean': 'Fwd Packet Length Mean',
    'Fwd Packet Length Std': 'Fwd Packet Length Std',
    'Bwd Packet Length Max': 'Bwd Packet Length Max',
    'Bwd Packet Length Min': 'Bwd Packet Length Min',
    'Bwd Packet Length Mean': 'Bwd Packet Length Mean',
    'Bwd Packet Length Std': 'Bwd Packet Length Std',
    'Flow Bytes/s': 'Flow Bytes/s',
    'Flow Packets/s': 'Flow Packets/s',
    'Flow IAT Mean': 'Flow IAT Mean',
    'Flow IAT Std': 'Flow IAT Std',
    'Flow IAT Max': 'Flow IAT Max',
    'Flow IAT Min': 'Flow IAT Min',
    'Fwd IAT Total': 'Fwd IAT Total',
    'Fwd IAT Mean': 'Fwd IAT Mean',
    'Fwd IAT Std': 'Fwd IAT Std',
    'Fwd IAT Max': 'Fwd IAT Max',
    'Fwd IAT Min': 'Fwd IAT Min',
    'Bwd IAT Total': 'Bwd IAT Total',
    'Bwd IAT Mean': 'Bwd IAT Mean',
    'Bwd IAT Std': 'Bwd IAT Std',
    'Bwd IAT Max': 'Bwd IAT Max',
    'Bwd IAT Min': 'Bwd IAT Min',
    'Fwd Header Length': 'Fwd Header Length',
    'Bwd Header Length': 'Bwd Header Length',
    'Fwd Packets/s': 'Fwd Packets/s',
    'Bwd Packets/s': 'Bwd Packets/s',
    'Min Packet Length': 'Min Packet Length',
    'Max Packet Length': 'Max Packet Length',
    'Packet Length Mean': 'Packet Length Mean',
    'Packet Length Std': 'Packet Length Std',
    'Packet Length Variance': 'Packet Length Variance',
    'FIN Flag Count': 'FIN Flag Count',
    'PSH Flag Count': 'PSH Flag Count',
    'ACK Flag Count': 'ACK Flag Count',
    'Average Packet Size': 'Average Packet Size',
    'Subflow Fwd Bytes': 'Subflow Fwd Bytes',
    'Init_Win_bytes_forward': 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward': 'Init_Win_bytes_backward',
    'act_data_pkt_fwd': 'act_data_pkt_fwd',
    'min_seg_size_forward': 'min_seg_size_forward',
    'Active Mean': 'Active Mean',
    'Active Max': 'Active Max',
    'Active Min': 'Active Min',
    'Idle Mean': 'Idle Mean',
    'Idle Max': 'Idle Max',
    'Idle Min': 'Idle Min'
}

final_cols_df2 = {
    'src_ip': 'Source IP',
    'dst_ip': 'Destination IP',
    'protocol': 'Protocol',
    'src_port': 'Source Port',
    'dst_port': 'Destination Port',
    'flow_duration': 'Flow Duration',
    'tot_fwd_pkts': 'Total Fwd Packets',
    'totlen_fwd_pkts': 'Total Length of Fwd Packets',
    'fwd_pkt_len_max': 'Fwd Packet Length Max',
    'fwd_pkt_len_min': 'Fwd Packet Length Min',
    'fwd_pkt_len_mean': 'Fwd Packet Length Mean',
    'fwd_pkt_len_std': 'Fwd Packet Length Std',
    'bwd_pkt_len_max': 'Bwd Packet Length Max',
    'bwd_pkt_len_min': 'Bwd Packet Length Min',
    'bwd_pkt_len_mean': 'Bwd Packet Length Mean',
    'bwd_pkt_len_std': 'Bwd Packet Length Std',
    'flow_byts_s': 'Flow Bytes/s',
    'flow_pkts_s': 'Flow Packets/s',
    'flow_iat_mean': 'Flow IAT Mean',
    'flow_iat_std': 'Flow IAT Std',
    'flow_iat_max': 'Flow IAT Max',
    'flow_iat_min': 'Flow IAT Min',
    'fwd_iat_tot': 'Fwd IAT Total',
    'fwd_iat_mean': 'Fwd IAT Mean',
    'fwd_iat_std': 'Fwd IAT Std',
    'fwd_iat_max': 'Fwd IAT Max',
    'fwd_iat_min': 'Fwd IAT Min',
    'bwd_iat_tot': 'Bwd IAT Total',
    'bwd_iat_mean': 'Bwd IAT Mean',
    'bwd_iat_std': 'Bwd IAT Std',
    'bwd_iat_max': 'Bwd IAT Max',
    'bwd_iat_min': 'Bwd IAT Min',
    'fwd_header_len': 'Fwd Header Length',
    'bwd_header_len': 'Bwd Header Length',
    'fwd_pkts_s': 'Fwd Packets/s',
    'bwd_pkts_s': 'Bwd Packets/s',
    'pkt_len_min': 'Min Packet Length',
    'pkt_len_max': 'Max Packet Length',
    'pkt_len_mean': 'Packet Length Mean',
    'pkt_len_std': 'Packet Length Std',
    'pkt_len_var': 'Packet Length Variance',
    'fin_flag_cnt': 'FIN Flag Count',
    'psh_flag_cnt': 'PSH Flag Count',
    'ack_flag_cnt': 'ACK Flag Count',
    'pkt_size_avg': 'Average Packet Size',
    'subflow_fwd_byts': 'Subflow Fwd Bytes',
    'init_fwd_win_byts': 'Init_Win_bytes_forward',
    'init_bwd_win_byts': 'Init_Win_bytes_backward',
    'fwd_act_data_pkts': 'act_data_pkt_fwd',
    'fwd_seg_size_min': 'min_seg_size_forward',
    'active_mean': 'Active Mean',
    'active_max': 'Active Max',
    'active_min': 'Active Min',
    'idle_mean': 'Idle Mean',
    'idle_max': 'Idle Max',
    'idle_min': 'Idle Min'
}

# Modify column names and drop unnecessary columns
df1 = df1[list(final_cols_df1.keys())].rename(columns=final_cols_df1)
df2 = df2[list(final_cols_df2.keys())].rename(columns=final_cols_df2)

# Comparing dataframes
# Generate flow key
df1['flow_key'] = (
    df1['Source IP'].astype(str) + ':' +
    df1['Source Port'].astype(str) + '-' +
    df1['Destination IP'].astype(str) + ':' +
    df1['Destination Port'].astype(str) + '-' +
    df1['Protocol'].astype(str)
    )

df2['flow_key'] = (
    df2['Source IP'].astype(str) + ':' +
    df2['Source Port'].astype(str) + '-' +
    df2['Destination IP'].astype(str) + ':' +
    df2['Destination Port'].astype(str) + '-' +
    df2['Protocol'].astype(str)
    )


# Find intersections
df1_key = set(df1['flow_key'])
df2_key = set(df2['flow_key'])
matched_keys = df1_key.intersection(df2_key)

print(f"Number of matched flows: {len(matched_keys)}")
print(f"Percentage of matched flows in df1: {len(matched_keys) / len(df1_key) * 100:.2f}%")

# Remove non-matching flows from df1
df1 = df1[df1['flow_key'].isin(matched_keys)].copy()

# Compare number of rows
print(f"Number of rows (df1): {len(df1)}")
print(f"Number of rows (df2): {len(df2)}")


