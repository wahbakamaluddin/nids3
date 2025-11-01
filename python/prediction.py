import joblib
import numpy as np
import pandas as pd
import time

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

flow_web_attack = {
   'features' : {
        'Destination Port': 80,
        'Flow Duration': 5020638,
        'Total Fwd Packets': 7,
        'Total Length of Fwd Packets': 973,
        'Fwd Packet Length Max': 565,
        'Fwd Packet Length Min': 0,
        'Fwd Packet Length Mean': 139.0,
        'Fwd Packet Length Std': 241.6754021,
        'Bwd Packet Length Max': 1066,
        'Bwd Packet Length Min': 0,
        'Bwd Packet Length Mean': 357.5,
        'Bwd Packet Length Std': 502.5359025,
        'Flow Bytes/s': 478.6244298,
        'Flow Packets/s': 2.190956608,
        'Flow IAT Mean': 502063.8,
        'Flow IAT Std': 1567338.192,
        'Flow IAT Max': 4962654,
        'Flow IAT Min': 18,
        'Fwd IAT Total': 5020638,
        'Fwd IAT Mean': 836773.0,
        'Fwd IAT Std': 2021330.139,
        'Fwd IAT Max': 4962654,
        'Fwd IAT Min': 18,
        'Bwd IAT Total': 18708,
        'Bwd IAT Mean': 6236.0,
        'Bwd IAT Std': 5195.494587,
        'Bwd IAT Max': 11318,
        'Bwd IAT Min': 934,
        'Fwd Header Length': 232,
        'Bwd Header Length': 136,
        'Fwd Packets/s': 1.394245114,
        'Bwd Packets/s': 0.796711494,
        'Min Packet Length': 0,
        'Max Packet Length': 1066,
        'Packet Length Mean': 200.25,
        'Packet Length Std': 340.2325742,
        'Packet Length Variance': 115758.2045,
        'FIN Flag Count': 0,
        'PSH Flag Count': 1,
        'ACK Flag Count': 0,
        'Average Packet Size': 218.4545455,
        'Subflow Fwd Bytes': 973,
        'Init_Win_bytes_forward': 29200,
        'Init_Win_bytes_backward': 244,
        'act_data_pkt_fwd': 2,
        'min_seg_size_forward': 32,
        'Active Mean': 0.0,
        'Active Max': 0,
        'Active Min': 0,
        'Idle Mean': 0.0,
        'Idle Max': 0,
        'Idle Min': 0
   } 
}


flow = {
    'features' : {
        'Destination Port': 80,
        'Flow Duration': 12345,
        'Total Fwd Packets': 10,
        'Total Length of Fwd Packets': 1500,
        'Fwd Packet Length Max': 200,
        'Fwd Packet Length Min': 50,
        'Fwd Packet Length Mean': 150,
        'Fwd Packet Length Std': 30,
        'Bwd Packet Length Max': 180,
        'Bwd Packet Length Min': 40,
        'Bwd Packet Length Mean': 120,
        'Bwd Packet Length Std': 25,
        'Flow Bytes/s': 10000,
        'Flow Packets/s': 50,
        'Flow IAT Mean': 20,
        'Flow IAT Std': 5,
        'Flow IAT Max': 100,
        'Flow IAT Min': 5,
        'Fwd IAT Total': 200,
        'Fwd IAT Mean': 20,
        'Fwd IAT Std': 5,
        'Fwd IAT Max': 50,
        'Fwd IAT Min': 5,
        'Bwd IAT Total': 150,
        'Bwd IAT Mean': 15,
        'Bwd IAT Std': 3,
        'Bwd IAT Max': 40,
        'Bwd IAT Min': 2,
        'Fwd Header Length': 20,
        'Bwd Header Length': 20,
        'Fwd Packets/s': 10,
        'Bwd Packets/s': 10,
        'Min Packet Length': 40,
        'Max Packet Length': 200,
        'Packet Length Mean': 130,
        'Packet Length Std': 25,
        'Packet Length Variance': 625,
        'FIN Flag Count': 0,
        'PSH Flag Count': 5,
        'ACK Flag Count': 10,
        'Average Packet Size': 150,
        'Subflow Fwd Bytes': 500,
        'Init_Win_bytes_forward': 8192,
        'Init_Win_bytes_backward': 8192,
        'act_data_pkt_fwd': 10,
        'min_seg_size_forward': 1,
        'Active Mean': 100,
        'Active Max': 200,
        'Active Min': 50,
        'Idle Mean': 10,
        'Idle Max': 20,
        'Idle Min': 5
    }
}

dataframe = np.array([flow_web_attack['features'][feature] for feature in required_features[:-1]]).reshape(1, -1)

print(dataframe)


knn_model = joblib.load('/Users/wahba/Library/Mobile Documents/com~apple~CloudDocs/others/nids3/models/knn.joblib')
random_forest_model = joblib.load('/Users/wahba/Library/Mobile Documents/com~apple~CloudDocs/others/nids3/models/random_forest.joblib')
xgb_model = joblib.load('/Users/wahba/Library/Mobile Documents/com~apple~CloudDocs/others/nids3/models/xgb.joblib')

def prediction(model):
    start_time = time.time()
    prediction = model.predict(dataframe)
    total_time = time.time() - start_time

    return prediction, total_time


knn_prediction, knn_total_time = prediction(knn_model)
random_forest_prediction, random_forest_total_time = prediction(random_forest_model)
xgb_prediction, xgb_total_time = prediction(xgb_model)


print(f'''
    knn_prediction: {knn_prediction} - {knn_total_time}
    random_forest_prediction: {random_forest_prediction} - {random_forest_total_time}
    xgb_prediction: {xgb_prediction} - {xgb_total_time}
      '''
      )