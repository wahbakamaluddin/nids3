import joblib
import numpy as np
import pandas as pd
import time

data = pd.DataFrame([{
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
}])

knn_model = joblib.load('../models/knn.joblib')
random_forest_model = joblib.load('../models/random_forest.joblib')
xgb_model = joblib.load('../models/xgb.joblib')

def prediction(model):
    start_time = time.time()
    prediction = model.predict(data)
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