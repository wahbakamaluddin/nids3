Small GUI + engine for real‑time network flow feature extraction and anomaly detection.

# ONGOING PROJECT

## Overview
- GUI: `src/nids_gui3.py` — Tkinter front end to start/stop capture, view logs, and monitor throughput & system metrics.
- Engine: `src/nids_engine.py` (and `src/nids_engine2.py`) — packet capture (Scapy), flow feature extraction, and ML anomaly detection (loads a joblib model).
- Expected model file: `models/xgb.joblib` (adjust path in GUI or when creating the engine).

## Requirements (tested on macOS)
- System:
  - macOS (packet capture)
  - libpcap (bundled on macOS)
  - Administrator / root privileges (or appropriate capture permissions) to sniff live traffic
- Python:
  - Python 3.13 (environment.yml targets 3.13; 3.11+ should generally work)
- Python packages (primary):
  - scapy
  - psutil
  - joblib
  - numpy
  - pandas
  - scikit-learn
  - xgboost (if the model is an XGBoost model)
  - tkinter (Tcl/Tk; usually bundled with system Python)
