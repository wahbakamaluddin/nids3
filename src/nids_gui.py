# # nids_gui.py
# import tkinter as tk
# from tkinter import ttk, scrolledtext
# import threading
# import time
# import psutil
# from nids_engine import NIDSEngine  # Import your existing NIDSEngine

# class NIDSGUI:
#     def __init__(self):
#         self.root = tk.Tk()
#         self.root.title("Lightweight NIDS Monitor")
#         self.root.geometry("650x450")
        
#         self.nids_engine = None
#         self.capturing = False
#         self.throughput_value = 0
        
#         self.setup_gui()
        
#     def setup_gui(self):
#         # Title
#         ttk.Label(self.root, text="Lightweight NIDS Monitor", font=("Segoe UI", 14, "bold")).pack(pady=5)

#         # Network Interface Section
#         ttk.Label(self.root, text="Network Interface:").pack(pady=3)
#         self.interface_entry = ttk.Entry(self.root)
#         self.interface_entry.insert(0, "en0")  # Default interface
#         self.interface_entry.pack()

#         # Model Path Section
#         ttk.Label(self.root, text="Model Path:").pack(pady=3)
#         self.model_entry = ttk.Entry(self.root, width=80)
#         self.model_entry.insert(0, "/Users/wahba/Library/Mobile Documents/com~apple~CloudDocs/others/nids3/models/xgb.joblib")
#         self.model_entry.pack()

#         # === Process Usage Section ===
#         sys_frame = ttk.Frame(self.root)
#         sys_frame.pack(pady=5)

#         self.cpu_label = ttk.Label(sys_frame, text="CPU: --%", font=("Consolas", 10))
#         self.cpu_label.pack(side=tk.LEFT, padx=10)

#         self.mem_label = ttk.Label(sys_frame, text="Memory: --%", font=("Consolas", 10))
#         self.mem_label.pack(side=tk.LEFT, padx=10)

#         self.power_label = ttk.Label(sys_frame, text="Power: --", font=("Consolas", 10))
#         self.power_label.pack(side=tk.LEFT, padx=10)
        
#         self.throughput_label = ttk.Label(sys_frame, text="Throughput: -- pkt/s", font=("Consolas", 10))
#         self.throughput_label.pack(side=tk.LEFT, padx=10)

#         # === Log widget ===
#         self.log_widget = scrolledtext.ScrolledText(
#             self.root, 
#             height=18, 
#             bg="black", 
#             fg="lime", 
#             insertbackground="white",
#             font=("Consolas", 10)
#         )
#         self.log_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

#         # === Buttons ===
#         button_frame = ttk.Frame(self.root)
#         button_frame.pack(pady=10)

#         self.start_btn = ttk.Button(
#             button_frame,
#             text="Start Capture",
#             command=self.start_capture
#         )
#         self.start_btn.pack(side=tk.LEFT, padx=5)

#         self.stop_btn = ttk.Button(
#             button_frame, 
#             text="Stop Capture", 
#             command=self.stop_capture,
#             state="disabled"
#         )
#         self.stop_btn.pack(side=tk.LEFT, padx=5)

#         self.clear_btn = ttk.Button(
#             button_frame,
#             text="Clear Log",
#             command=self.clear_log
#         )
#         self.clear_btn.pack(side=tk.LEFT, padx=5)

#         exit_btn = ttk.Button(button_frame, text="Exit", command=self.exit_app)
#         exit_btn.pack(side=tk.LEFT, padx=5)

#     def log_callback(self, flow_key, prediction, processing_time):
#         """Callback for NIDS engine to log detection results"""
#         timestamp = time.strftime('%H:%M:%S')
#         # status = "MALICIOUS" if prediction == 1 else "NORMAL"
#         # color = "red" if prediction == 1 else "lime"
#         color = "white"
        
#         log_entry = f"[{timestamp}] Flow {flow_key} → {prediction} ({processing_time:.2f} ms)\n"
        
#         # Use thread-safe GUI update
#         self.root.after(0, self._update_log_widget, log_entry, color)

#     def _update_log_widget(self, log_entry, color):
#         """Thread-safe method to update the log widget"""
#         self.log_widget.config(state=tk.NORMAL)
#         self.log_widget.insert(tk.END, log_entry)
        
#         # Apply color tagging (basic implementation)
#         if color == "red":
#             # You can enhance this with proper text tagging for colored text
#             pass
            
#         self.log_widget.see(tk.END)
#         self.log_widget.config(state=tk.DISABLED)

#     def throughput_callback(self, throughput):
#         """Callback for throughput updates"""
#         self.throughput_value = throughput
        
#     def resource_usage_callback(self, cpu_usage, memory_usage):
#         self.cpu_usage_value = cpu_usage
#         self.mempory_usage_value = memory_usage

#     def start_capture(self):
#         """Start packet capture"""
#         if self.capturing:
#             return
            
#         interface = self.interface_entry.get().strip()
#         model_path = self.model_entry.get().strip()
        
#         if not interface:
#             self._update_log_widget("[ERROR] Please specify a network interface\n", "red")
#             return
            
#         try:
#             self.nids_engine = NIDSEngine(
#                 interface=interface,
#                 model_path=model_path,
#                 on_log=self.log_callback,
#                 on_throughput=self.throughput_callback,
#                 on_resource_usage=self.resource_usage_callback,
#             )
            
#             self.nids_engine.start()
#             self.capturing = True
            
#             self.start_btn.config(state="disabled")
#             self.stop_btn.config(state="normal")
            
#             self._update_log_widget(f"[*] Started packet capture on interface {interface}\n", "lime")
#             self._update_log_widget(f"[*] Anomaly detector: {model_path}\n", "lime")
            
#         except FileNotFoundError:
#             self._update_log_widget(f"[ERROR] Model file not found: {model_path}\n", "red")
#         except Exception as e:
#             self._update_log_widget(f"[ERROR] Failed to start capture: {str(e)}\n", "red")

#     def stop_capture(self):
#         """Stop packet capture"""
#         if self.nids_engine and self.capturing:
#             self.nids_engine.stop()
#             self.capturing = False
            
#             self.start_btn.config(state="normal")
#             self.stop_btn.config(state="disabled")
            
#             self._update_log_widget("[!] Stopped packet capture\n", "yellow")

#     def clear_log(self):
#         """Clear the log widget"""
#         self.log_widget.config(state=tk.NORMAL)
#         self.log_widget.delete(1.0, tk.END)
#         self.log_widget.config(state=tk.DISABLED)

#     def update_process_usage(self):
#         """Update system resource usage displays"""
#         while True:
#             if self.root.winfo_exists():
                
#                 try:
#                     power_plugged = psutil.sensors_battery().power_plugged if hasattr(psutil, "sensors_battery") and psutil.sensors_battery() else None
#                     power_status = "Plugged" if power_plugged else "Battery" if power_plugged is not None else "Unknown"
                    
#                     # Throughput
#                     throughput_text = f"Throughput: {self.throughput_value} pkt/s"
                    
#                     # Update labels in thread-safe manner
#                     self.root.after(0, self._update_resource_labels, 
#                                    f"CPU: {self.cpu_usage_value:.1f}%",
#                                    f"Memory: {self.mempory_usage_value:.1f} mb",
#                                    f"Power: {power_status}",
#                                    throughput_text)
                    
#                 except Exception as e:
#                     print(f"Error updating process usage: {e}")
                
#                 time.sleep(1)
#             else:
#                 break

#     def _update_resource_labels(self, cpu_text, mem_text, power_text, throughput_text):
#         """Thread-safe method to update resource labels"""
#         self.cpu_label.config(text=cpu_text)
#         self.mem_label.config(text=mem_text)
#         self.power_label.config(text=power_text)
#         self.throughput_label.config(text=throughput_text)

#     def exit_app(self):
#         """Clean exit from application"""
#         if self.capturing and self.nids_engine:
#             self.nids_engine.stop()
#         self.root.quit()
#         self.root.destroy()

#     def run(self):
#         """Start the GUI application"""
#         # Start process monitoring thread
#         threading.Thread(target=self.update_process_usage, daemon=True).start()
        
#         # Start the GUI maisn loop
#         self.root.mainloop()


# if __name__ == "__main__":
#     app = NIDSGUI()
#     app.run()

# nids_gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import psutil
from collections import deque
from nids_engine import NIDSEngine  # Import your existing NIDSEngine

class NIDSGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Lightweight NIDS Monitor")
        self.root.geometry("650x450")
        self.root.protocol("WM_DELETE_WINDOW", self.exit_app)
        
        self.nids_engine = None
        self.capturing = False
        self.throughput_value = 0
        self.cpu_usage_value = 0
        self.memory_usage_value = 0
        
        # Performance optimizations
        self.log_queue = deque(maxlen=1000)  # Limit log history
        self.last_update_time = 0
        self.update_interval = 0.1  # 100ms for UI updates
        self.resource_update_interval = 1.0  # 1 second for resource updates
        
        self.setup_gui()
        
    def setup_gui(self):
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Lightweight NIDS Monitor", 
                               font=("Segoe UI", 14, "bold"))
        title_label.pack(pady=5)

        # Configuration Frame
        config_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="5")
        config_frame.pack(fill=tk.X, pady=5)
        
        # Network Interface
        ttk.Label(config_frame, text="Network Interface:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.interface_entry = ttk.Entry(config_frame, width=15)
        self.interface_entry.insert(0, "en0")
        self.interface_entry.grid(row=0, column=1, sticky="w", padx=(0, 15))
        
        # Model Path
        ttk.Label(config_frame, text="Model Path:").grid(row=0, column=2, sticky="w", padx=(0, 5))
        self.model_entry = ttk.Entry(config_frame, width=50)
        self.model_entry.insert(0, "/Users/wahba/Library/Mobile Documents/com~apple~CloudDocs/others/nids3/models/xgb.joblib")
        self.model_entry.grid(row=0, column=3, sticky="we", padx=(0, 5))
        
        config_frame.columnconfigure(3, weight=1)

        # System Metrics Frame
        metrics_frame = ttk.LabelFrame(main_frame, text="System Metrics", padding="5")
        metrics_frame.pack(fill=tk.X, pady=5)
        
        # Create metrics in a grid for better alignment
        self.cpu_label = ttk.Label(metrics_frame, text="CPU: --%", font=("Consolas", 9))
        self.cpu_label.grid(row=0, column=0, padx=10, sticky="w")
        
        self.mem_label = ttk.Label(metrics_frame, text="Memory: --%", font=("Consolas", 9))
        self.mem_label.grid(row=0, column=1, padx=10, sticky="w")
        
        self.power_label = ttk.Label(metrics_frame, text="Power: --", font=("Consolas", 9))
        self.power_label.grid(row=0, column=2, padx=10, sticky="w")
        
        self.throughput_label = ttk.Label(metrics_frame, text="Throughput: -- pkt/s", font=("Consolas", 9))
        self.throughput_label.grid(row=0, column=3, padx=10, sticky="w")
        
        metrics_frame.columnconfigure(3, weight=1)

        # Log widget with optimized configuration
        log_frame = ttk.LabelFrame(main_frame, text="Detection Log", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_widget = scrolledtext.ScrolledText(
            log_frame, 
            height=18, 
            bg="black", 
            fg="lime", 
            insertbackground="white",
            font=("Consolas", 9),
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.log_widget.pack(fill=tk.BOTH, expand=True)

        # Button Frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)

        self.start_btn = ttk.Button(
            button_frame,
            text="Start Capture",
            command=self.start_capture
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(
            button_frame, 
            text="Stop Capture", 
            command=self.stop_capture,
            state="disabled"
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = ttk.Button(
            button_frame,
            text="Clear Log",
            command=self.clear_log
        )
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(button_frame, text="Exit", command=self.exit_app).pack(side=tk.LEFT, padx=5)
        
        # Add a spacer to push buttons left
        ttk.Label(button_frame).pack(side=tk.LEFT, expand=True)

    def log_callback(self, flow_key, prediction, processing_time):
        """Callback for NIDS engine to log detection results"""
        timestamp = time.strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] Flow {flow_key} → {prediction} ({processing_time:.2f} ms)\n"
        
        # Add to queue instead of immediate GUI update
        self.log_queue.append(log_entry)
        
        # Throttle GUI updates
        current_time = time.time()
        if current_time - self.last_update_time >= self.update_interval:
            self.last_update_time = current_time
            self.root.after(0, self._process_log_queue)

    def _process_log_queue(self):
        """Process accumulated log entries in batch"""
        if not self.log_queue:
            return
            
        self.log_widget.config(state=tk.NORMAL)
        
        # Batch insert to reduce GUI updates
        batch_size = min(50, len(self.log_queue))  # Process up to 50 entries at once
        batch_text = ''.join([self.log_queue.popleft() for _ in range(batch_size)])
        
        self.log_widget.insert(tk.END, batch_text)
        self.log_widget.see(tk.END)
        self.log_widget.config(state=tk.DISABLED)
        
        # If there are more entries, schedule another update
        if self.log_queue:
            self.root.after(10, self._process_log_queue)

    def throughput_callback(self, throughput):
        """Callback for throughput updates"""
        self.throughput_value = throughput
        
    def resource_usage_callback(self, cpu_usage, memory_usage):
        """Callback for resource usage updates"""
        self.cpu_usage_value = cpu_usage
        self.memory_usage_value = memory_usage

    def start_capture(self):
        """Start packet capture"""
        if self.capturing:
            return
            
        interface = self.interface_entry.get().strip()
        model_path = self.model_entry.get().strip()
        
        if not interface:
            self._update_log_widget("[ERROR] Please specify a network interface\n")
            return
            
        # Disable UI during startup
        self._set_ui_state(False)
            
        try:
            self.nids_engine = NIDSEngine(
                interface=interface,
                model_path=model_path,
                on_log=self.log_callback,
                on_throughput=self.throughput_callback,
                on_resource_usage=self.resource_usage_callback,
            )
            
            self.nids_engine.start()
            self.capturing = True
            
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            
            self._update_log_widget(f"[*] Started packet capture on interface {interface}\n")
            self._update_log_widget(f"[*] Anomaly detector: {model_path}\n")
            
        except FileNotFoundError:
            self._update_log_widget(f"[ERROR] Model file not found: {model_path}\n")
            self._set_ui_state(True)
        except Exception as e:
            self._update_log_widget(f"[ERROR] Failed to start capture: {str(e)}\n")
            self._set_ui_state(True)

    def _set_ui_state(self, enabled):
        """Enable/disable UI elements"""
        state = "normal" if enabled else "disabled"
        self.start_btn.config(state=state)
        self.interface_entry.config(state=state)
        self.model_entry.config(state=state)

    def stop_capture(self):
        """Stop packet capture"""
        if self.nids_engine and self.capturing:
            self.nids_engine.stop()
            self.capturing = False
            
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self._set_ui_state(True)
            
            self._update_log_widget("[!] Stopped packet capture\n")

    def _update_log_widget(self, message):
        """Immediate log update for important messages"""
        self.log_widget.config(state=tk.NORMAL)
        self.log_widget.insert(tk.END, message)
        self.log_widget.see(tk.END)
        self.log_widget.config(state=tk.DISABLED)

    def clear_log(self):
        """Clear the log widget and queue"""
        self.log_queue.clear()
        self.log_widget.config(state=tk.NORMAL)
        self.log_widget.delete(1.0, tk.END)
        self.log_widget.config(state=tk.DISABLED)

    def update_system_metrics(self):
        """Update system resource usage displays"""
        try:
            # Get battery info if available
            battery = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
            power_status = "Plugged" if battery and battery.power_plugged else "Battery" if battery else "Unknown"
            
            # Update labels
            throughput_text = f"Throughput: {self.throughput_value} pkt/s"
            cpu_text = f"CPU: {self.cpu_usage_value:.1f}%"
            mem_text = f"Memory: {self.memory_usage_value:.1f} MB"
            power_text = f"Power: {power_status}"
            
            self.cpu_label.config(text=cpu_text)
            self.mem_label.config(text=mem_text)
            self.power_label.config(text=power_text)
            self.throughput_label.config(text=throughput_text)
            
        except Exception as e:
            print(f"Error updating system metrics: {e}")

    def exit_app(self):
        """Clean exit from application"""
        if self.capturing and self.nids_engine:
            self.stop_capture()
        
        if self.root:
            self.root.quit()
            self.root.destroy()

    def run(self):
        """Start the GUI application"""
        # Start periodic updates for system metrics
        def periodic_updates():
            while True:
                try:
                    if not self.root.winfo_exists():
                        break
                    
                    # Update system metrics
                    self.root.after(0, self.update_system_metrics)
                    
                    # Process any remaining log entries
                    if self.log_queue:
                        self.root.after(0, self._process_log_queue)
                    
                    time.sleep(self.resource_update_interval)
                    
                except Exception as e:
                    print(f"Error in periodic updates: {e}")
                    break
        
        # Start background thread for updates
        threading.Thread(target=periodic_updates, daemon=True).start()
        
        # Start the GUI main loop
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.exit_app()


if __name__ == "__main__":
    app = NIDSGUI()
    app.run()