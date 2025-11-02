# nids_gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import psutil
from nids_engine import NIDSEngine  # Import your existing NIDSEngine

class NIDSGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Lightweight NIDS Monitor")
        self.root.geometry("650x450")
        
        self.nids_engine = None
        self.capturing = False
        self.throughput_value = 0
        
        self.setup_gui()
        
    def setup_gui(self):
        # Title
        ttk.Label(self.root, text="Lightweight NIDS Monitor", font=("Segoe UI", 14, "bold")).pack(pady=5)

        # Network Interface Section
        ttk.Label(self.root, text="Network Interface:").pack(pady=3)
        self.interface_entry = ttk.Entry(self.root)
        self.interface_entry.insert(0, "en0")  # Default interface
        self.interface_entry.pack()

        # Model Path Section
        ttk.Label(self.root, text="Model Path:").pack(pady=3)
        self.model_entry = ttk.Entry(self.root, width=80)
        self.model_entry.insert(0, "/Users/wahba/Library/Mobile Documents/com~apple~CloudDocs/others/nids3/models/xgb.joblib")
        self.model_entry.pack()

        # === Process Usage Section ===
        sys_frame = ttk.Frame(self.root)
        sys_frame.pack(pady=5)

        self.cpu_label = ttk.Label(sys_frame, text="CPU: --%", font=("Consolas", 10))
        self.cpu_label.pack(side=tk.LEFT, padx=10)

        self.mem_label = ttk.Label(sys_frame, text="Memory: --%", font=("Consolas", 10))
        self.mem_label.pack(side=tk.LEFT, padx=10)

        self.power_label = ttk.Label(sys_frame, text="Power: --", font=("Consolas", 10))
        self.power_label.pack(side=tk.LEFT, padx=10)
        
        self.throughput_label = ttk.Label(sys_frame, text="Throughput: -- pkt/s", font=("Consolas", 10))
        self.throughput_label.pack(side=tk.LEFT, padx=10)

        # === Log widget ===
        self.log_widget = scrolledtext.ScrolledText(
            self.root, 
            height=18, 
            bg="black", 
            fg="lime", 
            insertbackground="white",
            font=("Consolas", 10)
        )
        self.log_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # === Buttons ===
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)

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

        exit_btn = ttk.Button(button_frame, text="Exit", command=self.exit_app)
        exit_btn.pack(side=tk.LEFT, padx=5)

    def log_callback(self, flow_key, prediction, processing_time):
        """Callback for NIDS engine to log detection results"""
        timestamp = time.strftime('%H:%M:%S')
        # status = "MALICIOUS" if prediction == 1 else "NORMAL"
        # color = "red" if prediction == 1 else "lime"
        color = "white"
        
        log_entry = f"[{timestamp}] Flow {flow_key} → {prediction} ({processing_time:.2f} ms)\n"
        
        # Use thread-safe GUI update
        self.root.after(0, self._update_log_widget, log_entry, color)

    def _update_log_widget(self, log_entry, color):
        """Thread-safe method to update the log widget"""
        self.log_widget.config(state=tk.NORMAL)
        self.log_widget.insert(tk.END, log_entry)
        
        # Apply color tagging (basic implementation)
        if color == "red":
            # You can enhance this with proper text tagging for colored text
            pass
            
        self.log_widget.see(tk.END)
        self.log_widget.config(state=tk.DISABLED)

    def throughput_callback(self, throughput):
        """Callback for throughput updates"""
        self.throughput_value = throughput
        
    def resource_usage_callback(self, cpu_usage, memory_usage):
        self.cpu_usage_value = cpu_usage
        self.mempory_usage_value = memory_usage

    def start_capture(self):
        """Start packet capture"""
        if self.capturing:
            return
            
        interface = self.interface_entry.get().strip()
        model_path = self.model_entry.get().strip()
        
        if not interface:
            self._update_log_widget("[ERROR] Please specify a network interface\n", "red")
            return
            
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
            
            self._update_log_widget(f"[*] Started packet capture on interface {interface}\n", "lime")
            self._update_log_widget(f"[*] Anomaly detector: {model_path}\n", "lime")
            
        except FileNotFoundError:
            self._update_log_widget(f"[ERROR] Model file not found: {model_path}\n", "red")
        except Exception as e:
            self._update_log_widget(f"[ERROR] Failed to start capture: {str(e)}\n", "red")

    def stop_capture(self):
        """Stop packet capture"""
        if self.nids_engine and self.capturing:
            self.nids_engine.stop()
            self.capturing = False
            
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            
            self._update_log_widget("[!] Stopped packet capture\n", "yellow")

    def clear_log(self):
        """Clear the log widget"""
        self.log_widget.config(state=tk.NORMAL)
        self.log_widget.delete(1.0, tk.END)
        self.log_widget.config(state=tk.DISABLED)

    def update_process_usage(self):
        """Update system resource usage displays"""
        while True:
            if self.root.winfo_exists():
                
                try:
                    power_plugged = psutil.sensors_battery().power_plugged if hasattr(psutil, "sensors_battery") and psutil.sensors_battery() else None
                    power_status = "Plugged" if power_plugged else "Battery" if power_plugged is not None else "Unknown"
                    
                    # Throughput
                    throughput_text = f"Throughput: {self.throughput_value} pkt/s"
                    
                    # Update labels in thread-safe manner
                    self.root.after(0, self._update_resource_labels, 
                                   f"CPU: {self.cpu_usage_value:.1f}%",
                                   f"Memory: {self.mempory_usage_value:.1f} mb",
                                   f"Power: {power_status}",
                                   throughput_text)
                    
                except Exception as e:
                    print(f"Error updating process usage: {e}")
                
                time.sleep(1)
            else:
                break

    def _update_resource_labels(self, cpu_text, mem_text, power_text, throughput_text):
        """Thread-safe method to update resource labels"""
        self.cpu_label.config(text=cpu_text)
        self.mem_label.config(text=mem_text)
        self.power_label.config(text=power_text)
        self.throughput_label.config(text=throughput_text)

    def exit_app(self):
        """Clean exit from application"""
        if self.capturing and self.nids_engine:
            self.nids_engine.stop()
        self.root.quit()
        self.root.destroy()

    def run(self):
        """Start the GUI application"""
        # Start process monitoring thread
        threading.Thread(target=self.update_process_usage, daemon=True).start()
        
        # Start the GUI maisn loop
        self.root.mainloop()


if __name__ == "__main__":
    app = NIDSGUI()
    app.run()