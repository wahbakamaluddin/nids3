import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import psutil
import argparse
import sys
import os

# Add the parent directory to path to import nids_engine
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nids_engine import NIDSEngine

class NIDSGUI:
    """Graphical User Interface for the Network Intrusion Detection System."""
    
    def __init__(self, nids_engine):
        """
        Initialize the NIDS GUI.
        
        Args:
            nids_engine (NIDSEngine): The NIDS engine instance to control and monitor
        """
        self.nids = nids_engine
        self.root = None
        self.cpu_label = None
        self.mem_label = None
        self.power_label = None
        self.throughput_label = None
        self.log_widget = None
        self.interface_entry = None
        
    def start_gui(self):
        """Start the NIDS graphical user interface."""
        self.root = tk.Tk()
        self.root.title("Lightweight NIDS Monitor")
        self.root.geometry("700x500")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        
        self._create_widgets()
        self._start_monitors()
        
        self.root.mainloop()
    
    def _on_close(self):
        """Handle window close event."""
        if self.nids.capturing:
            if messagebox.askokcancel("Quit", "NIDS is still capturing packets. Stop capture and quit?"):
                self.nids.stop()
                self.root.destroy()
        else:
            self.root.destroy()
    
    def _create_widgets(self):
        """Create and arrange all GUI widgets."""
        # Title
        ttk.Label(self.root, text="Lightweight NIDS Monitor", 
                 font=("Segoe UI", 14, "bold")).pack(pady=5)
        
        # Interface configuration
        config_frame = ttk.Frame(self.root)
        config_frame.pack(pady=3, fill=tk.X, padx=10)
        
        ttk.Label(config_frame, text="Network Interface:").pack(side=tk.LEFT)
        self.interface_entry = ttk.Entry(config_frame, width=15)
        self.interface_entry.insert(0, self.nids.interface)
        self.interface_entry.pack(side=tk.LEFT, padx=5)
        
        # System monitoring frame
        self._create_system_monitor()
        
        # Log display
        self._create_log_widget()
        
        # Control buttons
        self._create_control_buttons()
    
    def _create_system_monitor(self):
        """Create system monitoring labels."""
        sys_frame = ttk.Frame(self.root)
        sys_frame.pack(pady=5, fill=tk.X, padx=10)
        
        self.cpu_label = ttk.Label(sys_frame, text="CPU: --%", font=("Consolas", 9))
        self.cpu_label.pack(side=tk.LEFT, padx=8)
        
        self.mem_label = ttk.Label(sys_frame, text="Memory: -- MB", font=("Consolas", 9))
        self.mem_label.pack(side=tk.LEFT, padx=8)
        
        self.power_label = ttk.Label(sys_frame, text="Power: --", font=("Consolas", 9))
        self.power_label.pack(side=tk.LEFT, padx=8)
        
        self.throughput_label = ttk.Label(sys_frame, text="Throughput: -- pkt/s", 
                                         font=("Consolas", 9))
        self.throughput_label.pack(side=tk.LEFT, padx=8)
    
    def _create_log_widget(self):
        """Create the log display widget."""
        # Log frame with scrollbar
        log_frame = ttk.Frame(self.root)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(log_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Text widget for logs
        self.log_widget = tk.Text(
            log_frame, 
            height=18, 
            bg="black", 
            fg="lime", 
            insertbackground="white",
            yscrollcommand=scrollbar.set,
            font=("Consolas", 9)
        )
        self.log_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.log_widget.yview)
        
        # Redirect NIDS logs to GUI
        self.nids.on_log = self._log_message
    
    def _create_control_buttons(self):
        """Create control buttons for starting/stopping capture."""
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)
        
        self.start_btn = ttk.Button(
            button_frame,
            text="Start Capture",
            command=self._start_capture
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(
            button_frame,
            text="Stop Capture", 
            command=self._stop_capture,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = ttk.Button(
            button_frame,
            text="Clear Log",
            command=self._clear_log
        )
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        exit_btn = ttk.Button(
            button_frame,
            text="Exit",
            command=self._on_close
        )
        exit_btn.pack(side=tk.LEFT, padx=5)
    
    def _start_monitors(self):
        """Start background monitoring threads."""
        # System usage monitor
        threading.Thread(target=self._update_system_usage, daemon=True).start()
    
    def _log_message(self, message):
        """Add a message to the log widget (thread-safe)."""
        def update_log():
            self.log_widget.insert(tk.END, f"{message}\n")
            self.log_widget.see(tk.END)
        
        # Ensure thread-safe GUI updates
        if self.root:
            self.root.after(0, update_log)
    
    def _clear_log(self):
        """Clear the log widget."""
        self.log_widget.delete(1.0, tk.END)
    
    def _update_system_usage(self):
        """Monitor and update system resource usage."""
        process = psutil.Process()
        
        while True:
            try:
                # CPU usage
                cpu_usage = process.cpu_percent(interval=1)
                
                # Memory usage
                mem_info = process.memory_info()
                mem_usage_mb = mem_info.rss / (1024 * 1024)
                mem_percent = process.memory_percent()
                
                # Power info
                battery = psutil.sensors_battery()
                if battery:
                    power_text = f"Battery: {battery.percent:.0f}% ({'Plugged In' if battery.power_plugged else 'On Battery'})"
                else:
                    power_text = "Power: N/A"
                
                # Update GUI (thread-safe)
                if self.root:
                    self.root.after(0, lambda: self.cpu_label.config(
                        text=f"CPU: {cpu_usage:.1f}%"))
                    self.root.after(0, lambda: self.mem_label.config(
                        text=f"Memory: {mem_usage_mb:.1f} MB"))
                    self.root.after(0, lambda: self.power_label.config(
                        text=power_text))
                    
            except Exception as e:
                if self.root:
                    self.root.after(0, lambda: self.cpu_label.config(text="CPU: Error"))
                    self.root.after(0, lambda: self.mem_label.config(text="Memory: Error"))
                    self.root.after(0, lambda: self.power_label.config(text="Power: Error"))
            
            time.sleep(2)
    
    def _start_capture(self):
        """Start packet capture in a separate thread."""
        # Update interface from entry field
        new_interface = self.interface_entry.get().strip()
        if new_interface:
            self.nids.interface = new_interface
        
        # Disable start button, enable stop button
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Start capture in background thread
        capture_thread = threading.Thread(target=self.nids.start, daemon=True)
        capture_thread.start()
        
        self._log_message("[*] Starting packet capture...")
    
    def _stop_capture(self):
        """Stop packet capture."""
        self.nids.stop()
        
        # Enable start button, disable stop button
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        self._log_message("[!] Stopping packet capture...")


def main():
    """Main function to start the NIDS GUI."""
    parser = argparse.ArgumentParser(description='NIDS GUI Interface')
    parser.add_argument('--interface', default='en0', help='Network interface to monitor')
    parser.add_argument('--model', default='/Users/wahba/Library/Mobile Documents/com~apple~CloudDocs/others/nids3/models/xgb.joblib', 
                      help='Path to trained model')
    
    args = parser.parse_args()
    
    # Create NIDS engine
    nids = NIDSEngine(
        interface=args.interface,
        model_path=args.model
    )
    
    # Create and start GUI
    gui = NIDSGUI(nids)
    gui.start_gui()


if __name__ == "__main__":
    main()