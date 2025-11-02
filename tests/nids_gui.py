#!/usr/bin/env python3
"""
Lightweight NIDS Monitor GUI for nids2.py

Creates a Tkinter GUI (class-based) that starts/stops packet capture using
Scapy's AsyncSniffer, calls `nids2.packet_parser` for processing, and
displays a live-updating Treeview of captured packets.

Note: sniffing usually requires elevated privileges.
"""
import os
import sys
import time
import threading
import queue
import tkinter as tk
from tkinter import ttk

from scapy.all import AsyncSniffer, IP, TCP, UDP

# Ensure the local `nids2.py` in the same folder is importable
SCRIPT_DIR = os.path.dirname(__file__)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

try:
    import nids2
except Exception as e:
    # Import error will be visible when running; keep the module import attempt here
    nids2 = None


class NIDSMonitor(tk.Tk):
    def __init__(self, iface='en0', poll_interval=200):
        super().__init__()
        self.title("Lightweight NIDS Monitor")
        self.geometry("980x520")
        self.minsize(800, 420)

        self.iface = iface
        self.poll_interval = poll_interval  # ms
        self.packet_queue = queue.Queue()
        self.sniffer = None
        self.running = False
        self.total_packets = 0

        self._build_ui()
        # start periodic queue processing
        self.after(self.poll_interval, self._process_packet_queue)

    def _build_ui(self):
        # Top frame for controls and status
        top_frame = ttk.Frame(self, padding=(10, 8))
        top_frame.pack(side=tk.TOP, fill=tk.X)

        btn_frame = ttk.Frame(top_frame)
        btn_frame.pack(side=tk.LEFT)

        self.start_btn = ttk.Button(btn_frame, text="Start Capture", command=self.start_capture)
        self.start_btn.grid(row=0, column=0, padx=(0, 6))

        self.stop_btn = ttk.Button(btn_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=1)

        # Stats
        stats_frame = ttk.Frame(top_frame)
        stats_frame.pack(side=tk.RIGHT)

        self.status_var = tk.StringVar(value="Stopped")
        status_label = ttk.Label(stats_frame, textvariable=self.status_var, foreground="blue")
        status_label.grid(row=0, column=0, padx=8)

        self.packet_count_var = tk.StringVar(value="Packets: 0")
        ttk.Label(stats_frame, textvariable=self.packet_count_var).grid(row=0, column=1, padx=8)

        self.flow_count_var = tk.StringVar(value="Flows: 0")
        ttk.Label(stats_frame, textvariable=self.flow_count_var).grid(row=0, column=2, padx=8)

        # Main frame for Treeview
        main_frame = ttk.Frame(self, padding=(10, 8))
        main_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Timestamp", "Source IP", "Destination IP", "Protocol", "Packet Size", "Flow Key")
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col)
            if col == 'Flow Key':
                self.tree.column(col, width=300, anchor=tk.W)
            elif col == 'Timestamp':
                self.tree.column(col, width=140, anchor=tk.W)
            else:
                self.tree.column(col, width=120, anchor=tk.CENTER)

        vsb = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(main_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        main_frame.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        # Footer note
        footer = ttk.Label(self, text="Interface: {}  |  Note: sniffing may require elevated privileges".format(self.iface), anchor=tk.W)
        footer.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(0, 6))

        # Bind close window
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def start_capture(self):
        if self.running:
            return
        # Create AsyncSniffer
        if nids2 is None:
            tk.messagebox.showerror("Import Error", "Could not import nids2 module. Make sure nids2.py is present and importable.")
            return

        # Use wrapper callback: call nids2.packet_parser then push summary to queue
        def wrapper(pkt):
            try:
                # let nids2 update its own flow_stats and features
                nids2.packet_parser(pkt)
            except Exception:
                # ensure exceptions in parsing don't stop the sniffer
                pass

            # extract summary fields for GUI
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            src = dst = proto = "-"
            size = len(pkt)
            flow_key = "-"
            try:
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                if TCP in pkt:
                    proto = 'TCP'
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    flow_key = f"{src}:{sport}-{dst}:{dport}-TCP"
                elif UDP in pkt:
                    proto = 'UDP'
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                    flow_key = f"{src}:{sport}-{dst}:{dport}-UDP"
                else:
                    proto = pkt.name
                    flow_key = f"{src}-{dst}-{proto}"
            except Exception:
                pass

            # enqueue a small summary
            self.packet_queue.put((ts, src, dst, proto, size, flow_key))

        # Create and start AsyncSniffer
        self.sniffer = AsyncSniffer(iface=self.iface, prn=wrapper, store=False)
        try:
            self.sniffer.start()
        except Exception as e:
            tk.messagebox.showerror("Sniffer Error", f"Failed to start sniffer on {self.iface}: {e}")
            self.sniffer = None
            return

        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("Running...")

    def stop_capture(self):
        if not self.running:
            return
        try:
            if self.sniffer is not None:
                # AsyncSniffer.stop() will stop background capture
                self.sniffer.stop()
        except Exception:
            pass
        finally:
            self.sniffer = None
            self.running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.status_var.set("Stopped")

    def _process_packet_queue(self):
        changed = False
        while True:
            try:
                pkt = self.packet_queue.get_nowait()
            except queue.Empty:
                break
            else:
                ts, src, dst, proto, size, flow_key = pkt
                # Insert at end
                self.tree.insert('', tk.END, values=(ts, src, dst, proto, size, flow_key))
                # keep treeview from growing unbounded: optional prune (keep last 2000)
                if len(self.tree.get_children()) > 5000:
                    # remove oldest 1000
                    children = self.tree.get_children()
                    for cid in children[:1000]:
                        self.tree.delete(cid)
                self.total_packets += 1
                changed = True

        if changed:
            self.packet_count_var.set(f"Packets: {self.total_packets}")
            # update flows from nids2.flow_stats when available
            try:
                flows = len(nids2.flow_stats) if (nids2 is not None and hasattr(nids2, 'flow_stats')) else 0
            except Exception:
                flows = 0
            self.flow_count_var.set(f"Flows: {flows}")

        # schedule next poll
        self.after(self.poll_interval, self._process_packet_queue)

    def _on_close(self):
        # stop capture if running
        if self.running:
            self.stop_capture()
            # small wait to ensure sniffer thread stops
            time.sleep(0.2)
        self.destroy()


def main():
    # create and run GUI
    app = NIDSMonitor(iface='en0')
    app.mainloop()


if __name__ == '__main__':
    main()
