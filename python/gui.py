from tkinter import *
from threading import Thread
from scapy.all import sniff

class NIDSGUI:
    def __init__(self, master):
        self.master = master
        self.master.geometry("420x200")
        self.master.title("NIDS")
        self.capturing = False
        self.packet_count = 0

        self.label = Label(master, text="Packets Captured: 0", font=("Arial", 16))
        self.label.pack(pady=20)

        self.start_button = Button(master, text="Start", command=self.start_capture, width=10)
        self.start_button.pack(side=LEFT, padx=40)

        self.stop_button = Button(master, text="Stop", command=self.stop_capture, width=10, state=DISABLED)
        self.stop_button.pack(side=RIGHT, padx=40)

    def start_capture(self):
        self.capturing = True
        self.packet_count = 0
        self.label.config(text="Packets Captured: 0")
        self.start_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)
        self.capture_thread = Thread(target=self.packet_capture)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_capture(self):
        self.capturing = False
        self.start_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)

    def packet_parser(self, packet):
        if self.capturing:
            self.packet_count += 1
            # Use after() to update label from the main thread
            self.master.after(0, lambda: self.label.config(text=f"Packets Captured: {self.packet_count}"))
            print(f"Packet {self.packet_count} captured")  # Debug print

    def packet_capture(self):
        # Remove iface to use default, or set to your actual interface
        sniff(prn=self.packet_parser, stop_filter=lambda x: not self.capturing)

if __name__ == "__main__":
    window = Tk()
    app = NIDSGUI(window)
    window.mainloop()