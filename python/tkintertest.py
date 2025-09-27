import tkinter as tk

class SimpleNIDSInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple NIDS Interface")
        self.status_var = tk.StringVar(value="Status: Idle")

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Network Intrusion Detection System", font=("Helvetica", 16)).pack(pady=10)

        tk.Button(self.root, text="Start Capture", command=self.start_capture, width=20).pack(pady=5)
        tk.Button(self.root, text="Stop Capture", command=self.stop_capture, width=20).pack(pady=5)

        tk.Label(self.root, textvariable=self.status_var, font=("Helvetica", 12)).pack(pady=10)

    def start_capture(self):
        self.status_var.set("Status: Running")

    def stop_capture(self):
        self.status_var.set("Status: Stopped")

if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleNIDSInterface(root)
    root.mainloop()
