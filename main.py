# main.py
# An advanced proof-of-concept Intrusion Detection System (IDS) with a modern
# Tkinter GUI using the ttk themed widgets.
#
# GUI Features:
# - Modern, tabbed interface (Live Alerts & Configuration).
# - Real-time alert display with a dark theme.
# - Dynamic IP whitelist management (add/remove from GUI).
# - Adjustable detection thresholds for Port Scans and DDoS attacks.
# - Live statistics panel for packets analyzed and alerts detected.
# - Start, Stop, and Clear Log controls.

import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import scapy.all as scapy
import threading
import time
from collections import deque
import datetime
import queue
import ipaddress

# --- Default Configuration ---
LOG_FILE = "ids_alerts.log"

class SimpleIDS:
    """
    The core IDS engine. Handles packet sniffing and threat detection.
    It runs in a separate thread and communicates with the GUI via queues.
    """
    def __init__(self, alert_queue, stats_queue, config):
        """
        Initializes the IDS engine with dynamic configuration.
        Args:
            alert_queue (queue.Queue): Queue for sending alert messages to the GUI.
            stats_queue (queue.Queue): Queue for sending packet count updates.
            config (dict): A dictionary containing the IDS settings.
        """
        self.is_running = False
        self.sniffer_thread = None
        self.log_file = None
        self.alert_queue = alert_queue
        self.stats_queue = stats_queue
        self.config = config
        self.port_scan_tracker = {}
        self.ddos_tracker = {}

    def _feature_extractor(self, packet):
        # This function remains the same
        features = {}
        if packet.haslayer(scapy.IP):
            features['src_ip'] = packet[scapy.IP].src
            features['dst_ip'] = packet[scapy.IP].dst
            if packet.haslayer(scapy.TCP):
                features['protocol'] = 'TCP'
                features['src_port'] = packet[scapy.TCP].sport
                features['dst_port'] = packet[scapy.TCP].dport
                return features
            elif packet.haslayer(scapy.UDP):
                features['protocol'] = 'UDP'
                features['src_port'] = packet[scapy.UDP].sport
                features['dst_port'] = packet[scapy.UDP].dport
                return features
        return None

    def _detect_threats(self, features):
        threats = []
        src_ip = features['src_ip']
        current_time = time.time()
        
        # Rule 1: Suspicious Ports
        if features.get('dst_port') in self.config['suspicious_ports']:
            threats.append(f"Suspicious Port Access: Traffic to port {features['dst_port']}")
            
        # Rule 2: Port Scanning
        dst_port = features.get('dst_port')
        if src_ip not in self.port_scan_tracker: self.port_scan_tracker[src_ip] = deque()
        self.port_scan_tracker[src_ip].append((current_time, dst_port))
        while self.port_scan_tracker[src_ip] and self.port_scan_tracker[src_ip][0][0] < current_time - self.config['time_window']:
            self.port_scan_tracker[src_ip].popleft()
        unique_ports = {port for _, port in self.port_scan_tracker[src_ip]}
        if len(unique_ports) > self.config['port_scan_threshold']:
            threats.append(f"Potential Port Scan: {len(unique_ports)} unique ports targeted in {self.config['time_window']}s")
            self.port_scan_tracker[src_ip].clear()

        # Rule 3: DDoS Attack
        if src_ip not in self.ddos_tracker: self.ddos_tracker[src_ip] = [0, current_time]
        self.ddos_tracker[src_ip][0] += 1
        packet_count, start_time = self.ddos_tracker[src_ip]
        if current_time - start_time > self.config['ddos_time_window']:
            if packet_count > self.config['ddos_threshold']:
                threats.append(f"Potential DDoS Attack: {packet_count} packets in {self.config['ddos_time_window']:.2f}s")
            self.ddos_tracker[src_ip] = [1, current_time]
            
        return threats

    def _packet_handler(self, packet):
        self.stats_queue.put(1) # Signal that one packet was processed
        features = self._feature_extractor(packet)
        if features:
            if features['src_ip'] in self.config['ip_whitelist']:
                return
            threat_descriptions = self._detect_threats(features)
            for description in threat_descriptions:
                self._generate_alert(description, features)

    def _generate_alert(self, description, features):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_message = (
            f"--------------------------------------------------\n"
            f"[!] ALERT: Threat Detected!\n"
            f"    Timestamp: {timestamp}\n"
            f"    Description: {description}\n"
            f"    Source IP: {features.get('src_ip', 'N/A')}\n"
            f"    Destination IP: {features.get('dst_ip', 'N/A')}\n"
            f"    Protocol: {features.get('protocol', 'N/A')}\n"
            f"    Source Port: {features.get('src_port', 'N/A')}\n"
            f"    Destination Port: {features.get('dst_port', 'N/A')}\n"
            f"--------------------------------------------------"
        )
        self.alert_queue.put(alert_message)
        if self.log_file:
            self.log_file.write(alert_message + "\n\n")
            self.log_file.flush()

    def start_sniffing(self):
        if self.is_running: return
        try:
            self.log_file = open(LOG_FILE, "a")
        except IOError as e:
            self.alert_queue.put(f"ERROR: Could not open log file '{LOG_FILE}'. {e}")
            return
        self.is_running = True
        self.sniffer_thread = threading.Thread(
            target=lambda: scapy.sniff(prn=self._packet_handler, store=0, stop_filter=lambda p: not self.is_running)
        )
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

    def stop_sniffing(self):
        if not self.is_running: return
        self.is_running = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1.0)
        if self.log_file: self.log_file.close()

class IDS_GUI:
    """ The main class for the Tkinter GUI. """
    def __init__(self, root):
        self.root = root
        self.root.title("Modern IDS")
        self.root.geometry("800x600")
        self.ids = None
        self.alert_queue = queue.Queue()
        self.stats_queue = queue.Queue()
        self.packets_analyzed = 0
        self.alerts_detected = 0

        # --- Style Configuration ---
        style = ttk.Style(self.root)
        style.theme_use("clam") # A clean, modern theme
        style.configure("TNotebook.Tab", font=('Helvetica', 10, 'bold'))

        # --- Main Layout ---
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)
        
        # --- Control and Stats Frame ---
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        self._create_controls(top_frame)
        self._create_stats(top_frame)

        # --- Notebook for Tabs ---
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(expand=True, fill=tk.BOTH)
        self._create_alerts_tab()
        self._create_config_tab()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _create_controls(self, parent):
        controls_frame = ttk.LabelFrame(parent, text="Controls", padding="10")
        controls_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        self.start_button = ttk.Button(controls_frame, text="Start Sniffing", command=self.start_ids, width=15)
        self.start_button.pack(pady=5, padx=5, fill=tk.X)
        self.stop_button = ttk.Button(controls_frame, text="Stop Sniffing", command=self.stop_ids, state=tk.DISABLED, width=15)
        self.stop_button.pack(pady=5, padx=5, fill=tk.X)
        self.clear_log_button = ttk.Button(controls_frame, text="Clear Log", command=self.clear_log)
        self.clear_log_button.pack(pady=5, padx=5, fill=tk.X)

    def _create_stats(self, parent):
        stats_frame = ttk.LabelFrame(parent, text="Statistics", padding="10")
        stats_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        
        self.packets_var = tk.StringVar(value="Packets Analyzed: 0")
        ttk.Label(stats_frame, textvariable=self.packets_var, font=('Helvetica', 10)).pack(anchor="w")
        
        self.alerts_var = tk.StringVar(value="Alerts Detected: 0")
        ttk.Label(stats_frame, textvariable=self.alerts_var, font=('Helvetica', 10)).pack(anchor="w")

    def _create_alerts_tab(self):
        alerts_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(alerts_frame, text="Live Alerts")
        self.log_display = scrolledtext.ScrolledText(alerts_frame, state=tk.DISABLED, wrap=tk.WORD, bg="#2b2b2b", fg="#a9b7c6", font=("Consolas", 10))
        self.log_display.pack(expand=True, fill=tk.BOTH)

    def _create_config_tab(self):
        config_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(config_frame, text="Configuration")

        # Whitelist Management
        whitelist_frame = ttk.LabelFrame(config_frame, text="IP Whitelist", padding="10")
        whitelist_frame.pack(fill=tk.X, pady=5)
        
        self.whitelist_entry = ttk.Entry(whitelist_frame, width=40)
        self.whitelist_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        
        ttk.Button(whitelist_frame, text="Add", command=self.add_to_whitelist).pack(side=tk.LEFT, padx=5)
        ttk.Button(whitelist_frame, text="Remove", command=self.remove_from_whitelist).pack(side=tk.LEFT)
        
        self.whitelist_box = tk.Listbox(config_frame, height=6, bg="#f0f0f0")
        self.whitelist_box.pack(fill=tk.X, pady=5, padx=5)
        for ip in {"127.0.0.1", "192.168.1.1"}: self.whitelist_box.insert(tk.END, ip)

        # Thresholds Management
        thresholds_frame = ttk.LabelFrame(config_frame, text="Detection Thresholds", padding="10")
        thresholds_frame.pack(fill=tk.X, pady=5, expand=True)
        
        ttk.Label(thresholds_frame, text="Port Scan Threshold:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.port_scan_var = tk.StringVar(value="15")
        ttk.Entry(thresholds_frame, textvariable=self.port_scan_var, width=10).grid(row=0, column=1, sticky="w", padx=5, pady=2)
        
        ttk.Label(thresholds_frame, text="DDoS Threshold (packets/sec):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.ddos_var = tk.StringVar(value="1000")
        ttk.Entry(thresholds_frame, textvariable=self.ddos_var, width=10).grid(row=1, column=1, sticky="w", padx=5, pady=2)

    def start_ids(self):
        try:
            config = {
                'ip_whitelist': set(self.whitelist_box.get(0, tk.END)),
                'suspicious_ports': {21, 22, 23, 25, 53, 110, 139, 445, 3389, 8080},
                'port_scan_threshold': int(self.port_scan_var.get()),
                'time_window': 60,
                'ddos_threshold': int(self.ddos_var.get()),
                'ddos_time_window': 1
            }
        except ValueError:
            messagebox.showerror("Invalid Input", "Threshold values must be integers.")
            return

        self.log_message("Starting network traffic monitoring...")
        self.ids = SimpleIDS(self.alert_queue, self.stats_queue, config)
        self.ids.start_sniffing()

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.process_queues()

    def stop_ids(self):
        if self.ids:
            self.ids.stop_sniffing()
            self.log_message("Monitoring stopped.")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def process_queues(self):
        try:
            while True:
                message = self.alert_queue.get_nowait()
                self.log_message(message)
                self.alerts_detected += 1
        except queue.Empty: pass
        
        try:
            while True:
                self.packets_analyzed += self.stats_queue.get_nowait()
        except queue.Empty: pass

        self.packets_var.set(f"Packets Analyzed: {self.packets_analyzed}")
        self.alerts_var.set(f"Alerts Detected: {self.alerts_detected}")
        self.root.after(100, self.process_queues)

    def log_message(self, message):
        self.log_display.config(state=tk.NORMAL)
        self.log_display.insert(tk.END, message + "\n")
        self.log_display.see(tk.END)
        self.log_display.config(state=tk.DISABLED)

    def clear_log(self):
        self.log_display.config(state=tk.NORMAL)
        self.log_display.delete(1.0, tk.END)
        self.log_display.config(state=tk.DISABLED)

    def add_to_whitelist(self):
        ip = self.whitelist_entry.get().strip()
        if not ip: return
        try:
            ipaddress.ip_address(ip) # Validate IP address
            if ip not in self.whitelist_box.get(0, tk.END):
                self.whitelist_box.insert(tk.END, ip)
                self.whitelist_entry.delete(0, tk.END)
        except ValueError:
            messagebox.showerror("Invalid IP", f"'{ip}' is not a valid IP address.")

    def remove_from_whitelist(self):
        selected_indices = self.whitelist_box.curselection()
        for i in reversed(selected_indices):
            self.whitelist_box.delete(i)

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit? This will stop the IDS."):
            self.stop_ids()
            self.root.destroy()

def main():
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

