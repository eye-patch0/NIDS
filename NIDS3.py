import sys
import socket
import threading
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, IPv6, ARP, Ether, Dot11
from scapy.layers.l2 import getmacbyip
import pandas as pd
import tkinter as tk
import json
from tkinter import ttk, messagebox, filedialog
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import queue
import mac_vendor_lookup

class NIDSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Intrusion Detection System")
        self.root.geometry("1200x800")

        # Initialize variables
        self.packet_count = 0
        self.threat_count = 0
        self.is_sniffing = False
        self.packet_buffer = []
        self.packet_queue = queue.Queue()
        self.threat_queue = queue.Queue()
        self.known_threats = self.load_threat_signatures()
        self.ml_model = self.load_ml_model()
        self.devices = {}
        self.arp_table = {}
        self.vendor_lookup = mac_vendor_lookup.MacLookup()
        
        try:
            self.vendor_lookup.update_vendors()
        except:
            pass

        # Setup GUI
        self.setup_gui()
        self.update_stats()
        self.root.after(1000, self.periodic_update)
        self.initialize_json_files()

    def setup_gui(self):
        self.tab_control = ttk.Notebook(self.root)
        
        # Create tabs
        self.dashboard_tab = ttk.Frame(self.tab_control)
        self.packet_tab = ttk.Frame(self.tab_control)
        self.threat_tab = ttk.Frame(self.tab_control)
        self.device_tab = ttk.Frame(self.tab_control)
        
        self.tab_control.add(self.dashboard_tab, text='Dashboard')
        self.tab_control.add(self.packet_tab, text='Packet Inspector')
        self.tab_control.add(self.threat_tab, text='Threat Log')
        self.tab_control.add(self.device_tab, text='Network Devices')
        self.tab_control.pack(expand=1, fill='both')

        # Dashboard Tab
        self.setup_dashboard_tab()
        # Packet Inspector Tab
        self.setup_packet_tab()
        # Threat Log Tab
        self.setup_threat_tab()
        # Network Devices Tab
        self.setup_device_tab()
        # Control Buttons
        self.setup_control_buttons()
        # Traffic Plot
        self.setup_traffic_plot()

    def setup_dashboard_tab(self):
        self.status_frame = tk.Frame(self.dashboard_tab)
        self.status_frame.pack(pady=20)
        
        self.stats_label = tk.Label(self.status_frame, text="System Status: Not Running", 
                                  font=('Arial', 12, 'bold'), fg='red')
        self.stats_label.pack()
        
        self.packet_count_label = tk.Label(self.status_frame, text="Packets Analyzed: 0", 
                                         font=('Arial', 10))
        self.packet_count_label.pack()
        
        self.threat_count_label = tk.Label(self.status_frame, text="Threats Detected: 0", 
                                         font=('Arial', 10))
        self.threat_count_label.pack()

    def setup_packet_tab(self):
        self.packet_frame = ttk.Frame(self.packet_tab)
        self.packet_frame.pack(expand=1, fill='both')
        
        columns = [
            ("time", "Time", 150),
            ("src", "Source IP", 120),
            ("dst", "Dest IP", 120),
            ("sport", "Src Port", 80),
            ("dport", "Dest Port", 80),
            ("proto", "Protocol", 80),
            ("len", "Length", 80),
            ("flags", "Flags", 80)
        ]
        
        self.packet_tree = ttk.Treeview(self.packet_frame, columns=[c[0] for c in columns], show='headings')
        for col_id, heading, width in columns:
            self.packet_tree.heading(col_id, text=heading)
            self.packet_tree.column(col_id, width=width, anchor='center')
        
        y_scroll = ttk.Scrollbar(self.packet_frame, orient='vertical', command=self.packet_tree.yview)
        x_scroll = ttk.Scrollbar(self.packet_frame, orient='horizontal', command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        self.packet_tree.grid(row=0, column=0, sticky='nsew')
        y_scroll.grid(row=0, column=1, sticky='ns')
        x_scroll.grid(row=1, column=0, sticky='ew')
        
        self.packet_frame.grid_rowconfigure(0, weight=1)
        self.packet_frame.grid_columnconfigure(0, weight=1)

    def setup_threat_tab(self):
        self.threat_frame = ttk.Frame(self.threat_tab)
        self.threat_frame.pack(expand=1, fill='both')
        
        threat_columns = [
            ("time", "Time", 150),
            ("src", "Source IP", 120),
            ("dst", "Dest IP", 120),
            ("dport", "Dest Port", 80),
            ("type", "Threat Type", 120),
            ("severity", "Severity", 80),
            ("desc", "Description", 300)
        ]
        
        self.threat_tree = ttk.Treeview(self.threat_frame, columns=[c[0] for c in threat_columns], show='headings')
        for col_id, heading, width in threat_columns:
            self.threat_tree.heading(col_id, text=heading)
            self.threat_tree.column(col_id, width=width, anchor='center')
        
        y_scroll = ttk.Scrollbar(self.threat_frame, orient='vertical', command=self.threat_tree.yview)
        x_scroll = ttk.Scrollbar(self.threat_frame, orient='horizontal', command=self.threat_tree.xview)
        self.threat_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        self.threat_tree.grid(row=0, column=0, sticky='nsew')
        y_scroll.grid(row=0, column=1, sticky='ns')
        x_scroll.grid(row=1, column=0, sticky='ew')
        
        self.threat_frame.grid_rowconfigure(0, weight=1)
        self.threat_frame.grid_columnconfigure(0, weight=1)

        self.export_frame = tk.Frame(self.threat_tab)
        self.export_frame.pack(fill='x', padx=5, pady=5)
        self.export_btn = tk.Button(self.export_frame, text="Export to CSV", command=self.export_threats_to_csv)
        self.export_btn.pack(side='right')

    def setup_device_tab(self):
        self.device_frame = ttk.Frame(self.device_tab)
        self.device_frame.pack(expand=1, fill='both')
        
        device_columns = [
            ("mac", "MAC Address", 150),
            ("ips", "IP Addresses", 200),
            ("vendor", "Vendor", 200),
            ("first_seen", "First Seen", 150),
            ("last_seen", "Last Seen", 150)
        ]
        
        self.device_tree = ttk.Treeview(self.device_frame, columns=[c[0] for c in device_columns], show='headings')
        for col_id, heading, width in device_columns:
            self.device_tree.heading(col_id, text=heading)
            self.device_tree.column(col_id, width=width, anchor='center')
        
        y_scroll = ttk.Scrollbar(self.device_frame, orient='vertical', command=self.device_tree.yview)
        x_scroll = ttk.Scrollbar(self.device_frame, orient='horizontal', command=self.device_tree.xview)
        self.device_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        self.device_tree.grid(row=0, column=0, sticky='nsew')
        y_scroll.grid(row=0, column=1, sticky='ns')
        x_scroll.grid(row=1, column=0, sticky='ew')
        
        self.device_frame.grid_rowconfigure(0, weight=1)
        self.device_frame.grid_columnconfigure(0, weight=1)

    def setup_control_buttons(self):
        self.control_frame = tk.Frame(self.root)
        self.control_frame.pack(pady=10)
        
        self.start_btn = tk.Button(self.control_frame, text="Start Capture", 
                                 command=self.start_capture, width=15)
        self.start_btn.grid(row=0, column=0, padx=5)
        
        self.stop_btn = tk.Button(self.control_frame, text="Stop Capture", 
                                state='disabled', command=self.stop_capture, width=15)
        self.stop_btn.grid(row=0, column=1, padx=5)

    def setup_traffic_plot(self):
        self.plot_frame = tk.Frame(self.root)
        self.plot_frame.pack(fill='both', expand=True)
        
        self.figure = plt.Figure(figsize=(10, 4), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.ax.set_title('Network Traffic Over Time')
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Packets per Second')
        
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.plot_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
        
        self.timestamps = []
        self.packet_rates = []

    def load_threat_signatures(self):
        return {
            "Port Scan": {"flags": "S", "threshold": 10},
            "DDoS": {"packet_size": 0, "threshold": 100},
            "Malicious Payload": {"keywords": ["<script>", "DROP TABLE"]},
            "ARP Spoofing": {"description": "MAC-IP pair conflict"}
        }

    def load_ml_model(self):
        try:
            model = RandomForestClassifier(n_estimators=10)
            X = np.random.rand(100, 6)
            y = np.random.randint(0, 2, 100)
            model.fit(X, y)
            return model
        except Exception as e:
            print(f"ML model error: {e}")
            return None

    def periodic_update(self):
        self.update_stats()
        self.update_traffic_plot()

        while not self.packet_queue.empty():
            packet_info = self.packet_queue.get()
            self.store_packet(packet_info)

        while not self.threat_queue.empty():
            threat_details = self.threat_queue.get()
            self.store_threat(threat_details)

        self.root.after(1000, self.periodic_update)

    def update_traffic_plot(self):
        if len(self.timestamps) > 20:
            self.timestamps = self.timestamps[-20:]
            self.packet_rates = self.packet_rates[-20:]

        self.ax.clear()
        if self.timestamps:
            self.ax.plot(range(len(self.timestamps)), self.packet_rates, 'b-')
            self.ax.set_xticks(range(len(self.timestamps)))
            self.ax.set_xticklabels(self.timestamps, rotation=45)
            self.canvas.draw()

    def start_capture(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            self.stats_label.config(text="System Status: Running", fg='green')
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
            capture_thread = threading.Thread(target=self.packet_capture_loop, daemon=True)
            capture_thread.start()

    def stop_capture(self):
        if self.is_sniffing:
            self.is_sniffing = False
            self.stats_label.config(text="System Status: Not Running", fg='red')
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')

    def packet_capture_loop(self):
        while self.is_sniffing:
            try:
                sniff(prn=self.process_packet, timeout=1, store=False)
            except Exception as e:
                print(f"Packet capture error: {e}")

    def process_packet(self, packet):
        try:
            self.packet_count += 1
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            src_ip = dst_ip = src_mac = dst_mac = protocol = 'N/A'
            src_port = dst_port = 0
            flags = ''
            length = len(packet)

            # Ethernet layer
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                self.track_device(src_mac)
                self.track_device(dst_mac)

            # IP layers
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = 'IPv4'
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                protocol = 'IPv6'

            # ARP layer
            if packet.haslayer(ARP):
                protocol = 'ARP'
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst
                src_mac = packet[ARP].hwsrc
                self.detect_arp_spoofing(packet)

            # Transport layers
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = str(packet[TCP].flags)
                protocol = 'TCP'
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = 'UDP'

            # Wireless
            if packet.haslayer(Dot11):
                protocol = '802.11'
                if packet.type == 0:  # Management frame
                    src_mac = packet.addr2
                elif packet.type == 2:  # Data frame
                    src_mac = packet.addr2
                    dst_mac = packet.addr1

            packet_info = {
                'timestamp': current_time,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'length': length,
                'flags': flags,
                'threat_type': ''
            }

            self.packet_buffer.append(packet_info)
            self.timestamps.append(datetime.now().strftime('%H:%M:%S'))
            self.packet_rates.append(len(self.packet_buffer))

            threat = self.detect_threats(packet_info)
            if threat:
                self.threat_count += 1
                packet_info['threat_type'] = threat
                self.log_threat(packet_info)

            self.add_packet_to_table(packet_info)
            self.packet_queue.put(packet_info)

        except Exception as e:
            print(f"Error processing packet: {e}")

    def detect_threats(self, packet_info):
        # Signature-based detection
        if packet_info['protocol'] == 'TCP' and packet_info['flags'] == 'S':
            syn_count = sum(1 for p in self.packet_buffer[-100:] 
                          if p['src_ip'] == packet_info['src_ip'] and p['flags'] == 'S')
            if syn_count > self.known_threats['Port Scan']['threshold']:
                return "Port Scan"

        if packet_info['length'] < 50:
            small_pkt_count = sum(1 for p in self.packet_buffer[-100:] 
                                  if p['src_ip'] == packet_info['src_ip'] and p['length'] < 50)
            if small_pkt_count > self.known_threats['DDoS']['threshold']:
                return "DDoS Attack"

        # ML-based detection
        if self.ml_model:
            try:
                features = self.extract_features(packet_info)
                proba = self.ml_model.predict_proba([features])[0][1]
                if proba > 0.8:
                    return "Anomaly Detected"
            except Exception as e:
                print(f"ML detection error: {e}")

        return ""

    def extract_features(self, packet_info):
        return [
            len(packet_info['src_ip']),
            packet_info['src_port'],
            packet_info['dst_port'],
            packet_info['length'],
            1 if packet_info['protocol'] == 'TCP' else 0,
            1 if packet_info['protocol'] == 'UDP' else 0
        ]

    def add_packet_to_table(self, packet_info):
        values = (
            packet_info['timestamp'],
            packet_info['src_ip'],
            packet_info['dst_ip'],
            packet_info['src_port'],
            packet_info['dst_port'],
            packet_info['protocol'],
            packet_info['length'],
            packet_info['flags']
        )
        self.packet_tree.insert('', 'end', values=values)
        self.packet_tree.yview_moveto(1)

    def log_threat(self, packet_info):
        threat_details = {
            'timestamp': packet_info['timestamp'],
            'src_ip': packet_info['src_ip'],
            'dst_ip': packet_info['dst_ip'],
            'dport': packet_info['dst_port'],
            'threat_type': packet_info['threat_type'],
            'description': self.get_threat_description(packet_info['threat_type']),
            'severity': self.get_threat_severity(packet_info['threat_type'])
        }

        self.threat_tree.insert('', 'end', values=(
            threat_details['timestamp'],
            threat_details['src_ip'],
            threat_details['dst_ip'],
            threat_details['dport'],
            threat_details['threat_type'],
            threat_details['severity'],
            threat_details['description']
        ))
        self.threat_tree.yview_moveto(1)
        self.threat_queue.put(threat_details)

    def get_threat_description(self, threat_type):
        descriptions = {
            "Port Scan": "Multiple SYN packets from same source",
            "DDoS Attack": "High volume of small packets from same source",
            "Anomaly Detected": "Machine learning detected suspicious pattern",
            "ARP Spoofing": "Conflicting MAC-IP pairs detected",
            "": "No threat detected"
        }
        return descriptions.get(threat_type, "Unknown threat pattern")

    def get_threat_severity(self, threat_type):
        severities = {
            "Port Scan": "Medium",
            "DDoS Attack": "High",
            "Anomaly Detected": "Low",
            "ARP Spoofing": "High",
            "": "None"
        }
        return severities.get(threat_type, "Unknown")

    def track_device(self, mac, ip=None):
        if not mac or mac == 'ff:ff:ff:ff:ff:ff':
            return
            
        try:
            vendor = self.vendor_lookup.lookup(mac)
        except:
            vendor = "Unknown"

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if mac in self.devices:
            self.devices[mac]['last_seen'] = now
            if ip and ip not in self.devices[mac]['ips']:
                self.devices[mac]['ips'].append(ip)
        else:
            self.devices[mac] = {
                'mac': mac,
                'ips': [ip] if ip else [],
                'vendor': vendor,
                'first_seen': now,
                'last_seen': now
            }
        
        self.update_device_tree()

    def update_device_tree(self):
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        for mac, info in self.devices.items():
            ips = '\n'.join(info['ips']) if info['ips'] else 'N/A'
            self.device_tree.insert('', 'end', values=(
                mac,
                ips,
                info['vendor'],
                info['first_seen'],
                info['last_seen']
            ))

    def detect_arp_spoofing(self, packet):
        if packet[ARP].op == 2:  # ARP response
            src_mac = packet[ARP].hwsrc
            src_ip = packet[ARP].psrc
            
            if src_mac in self.arp_table:
                if self.arp_table[src_mac] != src_ip:
                    threat_details = {
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'src_mac': src_mac,
                        'src_ip': src_ip,
                        'threat_type': 'ARP Spoofing',
                        'description': f"MAC {src_mac} changed IP from {self.arp_table[src_mac]} to {src_ip}",
                        'severity': 'High'
                    }
                    self.threat_queue.put(threat_details)
            else:
                self.arp_table[src_mac] = src_ip

    def initialize_json_files(self):
        try:
            with open('packets.json', 'w') as f:
                json.dump([], f)
            with open('threats.json', 'w') as f:
                json.dump([], f)
        except Exception as e:
            print(f"Error initializing JSON files: {e}")

    def store_packet(self, packet_info):
        try:
            with open('packets.json', 'r+') as f:
                data = json.load(f)
                data.append(packet_info)
                f.seek(0)
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"Error storing packet: {e}")

    def store_threat(self, threat_details):
        try:
            with open('threats.json', 'r+') as f:
                data = json.load(f)
                data.append(threat_details)
                f.seek(0)
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"Error storing threat: {e}")

    def export_threats_to_csv(self):
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            
            if filename:
                with open('threats.json', 'r') as f:
                    threats = json.load(f)

                if threats:
                    df = pd.DataFrame(threats)
                    df.to_csv(filename, index=False)
                    messagebox.showinfo("Success", f"Threat log exported to {filename}")
                else:
                    messagebox.showwarning("Warning", "No threats found to export")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export threats: {str(e)}")

    def update_stats(self):
        self.packet_count_label.config(text=f"Packets Analyzed: {self.packet_count}")
        self.threat_count_label.config(text=f"Threats Detected: {self.threat_count}")

    def on_closing(self):
        self.stop_capture()
        self.root.destroy()
        sys.exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = NIDSGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
