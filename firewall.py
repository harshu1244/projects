from scapy.all import *
import socket
import logging
from threading import Thread
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import subprocess
import json
import os
import sys
from datetime import datetime

# Configuration
RULES_FILE = "firewall_rules.json"
LOG_FILE = "firewall.log"
DEFAULT_RULES = {
    "blocked_ips": ["192.168.1.100", "10.0.0.5"],
    "blocked_ports": [23, 4444],
    "allowed_protocols": ["TCP", "UDP", "ICMP"],
    "enable_logging": True
}

class PersonalFirewall:
    def __init__(self):
        self.rules = self.load_rules()
        self.setup_logging()
        self.setup_iptables()
        
    def load_rules(self):
        """Load firewall rules from JSON file"""
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE) as f:
                return json.load(f)
        return DEFAULT_RULES
    
    def save_rules(self):
        """Save current rules to file"""
        with open(RULES_FILE, 'w') as f:
            json.dump(self.rules, f, indent=4)
    
    def setup_logging(self):
        """Configure packet logging"""
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    def setup_iptables(self):
        """Initialize basic iptables rules"""
        subprocess.run(["iptables -F"], shell=True)
        subprocess.run(["iptables -A INPUT -j DROP"], shell=True)
        subprocess.run(["iptables -A OUTPUT -j DROP"], shell=True)
        
        # Apply saved rules
        for ip in self.rules["blocked_ips"]:
            self.block_ip(ip)
        for port in self.rules["blocked_ports"]:
            self.block_port(port)
    
    def packet_handler(self, packet):
        """Process each network packet"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                
                # Check if packet should be blocked
                if self.should_block(packet):
                    self.log_packet(packet, blocked=True)
                    return
                
                self.log_packet(packet, blocked=False)
        except Exception as e:
            print(f"Packet processing error: {e}")
    
    def should_block(self, packet):
        """Determine if packet violates rules"""
        ip_layer = packet.getlayer(IP)
        transport_layer = packet.getlayer(TCP) or packet.getlayer(UDP)
        
        # Block by IP
        if ip_layer.src in self.rules["blocked_ips"]:
            return True
        if ip_layer.dst in self.rules["blocked_ips"]:
            return True
            
        # Block by port
        if transport_layer:
            if transport_layer.sport in self.rules["blocked_ports"]:
                return True
            if transport_layer.dport in self.rules["blocked_ports"]:
                return True
                
        # Block by protocol
        protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        if protocol_map.get(ip_layer.proto) not in self.rules["allowed_protocols"]:
            return True
            
        return False
    
    def log_packet(self, packet, blocked):
        """Log packet details"""
        if not self.rules["enable_logging"]:
            return
            
        ip_layer = packet.getlayer(IP)
        transport_layer = packet.getlayer(TCP) or packet.getlayer(UDP)
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": ip_layer.src,
            "dest_ip": ip_layer.dst,
            "protocol": ip_layer.proto,
            "action": "BLOCKED" if blocked else "ALLOWED"
        }
        
        if transport_layer:
            log_entry.update({
                "source_port": transport_layer.sport,
                "dest_port": transport_layer.dport
            })
        
        logging.info(json.dumps(log_entry))
    
    def block_ip(self, ip):
        """Block an IP address"""
        if ip not in self.rules["blocked_ips"]:
            self.rules["blocked_ips"].append(ip)
            self.save_rules()
        subprocess.run([f"iptables -A INPUT -s {ip} -j DROP"], shell=True)
        subprocess.run([f"iptables -A OUTPUT -d {ip} -j DROP"], shell=True)
    
    def block_port(self, port):
        """Block a port"""
        if port not in self.rules["blocked_ports"]:
            self.rules["blocked_ports"].append(port)
            self.save_rules()
        subprocess.run([f"iptables -A INPUT -p tcp --dport {port} -j DROP"], shell=True)
        subprocess.run([f"iptables -A INPUT -p udp --dport {port} -j DROP"], shell=True)
    
    def start_sniffing(self):
        """Start packet capture"""
        sniff(prn=self.packet_handler, store=0)

class FirewallGUI:
    def __init__(self, firewall):
        self.firewall = firewall
        self.root = tk.Tk()
        self.root.title("Python Personal Firewall")
        self.setup_ui()
    
    def setup_ui(self):
        """Create the user interface"""
        # Rule management frame
        rule_frame = ttk.LabelFrame(self.root, text="Firewall Rules")
        rule_frame.pack(padx=10, pady=10, fill="both")
        
        # Blocked IPs
        ttk.Label(rule_frame, text="Blocked IPs:").grid(row=0, column=0)
        self.ip_list = tk.Listbox(rule_frame, height=5)
        self.ip_list.grid(row=1, column=0)
        self.refresh_ip_list()
        
        ttk.Button(rule_frame, text="Add IP", command=self.add_ip).grid(row=2, column=0)
        ttk.Button(rule_frame, text="Remove IP", command=self.remove_ip).grid(row=3, column=0)
        
        # Blocked Ports
        ttk.Label(rule_frame, text="Blocked Ports:").grid(row=0, column=1)
        self.port_list = tk.Listbox(rule_frame, height=5)
        self.port_list.grid(row=1, column=1)
        self.refresh_port_list()
        
        ttk.Button(rule_frame, text="Add Port", command=self.add_port).grid(row=2, column=1)
        ttk.Button(rule_frame, text="Remove Port", command=self.remove_port).grid(row=3, column=1)
        
        # Logging controls
        self.logging_var = tk.BooleanVar(value=self.firewall.rules["enable_logging"])
        ttk.Checkbutton(rule_frame, text="Enable Logging", variable=self.logging_var, 
                       command=self.toggle_logging).grid(row=4, columnspan=2)
        
        # Log viewer
        log_frame = ttk.LabelFrame(self.root, text="Firewall Logs")
        log_frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        self.log_text = tk.Text(log_frame, height=10)
        self.log_text.pack(fill="both", expand=True)
        
        # Add Clear Log button
        log_btn_frame = ttk.Frame(log_frame)
        log_btn_frame.pack(fill='x', pady=5)
        
        ttk.Button(log_btn_frame, text="Clear Log", command=self.clear_log).pack(side='right')
        
        # Start/Stop buttons
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Start Firewall", command=self.start_firewall).pack(side="left")
        ttk.Button(btn_frame, text="Stop Firewall", command=self.stop_firewall).pack(side="left")
        
        # Start log refresh
        self.update_logs()
    
    def refresh_ip_list(self):
        """Update the IP list display"""
        self.ip_list.delete(0, tk.END)
        for ip in self.firewall.rules["blocked_ips"]:
            self.ip_list.insert(tk.END, ip)
    
    def refresh_port_list(self):
        """Update the port list display"""
        self.port_list.delete(0, tk.END)
        for port in self.firewall.rules["blocked_ports"]:
            self.port_list.insert(tk.END, port)
    
    def add_ip(self):
        """Add a new IP to block"""
        ip = simpledialog.askstring("Block IP", "Enter IP address to block:")
        if ip:
            self.firewall.block_ip(ip)
            self.refresh_ip_list()
    
    def remove_ip(self):
        """Remove a blocked IP"""
        selection = self.ip_list.curselection()
        if selection:
            ip = self.ip_list.get(selection[0])
            self.firewall.rules["blocked_ips"].remove(ip)
            self.firewall.save_rules()
            self.refresh_ip_list()
    
    def add_port(self):
        """Add a new port to block"""
        port = simpledialog.askinteger("Block Port", "Enter port number to block:")
        if port:
            self.firewall.block_port(port)
            self.refresh_port_list()
    
    def remove_port(self):
        """Remove a blocked port"""
        selection = self.port_list.curselection()
        if selection:
            port = int(self.port_list.get(selection[0]))
            self.firewall.rules["blocked_ports"].remove(port)
            self.firewall.save_rules()
            self.refresh_port_list()
    
    def toggle_logging(self):
        """Enable/disable logging"""
        self.firewall.rules["enable_logging"] = self.logging_var.get()
        self.firewall.save_rules()
    
    def clear_log(self):
        """Clear the log file and text widget"""
        try:
            # Clear the log file
            open(LOG_FILE, 'w').close()
            # Clear the log display
            self.log_text.delete(1.0, tk.END)
            messagebox.showinfo("Success", "Log file cleared")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear log: {str(e)}")
    
    def update_logs(self):
        """Refresh the log display"""
        try:
            with open(LOG_FILE, "r") as f:
                logs = f.readlines()[-50:]  # Show last 50 lines
                self.log_text.delete(1.0, tk.END)
                for log in logs:
                    self.log_text.insert(tk.END, log)
        except FileNotFoundError:
            pass
        
        self.root.after(5000, self.update_logs)  # Update every 5 seconds
    
    def start_firewall(self):
        """Start the firewall"""
        Thread(target=self.firewall.start_sniffing, daemon=True).start()
        messagebox.showinfo("Firewall", "Firewall started")
    
    def stop_firewall(self):
        """Stop the firewall"""
        # This is a simple implementation - in production you'd need a better way to stop sniffing
        messagebox.showwarning("Firewall", "Please close the application to stop the firewall")
    
    def run(self):
        """Run the GUI"""
        self.root.mainloop()

if __name__ == "__main__":
    firewall = PersonalFirewall()
    
    # Run in CLI mode or GUI mode
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        print("Starting firewall in CLI mode...")
        firewall.start_sniffing()
    else:
        gui = FirewallGUI(firewall)
        gui.run()
