#!/usr/bin/env python3

import ipaddress
import platform
import socket
import os
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import threading
import sys

try:
    import scapy.all as scapy
except ImportError:
    print("Error: Scapy is not installed. Please install it with 'pip install scapy'")
    sys.exit(1)

def validate_ip_range(ip_range):
    """Validate the IP range format and return True if valid"""
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False

def get_os_from_ttl(ttl):
    """Guess OS based on initial TTL value"""
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Solaris/Cisco"
    return "Unknown"

def scan(ip_range):
    """Scan the network and return list of devices with OS info"""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc

        ping = scapy.IP(dst=ip) / scapy.ICMP()
        response = scapy.sr1(ping, timeout=1, verbose=False)

        ttl = response[scapy.IP].ttl if response else None
        os_guess = get_os_from_ttl(ttl) if ttl else "Unknown"

        device_info = {
            "ip": ip,
            "mac": mac,
            "os": os_guess,
            "version": "Unknown",
            "hostname": None
        }
        devices.append(device_info)

    return devices

def get_device_name(ip):
    """Try to get the device name (hostname) from the IP address"""
    try:
        host = socket.gethostbyaddr(ip)
        return host[0]
    except socket.herror:
        return "Unknown"

class NetworkScannerGUI(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack(fill="both", expand=True)
        self.create_widgets()

    def create_widgets(self):
        # Input frame at the top
        self.input_frame = tk.Frame(self)
        self.input_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        tk.Label(self.input_frame, text="IP Range:").pack(side="left")
        self.entry = tk.Entry(self.input_frame, width=30)
        self.entry.pack(side="left", padx=5)
        self.scan_button = tk.Button(self.input_frame, text="Scan", command=self.start_scan)
        self.scan_button.pack(side="left")

        # Treeview for results
        self.tree = ttk.Treeview(
            self,
            columns=("IP", "MAC", "Hostname", "OS", "Version"),
            show="headings"
        )
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("MAC", text="MAC Address")
        self.tree.heading("Hostname", text="Hostname")
        self.tree.heading("OS", text="OS")
        self.tree.heading("Version", text="Version")
        self.tree.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # Add scrollbar
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.grid(row=1, column=1, sticky="ns")

        # Status label
        self.status = tk.StringVar()
        self.status.set("")
        tk.Label(self, textvariable=self.status).grid(row=2, column=0, sticky="ew", padx=5, pady=5)

        # Make the Treeview expand with window resize
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

    def start_scan(self):
        """Initiate the scan when the button is clicked"""
        ip_range = self.entry.get().strip()
        if not validate_ip_range(ip_range):
            messagebox.showerror("Error", "Invalid IP range format. Use e.g., '192.168.1.0/24'")
            return

        self.status.set("Scanning...")
        self.scan_button.config(state="disabled")
        self.tree.delete(*self.tree.get_children())  # Clear previous results

        # Start scan in a separate thread
        thread = threading.Thread(target=self.run_scan, args=(ip_range,))
        thread.start()

    def run_scan(self, ip_range):
        """Run the scan in a background thread"""
        try:
            devices = scan(ip_range)
            for device in devices:
                device["hostname"] = get_device_name(device["ip"])
            # Sort devices by IP address in ascending order
            devices = sorted(devices, key=lambda x: ipaddress.ip_address(x["ip"]))
            self.master.after(0, self.update_results, devices)
        except Exception as e:
            self.master.after(0, self.show_error, str(e))

    def update_results(self, devices):
        """Update the Treeview with scan results"""
        for device in devices:
            self.tree.insert(
                "", "end",
                values=(device["ip"], device["mac"], device["hostname"], device["os"], device["version"])
            )
        self.status.set("Scan complete")
        self.scan_button.config(state="normal")

    def show_error(self, message):
        """Display an error message to the user"""
        messagebox.showerror("Error", message)
        self.status.set("Scan failed")
        self.scan_button.config(state="normal")

def main():
    """Launch the GUI application"""
    root = tk.Tk()
    root.title("Network Scanner")
    root.geometry("800x600")  # Set initial window size
    app = NetworkScannerGUI(master=root)
    app.mainloop()

if __name__ == "__main__":
    main()