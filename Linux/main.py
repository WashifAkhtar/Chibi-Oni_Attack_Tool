import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from host_discovery import start_host_discovery
from port_scanning import start_port_scan
from network_statistics import start_network_statistics
from ddos_attack import start_ddos_attack, stop_ddos_attack
from custom_widgets import CustomLabel, CustomEntry, CustomButton, CustomTextBox, CustomScrollbar

# Create the main window
window = ctk.CTk()
window.geometry("800x600")
window.title("Custom Zenmap GUI")

# Create a notebook (tab container)
notebook = ttk.Notebook(window)
notebook.pack(expand=True, fill="both")

# Host Discovery tab content
host_discovery_tab = ttk.Frame(notebook)
notebook.add(host_discovery_tab, text="Host Discovery")

host_discovery_label = CustomLabel(master=host_discovery_tab, text="Target Range:")
host_discovery_label.pack(pady=10)

host_discovery_target_entry = CustomEntry(master=host_discovery_tab, width=200)
host_discovery_target_entry.pack(pady=5)

host_discovery_button = CustomButton(master=host_discovery_tab, text="Start Host Discovery", command=lambda: start_host_discovery(host_discovery_target_entry, host_discovery_output_text_box))
host_discovery_button.pack(pady=10)

host_discovery_output_frame = ctk.CTkFrame(master=host_discovery_tab)
host_discovery_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

host_discovery_output_text_box = CustomTextBox(master=host_discovery_output_frame, height=20, width=600)
host_discovery_output_text_box.pack(side="left", fill="both", expand=True)

host_discovery_scrollbar = CustomScrollbar(master=host_discovery_output_frame, command=host_discovery_output_text_box.yview)
host_discovery_scrollbar.pack(side="right", fill="y")
host_discovery_output_text_box.configure(yscrollcommand=host_discovery_scrollbar.set)

# Port Scanning tab content
port_scan_tab = ttk.Frame(notebook)
notebook.add(port_scan_tab, text="Port Scanning")

port_scan_label = CustomLabel(master=port_scan_tab, text="Target Host:")
port_scan_label.pack(pady=10)

port_scan_target_entry = CustomEntry(master=port_scan_tab, width=200)
port_scan_target_entry.pack(pady=5)

start_port_scan_button = CustomButton(master=port_scan_tab, text="Start Port Scan", command=lambda: start_port_scan(port_scan_target_entry, port_scan_output_text_box))
start_port_scan_button.pack(pady=10)

port_scan_output_frame = ctk.CTkFrame(master=port_scan_tab)
port_scan_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

port_scan_output_text_box = CustomTextBox(master=port_scan_output_frame, height=20, width=600)
port_scan_output_text_box.pack(side="left", fill="both", expand=True)

port_scan_scrollbar = CustomScrollbar(master=port_scan_output_frame, command=port_scan_output_text_box.yview)
port_scan_scrollbar.pack(side="right", fill="y")
port_scan_output_text_box.configure(yscrollcommand=port_scan_scrollbar.set)

# Network Statistics tab content
network_statistics_tab = ttk.Frame(notebook)
notebook.add(network_statistics_tab, text="Network Statistics")

network_statistics_label = CustomLabel(master=network_statistics_tab, text="Capture Duration (seconds):")
network_statistics_label.pack(pady=10)

network_statistics_duration_entry = CustomEntry(master=network_statistics_tab, width=200)
network_statistics_duration_entry.insert(0, "120")
network_statistics_duration_entry.pack(pady=5)

start_network_statistics_button = CustomButton(master=network_statistics_tab, text="Start Network Statistics", command=lambda: start_network_statistics(network_statistics_duration_entry, network_statistics_output_text_box))
start_network_statistics_button.pack(pady=10)

network_statistics_output_frame = ctk.CTkFrame(master=network_statistics_tab)
network_statistics_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

network_statistics_output_text_box = CustomTextBox(master=network_statistics_output_frame, height=20, width=600)
network_statistics_output_text_box.pack(side="left", fill="both", expand=True)

network_statistics_scrollbar = CustomScrollbar(master=network_statistics_output_frame, command=network_statistics_output_text_box.yview)
network_statistics_scrollbar.pack(side="right", fill="y")
network_statistics_output_text_box.configure(yscrollcommand=network_statistics_scrollbar.set)

# DDOS Attack tab content
ddos_attack_tab = ttk.Frame(notebook)
notebook.add(ddos_attack_tab, text="DDOS Attack")

ddos_target_label = CustomLabel(master=ddos_attack_tab, text="Target Address:")
ddos_target_label.pack(pady=10)

ddos_target_entry = CustomEntry(master=ddos_attack_tab, width=200)
ddos_target_entry.pack(pady=5)

ddos_port_label = CustomLabel(master=ddos_attack_tab, text="Target Port:")
ddos_port_label.pack(pady=10)

ddos_port_entry = CustomEntry(master=ddos_attack_tab, width=200)
ddos_port_entry.pack(pady=5)
ddos_port_entry.insert(0, "80")

attack_type_var = tk.StringVar(value="Slowloris")

slowloris_radio_button = ctk.CTkRadioButton(master=ddos_attack_tab, text="Slowloris Attack", variable=attack_type_var, value="Slowloris")
slowloris_radio_button.pack(pady=5)

syn_flood_radio_button = ctk.CTkRadioButton(master=ddos_attack_tab, text="SYN Flood Attack (coming soon)", variable=attack_type_var, value="SYN Flood", state=tk.DISABLED)
syn_flood_radio_button.pack(pady=5)

start_ddos_attack_button = CustomButton(master=ddos_attack_tab, text="Start Attack", command=lambda: start_ddos_attack(ddos_target_entry, ddos_port_entry, attack_type_var, ddos_output_text_box))
start_ddos_attack_button.pack(pady=10)

stop_ddos_attack_button = CustomButton(master=ddos_attack_tab, text="Stop Attack", command=stop_ddos_attack)
stop_ddos_attack_button.pack(pady=10)

ddos_output_frame = ctk.CTkFrame(master=ddos_attack_tab)
ddos_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

ddos_output_text_box = CustomTextBox(master=ddos_output_frame, height=20, width=600)
ddos_output_text_box.pack(side="left", fill="both", expand=True)

ddos_scrollbar = CustomScrollbar(master=ddos_output_frame, command=ddos_output_text_box.yview)
ddos_scrollbar.pack(side="right", fill="y")
ddos_output_text_box.configure(yscrollcommand=ddos_scrollbar.set)

# Display descriptions for attack types in the output box initially
ddos_output_text_box.insert(tk.END, "Slowloris Attack: A type of Denial-of-Service (DoS) attack that sends partial HTTP requests to keep many connections to the target web server open and hold them open as long as possible.\n\n")
ddos_output_text_box.insert(tk.END, "SYN Flood Attack: A type of Denial-of-Service (DoS) attack that exploits the TCP handshake process by sending many SYN packets to a target server, overwhelming its resources. (Coming soon)\n\n")

# Run the main loop
window.mainloop()
