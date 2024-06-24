# nmap_scan.py
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
import nmap
import threading


def run_nmap_scan(target, output_text_box):
    output_text_box.delete('1.0', tk.END)
    output_text_box.insert(tk.END, "Please wait while scanning...\n")
    output_text_box.update()

    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-sV')

    output_text_box.delete('1.0', tk.END)
    for host in scanner.all_hosts():
        output_text_box.insert(tk.END, f'Host : {host} ({scanner[host].hostname()})\n')
        output_text_box.insert(tk.END, f'State : {scanner[host].state()}\n')
        for proto in scanner[host].all_protocols():
            output_text_box.insert(tk.END, f'----------\n')
            output_text_box.insert(tk.END, f'Protocol : {proto}\n')
            lport = scanner[host][proto].keys()
            for port in lport:
                output_text_box.insert(tk.END, f'port : {port}\tstate : {scanner[host][proto][port]["state"]}\n')
                output_text_box.insert(tk.END,
                                       f'service : {scanner[host][proto][port]["name"]}\tversion : {scanner[host][proto][port]["version"]}\n')


def start_nmap_scan(target, output_text_box):
    threading.Thread(target=run_nmap_scan, args=(target, output_text_box)).start()


def setup_nmap_scan_tab(notebook, target_var):
    nmap_scan_tab = ttk.Frame(notebook)
    notebook.add(nmap_scan_tab, text="Nmap Scan")

    nmap_target_label = ctk.CTkLabel(master=nmap_scan_tab, text="Target Host:")
    nmap_target_label.pack(pady=10)

    nmap_target_entry = ctk.CTkEntry(master=nmap_scan_tab, textvariable=target_var, width=200)
    nmap_target_entry.pack(pady=5)

    nmap_output_frame = ctk.CTkFrame(master=nmap_scan_tab)
    nmap_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

    global nmap_output_text_box
    nmap_output_text_box = ctk.CTkTextbox(master=nmap_output_frame, height=20, width=600)
    nmap_output_text_box.pack(side="left", fill="both", expand=True)

    nmap_scrollbar = ttk.Scrollbar(master=nmap_output_frame, orient="vertical", command=nmap_output_text_box.yview)
    nmap_scrollbar.pack(side="right", fill="y")
    nmap_output_text_box.configure(yscrollcommand=nmap_scrollbar.set)

    start_nmap_scan_button = ctk.CTkButton(master=nmap_scan_tab, text="Run Nmap Scan",
                                           command=lambda: start_nmap_scan(target_var.get(), nmap_output_text_box))
    start_nmap_scan_button.pack(pady=10)
