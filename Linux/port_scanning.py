# port_scanning.py
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
import asyncio
from getmac import get_mac_address

async def port_scanner(semaphore, target_ip, port, open_ports):
    async with semaphore:
        try:
            reader, writer = await asyncio.open_connection(target_ip, port)
            open_ports.append(port)
            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionRefusedError):
            pass  # Ignore errors like "Connection refused"

async def start_port_scan(target_entry, output_text_box):
    target_host = target_entry.get()
    mac_address = get_mac_address(ip=str(target_host))

    if not target_host:
        output_text_box.insert(tk.END, "Error: Please enter a target host.\n")
        return

    output_text_box.delete("1.0", tk.END)
    output_text_box.insert(tk.END, "Please wait while scanning...\n")
    output_text_box.update()

    open_ports = []
    semaphore = asyncio.Semaphore(100)

    tasks = [port_scanner(semaphore, target_host, port, open_ports) for port in range(1, 65535)]
    await asyncio.gather(*tasks)

    output_text_box.delete("1.0", tk.END)
    output_text_box.insert(tk.END, f"Scan Results for: {target_host}\t\t mac address: {mac_address}\n\n")
    if open_ports:
        for port in open_ports:
            output_text_box.insert(tk.END, f"Port {port} is open\n")
    else:
        output_text_box.insert(tk.END, "No open ports found.\n")

    output_text_box.insert(tk.END, "Scan completed!\n")

def setup_port_scanning_tab(notebook):
    port_scan_tab = ttk.Frame(notebook)
    notebook.add(port_scan_tab, text="Port Scanning")

    port_scan_label = ctk.CTkLabel(master=port_scan_tab, text="Target Host:")
    port_scan_label.pack(pady=10)

    port_scan_target_entry = ctk.CTkEntry(master=port_scan_tab, width=200)
    port_scan_target_entry.pack(pady=5)

    start_port_scan_button = ctk.CTkButton(master=port_scan_tab, text="Start Port Scan", command=lambda: asyncio.run(start_port_scan(port_scan_target_entry, port_scan_output_text_box)))
    start_port_scan_button.pack(pady=10)

    port_scan_output_frame = ctk.CTkFrame(master=port_scan_tab)
    port_scan_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

    port_scan_output_text_box = ctk.CTkTextbox(master=port_scan_output_frame, height=20, width=600)
    port_scan_output_text_box.pack(side="left", fill="both", expand=True)

    port_scan_scrollbar = ttk.Scrollbar(master=port_scan_output_frame, orient="vertical", command=port_scan_output_text_box.yview)
    port_scan_scrollbar.pack(side="right", fill="y")
    port_scan_output_text_box.configure(yscrollcommand=port_scan_scrollbar.set)
