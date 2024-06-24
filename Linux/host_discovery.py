# host_discovery.py
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
import asyncio
import ipaddress
from getmac import get_mac_address


async def ping_host(ip_str):
    process = await asyncio.create_subprocess_shell(
        f'ping -c 1 -W 1 {ip_str}',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    return process.returncode == 0


async def start_host_discovery(target_entry, output_text_box):
    target_range = target_entry.get()

    if not target_range:
        output_text_box.insert(tk.END, "Error: Please enter a target range.\n")
        return

    try:
        network = ipaddress.ip_network(target_range, strict=False)
    except ValueError as e:
        output_text_box.insert(tk.END, f"Error: {str(e)}\n")
        return

    output_text_box.delete("1.0", tk.END)
    output_text_box.insert(tk.END, "Please wait while scanning...\n")
    output_text_box.update()

    tasks = [ping_host(str(ip)) for ip in network.hosts()]
    reachable_ips = await asyncio.gather(*tasks)

    output_text_box.delete("1.0", tk.END)
    output_text_box.insert(tk.END, f"Starting scan for: {target_range}\n")
    for ip, reachable in zip(network.hosts(), reachable_ips):
        if reachable:
            mac_address = get_mac_address(ip=str(ip))
            output_text_box.insert(tk.END, f"Host {str(ip)} is up.\t\t mac address: {mac_address}\n")

    output_text_box.insert(tk.END, "Host discovery completed.\n")


def setup_host_discovery_tab(notebook):
    host_discovery_tab = ttk.Frame(notebook)
    notebook.add(host_discovery_tab, text="Host Discovery")

    host_discovery_label = ctk.CTkLabel(master=host_discovery_tab, text="Target Range:")
    host_discovery_label.pack(pady=10)

    host_discovery_target_entry = ctk.CTkEntry(master=host_discovery_tab, width=200)
    host_discovery_target_entry.pack(pady=5)

    host_discovery_button = ctk.CTkButton(master=host_discovery_tab, text="Start Host Discovery",
                                          command=lambda: asyncio.run(start_host_discovery(host_discovery_target_entry,
                                                                                           host_discovery_output_text_box)))
    host_discovery_button.pack(pady=10)

    host_discovery_output_frame = ctk.CTkFrame(master=host_discovery_tab)
    host_discovery_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

    host_discovery_output_text_box = ctk.CTkTextbox(master=host_discovery_output_frame, height=20, width=600)
    host_discovery_output_text_box.pack(side="left", fill="both", expand=True)

    host_discovery_scrollbar = ttk.Scrollbar(master=host_discovery_output_frame, orient="vertical",
                                             command=host_discovery_output_text_box.yview)
    host_discovery_scrollbar.pack(side="right", fill="y")
    host_discovery_output_text_box.configure(yscrollcommand=host_discovery_scrollbar.set)

