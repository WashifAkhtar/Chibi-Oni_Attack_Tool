#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from PIL import Image, ImageTk
from host_discovery import setup_host_discovery_tab
from port_scanning import setup_port_scanning_tab
from network_statistics_gui import setup_network_statistics_tab
from ddos_attack import setup_ddos_attack_tab
from nmap_scan import setup_nmap_scan_tab
from attack_launcher import setup_attack_launcher_tab

# Create the main window
window = ctk.CTk()
window.geometry("1600x900")
window.title("Chibi-Oni")

# Set the window icon
im = Image.open('icon.ico')
photo = ImageTk.PhotoImage(im)
window.wm_iconphoto(True, photo)

# Create a notebook (tab container)
notebook = ttk.Notebook(window)
notebook.pack(expand=True, fill="both")

# Apply styles
style = ttk.Style()
style.configure('TNotebook.Tab', font=('Helvetica', 10, 'bold'), padding=[8, 8], background='#FFFFFF', foreground='#2E2E2E')
style.map('TNotebook.Tab', background=[('selected', '#FFFFFF')], foreground=[('selected', '#1E1E1E')])
style.configure('TFrame', background='#1E1E1E')
style.configure('TLabel', background='#1E1E1E', foreground='#FFFFFF', font=('Helvetica', 12))
style.configure('TEntry', font=('Helvetica', 12))
style.configure('TButton', font=('Helvetica', 12), padding=[10, 10], background='#2E2E2E', foreground='#FFFFFF')

# Global variable for target host
target_var = tk.StringVar()

# Create the tabs
setup_host_discovery_tab(notebook)
setup_port_scanning_tab(notebook)
setup_network_statistics_tab(notebook)
setup_ddos_attack_tab(notebook)
setup_nmap_scan_tab(notebook, target_var)
setup_attack_launcher_tab(notebook, target_var)

# Run the main loop
window.mainloop()
