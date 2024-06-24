import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
import subprocess
import threading
import time

def run_network_statistics(password, duration, output_text_box):
    command = f'echo {password} | sudo -S python3 network_statistics.py {duration}'
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        output_text_box.delete("1.0", tk.END)
        output_text_box.insert(tk.END, result + "\n")
        output_text_box.insert(tk.END, "Network statistics capture completed!\n")
    except subprocess.CalledProcessError as e:
        output_text_box.delete("1.0", tk.END)
        output_text_box.insert(tk.END, f"Failed to capture network statistics: {e}\n")

def retrieve_password_and_run(dialog, password_entry, duration_entry, output_text_box):
    password = password_entry.get()
    dialog.destroy()
    output_text_box.delete("1.0", tk.END)
    output_text_box.insert(tk.END, "Please wait while capturing network traffic...\n")
    output_text_box.update()
    run_network_statistics(password, int(duration_entry.get()), output_text_box)

def show_password_prompt(duration_entry, output_text_box):
    dialog = ctk.CTkToplevel()
    dialog.title("Root Password Required")
    dialog.geometry("300x150")

    label = ctk.CTkLabel(dialog, text="Enter root password:", font=('Helvetica', 12))
    label.pack(pady=10)

    password_entry = ctk.CTkEntry(dialog, show="*", width=200)
    password_entry.pack(pady=5)

    def on_ok():
        threading.Thread(target=retrieve_password_and_run, args=(dialog, password_entry, duration_entry, output_text_box)).start()

    ok_button = ctk.CTkButton(dialog, text="OK", command=on_ok)
    ok_button.pack(pady=10)

    dialog.update_idletasks()  # Ensure the window is fully drawn
    time.sleep(0.1)  # Delay to ensure the window is viewable
    dialog.transient()
    dialog.grab_set()
    dialog.wait_window()

def setup_network_statistics_tab(notebook):
    network_statistics_tab = ttk.Frame(notebook)
    notebook.add(network_statistics_tab, text="Network Statistics")

    network_statistics_label = ctk.CTkLabel(master=network_statistics_tab, text="Capture Duration (seconds):")
    network_statistics_label.pack(pady=10)

    network_statistics_duration_entry = ctk.CTkEntry(master=network_statistics_tab, width=200)
    network_statistics_duration_entry.insert(0, "120")
    network_statistics_duration_entry.pack(pady=5)

    start_network_statistics_button = ctk.CTkButton(master=network_statistics_tab, text="Start Network Statistics", command=lambda: show_password_prompt(network_statistics_duration_entry, network_statistics_output_text_box))
    start_network_statistics_button.pack(pady=10)

    network_statistics_output_frame = ctk.CTkFrame(master=network_statistics_tab)
    network_statistics_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

    global network_statistics_output_text_box
    network_statistics_output_text_box = ctk.CTkTextbox(master=network_statistics_output_frame, height=20, width=600)
    network_statistics_output_text_box.pack(side="left", fill="both", expand=True)

    network_statistics_scrollbar = ttk.Scrollbar(master=network_statistics_output_frame, orient="vertical", command=network_statistics_output_text_box.yview)
    network_statistics_scrollbar.pack(side="right", fill="y")
    network_statistics_output_text_box.configure(yscrollcommand=network_statistics_scrollbar.set)
