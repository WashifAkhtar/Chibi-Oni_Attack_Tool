# attack_launcher.py
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from metasploit_interface import run_exploit

def setup_exploit_tab(notebook, exploit_name, payload_name, description, target_var):
    tab = ttk.Frame(notebook)
    notebook.add(tab, text=exploit_name.split('/')[-1])

    exploit_label = ctk.CTkLabel(master=tab, text=f"Exploit: {exploit_name}\nPayload: {payload_name}\n\nDescription: {description}", wraplength=600)
    exploit_label.pack(pady=10)

    target_label = ctk.CTkLabel(master=tab, text="Target Host:")
    target_label.pack(pady=10)

    target_entry = ctk.CTkEntry(master=tab, textvariable=target_var, width=200)
    target_entry.pack(pady=5)

    shell_output_frame = ctk.CTkFrame(master=tab)
    shell_output_frame.pack(expand=True, fill="both", padx=10, pady=10)

    shell_output_text_box = ctk.CTkTextbox(master=shell_output_frame, height=20, width=600)
    shell_output_text_box.pack(side="left", fill="both", expand=True)

    shell_scrollbar = ttk.Scrollbar(master=shell_output_frame, orient="vertical", command=shell_output_text_box.yview)
    shell_scrollbar.pack(side="right", fill="y")
    shell_output_text_box.configure(yscrollcommand=shell_scrollbar.set)

    launch_exploit_button = ctk.CTkButton(master=tab, text="Launch Exploit", command=lambda: run_exploit(exploit_name, payload_name, target_var.get(), shell_output_text_box))
    launch_exploit_button.pack(pady=10)

def setup_attack_launcher_tab(notebook, target_var):
    attack_launcher_tab = ttk.Frame(notebook)
    notebook.add(attack_launcher_tab, text="Launch Exploit")

    exploit_notebook = ttk.Notebook(attack_launcher_tab)
    exploit_notebook.pack(expand=True, fill="both")

    exploits = [
        ('unix/ftp/vsftpd_234_backdoor', 'cmd/unix/interact', 'Vsftpd 2.3.4 backdoor exploit allows attackers to gain root shell access via a malicious backdoor introduced into the source code of the vsftpd version 2.3.4.'),
        ('unix/misc/distcc_exec', 'cmd/unix/reverse', 'Distcc Daemon Command Execution allows remote code execution by leveraging a command execution vulnerability in the distcc daemon.'),
        ('unix/irc/unreal_ircd_3281_backdoor', 'cmd/unix/reverse', 'UnrealIRCD 3.2.8.1 Backdoor Command Execution exploits a malicious backdoor that was inserted into the UnrealIRCd source code, allowing attackers to execute arbitrary commands.'),
        ('multi/samba/usermap_script', 'cmd/unix/reverse_netcat', 'Samba "username map script" Command Execution allows remote attackers to execute arbitrary commands on the server by specifying a crafted username.'),
        ('multi/http/php_cgi_arg_injection', 'php/meterpreter/reverse_tcp', 'PHP CGI Argument Injection exploit leverages a vulnerability in PHP CGI that allows remote code execution by injecting arguments into the PHP CGI binary.')
    ]

    for exploit_name, payload_name, description in exploits:
        setup_exploit_tab(exploit_notebook, exploit_name, payload_name, description, target_var)
