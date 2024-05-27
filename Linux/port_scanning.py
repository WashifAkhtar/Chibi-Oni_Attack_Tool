import socket
import threading

def perform_port_scan(target, output_text_box):
    open_ports = []

    def scan_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        s.close()

    threads = []

    for port in range(1, 1025):
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    output_text_box.delete("1.0", tk.END)
    if open_ports:
        output_text_box.insert(tk.END, f"Open ports on {target}: {open_ports}\n")
    else:
        output_text_box.insert(tk.END, f"No open ports found on {target}.\n")

def start_port_scan(target_entry, output_text_box):
    target = target_entry.get()
    if not target:
        output_text_box.insert(tk.END, "Error: Please enter a target host.\n")
        return
    threading.Thread(target=perform_port_scan, args=(target, output_text_box)).start()
