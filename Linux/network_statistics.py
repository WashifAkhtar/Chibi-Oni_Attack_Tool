import psutil
import time
import threading

def capture_network_statistics(duration, output_text_box):
    output_text_box.delete("1.0", tk.END)
    output_text_box.insert(tk.END, "Capturing network statistics...\n")
    output_text_box.update()

    stats = []

    for _ in range(duration):
        net_io = psutil.net_io_counters()
        stats.append((net_io.bytes_sent, net_io.bytes_recv))
        time.sleep(1)

    for i in range(1, len(stats)):
        sent = stats[i][0] - stats[i - 1][0]
        recv = stats[i][1] - stats[i - 1][1]
        output_text_box.insert(tk.END, f"Second {i}: Bytes Sent: {sent}, Bytes Received: {recv}\n")
        output_text_box.update()

def start_network_statistics(duration_entry, output_text_box):
    try:
        duration = int(duration_entry.get())
    except ValueError:
        output_text_box.insert(tk.END, "Error: Please enter a valid number for the duration.\n")
        return

    threading.Thread(target=capture_network_statistics, args=(duration, output_text_box)).start()
