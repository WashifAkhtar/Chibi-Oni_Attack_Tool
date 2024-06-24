import os
import subprocess
import sys
from scapy.all import sniff
from collections import Counter

def is_root():
    """ Check if the script is being run as root. """
    return os.geteuid() == 0

def rerun_as_root():
    """ Rerun the script with sudo. """
    try:
        print("Requesting root privileges...")
        subprocess.check_call(['sudo', 'python3'] + sys.argv)
    except subprocess.CalledProcessError as e:
        print(f"Failed to rerun script as root: {e}")
    sys.exit()

if not is_root():
    rerun_as_root()

def capture_network_statistics(duration):
    host_counter = Counter()

    def packet_handler(packet):
        if packet.haslayer('IP'):
            dest_ip = packet['IP'].dst
            host_counter[dest_ip] += 1

    sniff(prn=packet_handler, timeout=duration)
    most_accessed_hosts = host_counter.most_common()
    for host, count in most_accessed_hosts:
        print(f"{host}: {count}")

if __name__ == "__main__":
    duration = int(sys.argv[1])
    capture_network_statistics(duration)
