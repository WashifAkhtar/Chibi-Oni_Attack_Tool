import subprocess
import sys

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

packages = [
    "customtkinter",
    "Pillow",
    "getmac",
    "asyncio",
    "ipaddress",
    "python-nmap",
    "paramiko",
    "pymetasploit3",
    "scapy"
]

for package in packages:
    install(package)
