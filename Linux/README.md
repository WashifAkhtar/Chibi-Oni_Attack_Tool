# Chibi-Oni Attack Tool

Chibi-Oni is a comprehensive cybersecurity tool designed for various network analysis tasks. It includes functionalities such as host discovery, port scanning, DDoS attacks, and more, all wrapped in a user-friendly GUI built with `tkinter` and `customtkinter`.

## Features

- **Host Discovery**: Identify active hosts in a network.
- **Port Scanning**: Scan for open ports on a target host.
- **Network Statistics**: Capture and display network statistics.
- **DDoS Attacks**: Launch Slowloris and SYN Flood attacks.
- **Metasploit Integration**: Interface with Metasploit for launching exploits.

## Requirements

- Python 3.6 or higher
- The following Python packages:
  - `customtkinter`
  - `Pillow`
  - `getmac`
  - `asyncio`
  - `ipaddress`
  - `python-nmap`
  - `paramiko`
  - `pymetasploit3`
  - `scapy`
  - `msgpack`

## Installation

### From Source

1. **Clone the Repository**

    ```bash
    git clone https://github.com/WashifAkhtar/Chibi-Oni_Attack_Tool
    cd Linux
    ```

2. **Install the Required Packages**

    ```bash
    pip install -r requirements.txt
    ```

3. **Run the Application**

    ```bash
    python3 main.py
    ```

### Using the Debian Package

1. **Download and Install the Debian Package**

    ```bash
    cd installer
    sudo dpkg -i chibi-oni_1.0_amd64.deb
    ```

2. **Run the Application**

    ```bash
    Chibi-Oni
    ```

## Directory Structure

