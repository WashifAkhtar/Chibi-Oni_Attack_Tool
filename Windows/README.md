<div align="center">
  <img src="./icon.ico" alt="Chibi-Oni Logo" width="200">
</div>

# Chibi-Oni_Attack_Tool

Chibi-Oni is a Python-based application that provides network utility tools including host discovery, port scanning, network traffic analysis, and DDoS attack simulation.

## Features

- **Host Discovery:** Scans a range of IP addresses and identifies active hosts.
- **Port Scanning:** Scans a target host for open ports.
- **Network Statistics:** Analyzes network traffic from a PCAP file and identifies the most accessed hosts.
- **DDoS Attack Simulation:** Simulates a Slowloris DDoS attack on a specified target.

## Requirements

- Python 3.12.0
- `cx_Freeze` library
- `customtkinter` library
- `getmac` library
- `scapy` library

## Installation

### Step 1: Clone the Repository

Clone the GitHub repository to your local machine.

```bash
git clone https://github.com/WashifAkhtar/Chibi-Oni_Attack_Tool.git
```
### Step 2: Install Required Libraries

Install the required Python libraries using pip.

```bash
pip install cx_Freeze 
```

### Step 3: Create the Windows Installer

Create a Windows installer using cx_Freeze.

```bash
python setup.py bdist_msi
```

This command will generate two folders:

- build: Contains the executable files.
- dist: Contains the installer file.

### Step 4: Install the Software

Navigate to the dist folder and run the installer file. This will install the Chibi-Oni software on your system.


## Usage

After installation, you can launch Chibi-Oni from the desktop shortcut or from the Start menu.

### Host Discovery
1. Open Chibi-Oni.
2. Go to the "Host Discovery" tab.
3. Enter the target range in CIDR notation (e.g., 192.168.1.0/24).
4. Click on "Start Host Discovery".
5. The results will be displayed in the output text box.

### Port Scanning
1. Go to the "Port Scanning" tab.
2. Enter the target host's IP address. 
3. Click on "Start Port Scan".
4. The results will be displayed in the output text box.

### Network Statistics
1. Go to the "Network Statistics" tab. 
2. Enter the number of top accessed hosts to display. 
3. Click on "Select PCAP File" and choose a PCAP file.
4. The results will be displayed in the output text box.

### DDoS Attack Simulation
1. Go to the "DDOS Attack" tab.
2. Enter the target host's IP address and port.
3. Select the attack type (e.g., Slowloris).
4. Click on "Start Attack" to begin the simulation.
5. Click on "Stop Attack" to end the simulation.

### File Descriptions

#### chibi-oni.py
This is the main application script that provides the user interface and implements all the features of Chibi-Oni. It uses tkinter for the GUI and includes functionalities for host discovery, port scanning, network statistics analysis, and DDoS attack simulation.

#### setup.py
This script is used to create a Windows installer for the Chibi-Oni application using cx_Freeze. It specifies the build options and includes the main script (chibi-oni.py) and the icon file (icon.ico).

#### icon.ico
This file is the icon used for the Chibi-Oni application. It is specified in the setup.py script to be used for the Windows installer.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.

## Author
Washif Akhtar

## Acknowledgements
- [cx_Freeze](https://github.com/marcelotduarte/cx_Freeze)
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)
- [Scapy](https://scapy.net/)
