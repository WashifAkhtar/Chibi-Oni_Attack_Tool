<div align="center">
  <img src="./Windows/icon.ico" alt="Chibi-Oni Logo" width="200">
</div>

# Chibi-Oni_Attack_Tool

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
    ```

2. **Install the Required Packages**

    ```bash
    cd Linux
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


## Usage

### Running the Application

1. **From Source**: Go to Chibi-Oni_Attack_Tool/Linux/ and run:

    ```bash
    python3 main.py
    ```

2. **From the Installed Package**: Simply run:

    ```bash
    Chibi-Oni
    ```

### Application Features

- **Host Discovery**: Use the Host Discovery tab to scan for active hosts in a specified network range.
- **Port Scanning**: Use the Port Scanning tab to check for open ports on a target host.
- **Network Statistics**: Use the Network Statistics tab to capture and display real-time network statistics.
- **DDoS Attacks**: Use the DDoS Attack tab to launch Slowloris or SYN Flood attacks on a specified target.
- **Metasploit Integration**: Use the Metasploit tab to interface with Metasploit for launching exploits.

## Troubleshooting

### Common Issues

- **Missing Dependencies**: Ensure all required Python packages are installed. Use `pip install -r requirements.txt` to install them.
- **Permission Issues**: Ensure you have the necessary permissions to run network operations and modify system files.

### Debugging

- **Running from the Terminal**: If you encounter issues running the application, try running it from the terminal to capture any error messages:

    ```bash
    python3 main.py
    ```

## Contributing

1. **Fork the Repository**

    ```bash
    git clone https://github.com/WashifAkhtar/Chibi-Oni_Attack_Tool
    cd Linux
    ```

2. **Create a Feature Branch**

    ```bash
    git checkout -b feature/your-feature
    ```

3. **Commit Your Changes**

    ```bash
    git commit -m "Add your feature"
    ```

4. **Push to the Branch**

    ```bash
    git push origin feature/your-feature
    ```

5. **Create a Pull Request**

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

## Contact

For questions or feedback, please reach out to `your-email@example.com`.



