import asyncio
import ipaddress
import subprocess
from getmac import get_mac_address

MAX_CONCURRENT_SCANS = 100  # Limit the number of concurrent scans

async def ping_host(ip_str):
    """Pings a single host and returns True if reachable, False otherwise."""
    process = await asyncio.create_subprocess_shell(
        f'ping -c 1 -W 1 {ip_str}',
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    return process.returncode == 0

async def perform_host_discovery(target_entry, output_text_box):
    target_range = target_entry.get()

    if not target_range:
        output_text_box.insert(tk.END, "Error: Please enter a target range.\n")
        return

    try:
        network = ipaddress.ip_network(target_range, strict=False)
    except ValueError as e:
        output_text_box.insert(tk.END, f"Error: {str(e)}\n")
        return

    output_text_box.delete("1.0", tk.END)
    output_text_box.insert(tk.END, "Please wait while scanning...\n")
    output_text_box.update()

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

    async def ping_and_get_mac(ip):
        async with semaphore:
            if await ping_host(str(ip)):
                mac = get_mac_address(ip=str(ip))
                output_text_box.insert(tk.END, f"{ip} is up, MAC address: {mac}\n")
            else:
                output_text_box.insert(tk.END, f"{ip} is down\n")
            output_text_box.update()

    await asyncio.gather(*[ping_and_get_mac(ip) for ip in network.hosts()])

def start_host_discovery(target_entry, output_text_box):
    asyncio.run(perform_host_discovery(target_entry, output_text_box))
