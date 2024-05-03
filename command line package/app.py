import sys
import os
import subprocess
import threading
import logging
from scapy.all import *
import netifaces

os.system("clear")

print("\033[34m .___        __        ___.   .__                  \033[0m")
print("\033[34m |   |______/  |______ \_ |__ |  |   ____   ______ \033[0m")
print("\033[34m |   \____ \   __\__  \ | __ \|  | _/ __ \ /  ___/ \033[0m")
print("\033[34m |   |  |_> >  |  / __ \| \_\ \  |_\  ___/ \___ \  \033[0m")
print("\033[34m |___|   __/|__| (____  /___  /____/\___  >____  > \033[0m")
print("\033[34m     |__|             \/    \/          \/     \/  \033[0m")

class TrafficCapture:
    def __init__(self):
        self.capture_thread = None
        self.capture_running = False

    def start_capture(self):
        if not self.capture_running:
            print("Starting traffic capture...")
            self.capture_running = True
            self.capture_thread = threading.Thread(target=self.capture_traffic)
            self.capture_thread.start()
        else:
            print("Traffic capture is already running.")

    def stop_capture(self):
        if self.capture_running:
            print("Stopping traffic capture...")
            self.capture_running = False
            # Do not need to join the thread, as it will stop automatically when the capture_running flag is set to False
            print("Traffic capture stopping...")
        else:
            print("Traffic capture is not currently running.")

    def capture_traffic(self):
        def packet_handler(pkt):
            # Print packet details
            print(pkt.summary())

        # Start sniffing traffic on all interfaces
        sniff(prn=packet_handler, store=0)

def get_available_interfaces():
    interfaces = netifaces.interfaces()
    return interfaces

def get_interface_ip(interface):
    try:
        addresses = netifaces.ifaddresses(interface)
        ipv4_addresses = addresses[netifaces.AF_INET]
        ip_address = ipv4_addresses[0]['addr']
        return ip_address
    except Exception as e:
        print(f"Error getting IP address for interface {interface}: {e}")
        return None

def print_interfaces(interfaces):
    print("Available Interfaces:")
    for i, interface in enumerate(interfaces):
        print(f"{i + 1}. {interface}")

def select_interface(interfaces):
    print_interfaces(interfaces)
    while True:
        choice = input("Select an interface: ")
        try:
            index = int(choice) - 1
            if 0 <= index < len(interfaces):
                return interfaces[index]
            else:
                print("Invalid selection. Please enter a valid index.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def protect_syn_flood(enable=True, interface=None):
    if enable:
        # Logic to protect against SYN flood attacks
        os.system(f"iptables -A INPUT -i {interface} -p tcp --syn -m limit --limit 5/s -j ACCEPT")
        os.system(f"iptables -A INPUT -i {interface} -p tcp --syn -j DROP")
        print("\nProtection against SYN flood attacks activated")
        logging.info("Protection against SYN flood attacks activated")
    else:
        # Logic to disable SYN flood protection
        os.system(f"iptables -D INPUT -i {interface} -p tcp --syn -m limit --limit 5/s -j ACCEPT")
        os.system(f"iptables -D INPUT -i {interface} -p tcp --syn -j DROP")
        print("\nProtection against SYN flood attacks disabled")
        logging.info("Protection against SYN flood attacks disabled")

def limit_ssh_access(enable=True, interface=None):
    if enable:
        # Logic to limit SSH access
        ip_address = input("\n[+] Enter trusted IP address: ")
        # Command to allow SSH access from the specified IP address using iptables
        command = f"iptables -A INPUT -i {interface} -p tcp --dport 22 -s {ip_address} -j ACCEPT"
        # Execute the command using the subprocess module
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error executing command: {e}")
        os.system(f"iptables -A INPUT -i {interface} -p tcp --dport 22 -j DROP")
        print("\nSSH access limited")
        logging.info("SSH access limited")
    else:
        # Logic to disable SSH access limitation
        os.system(f"iptables -D INPUT -i {interface} -p tcp --dport 22 -j DROP")
        print("\nSSH access limitation disabled")
        logging.info("SSH access limitation disabled")

def prevent_dos_attacks(interface=None):
    # Logic to prevent DoS attacks
    os.system(f"\niptables -A INPUT -i {interface} -p tcp --syn --dport 80 -m connlimit --connlimit-above 20 -j DROP")
    os.system(f"iptables -A INPUT -i {interface} -p tcp --dport 80 -m limit --limit 50/minute --limit-burst 30 -j ACCEPT")
    print("\nDoS attack prevention activated")

def prevent_port_scanning(interface=None):
    # Logic to prevent port scanning
    os.system(f"\niptables -N SCANNER_PROTECTION")
    os.system(f"iptables -A SCANNER_PROTECTION -i {interface} -p tcp --tcp-flags ALL NONE -j DROP")
    os.system(f"iptables -A SCANNER_PROTECTION -i {interface} -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP")
    print("\nPort scanning prevention activated")

def block_protocol(interface=None):
    # Logic to block a protocol
    protocol = input("\n[+] Enter the protocol you want to block (e.g., tcp, udp): ")
    # Command to block the protocol using iptables
    command = f"iptables -A INPUT -i {interface} -p {protocol} -j DROP"
    # Execute the command using the subprocess module
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"\n[+] Protocol {protocol} has been successfully blocked.")
        logging.info(f"Protocol {protocol} has been successfully blocked.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

def unblock_protocol(interface=None):
    # Logic to unblock a protocol
    protocol = input("\n[+] Enter the protocol you want to unblock (e.g., tcp, udp): ")
    # Command to unblock the protocol using iptables
    command = f"iptables -D INPUT -i {interface} -p {protocol} -j DROP"
    # Execute the command using the subprocess module
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"\n[+] Protocol {protocol} has been successfully unblocked.")
        logging.info(f"Protocol {protocol} has been successfully unblocked.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

def block_port(interface=None):
    # Logic to block a port
    port = input("\n[+] Enter the port number you want to block (e.g., 80, 443): ")
    # Command to block the port using iptables
    command = f"iptables -A INPUT -i {interface} -p tcp --dport {port} -j DROP"
    # Execute the command using the subprocess module
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"\n[+] Port {port} has been successfully blocked.")
        logging.info(f"Port {port} has been successfully blocked.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

def unblock_port(interface=None):
    # Logic to unblock a port
    port = input("\n[+] Enter the port number you want to unblock (e.g., 80, 443): ")
    # Command to unblock the port using iptables
    command = f"iptables -D INPUT -i {interface} -p tcp --dport {port} -j DROP"
    # Execute the command using the subprocess module
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"\n[+] Port {port} has been successfully unblocked.")
        logging.info(f"Port {port} has been successfully unblocked.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

def block_ip(interface=None):
    # Logic to block an IP address
    ip_address = input("\n[+] Enter the IP address you want to block: ")
    # Command to block the IP address using iptables
    command = f"iptables -A INPUT -i {interface} -s {ip_address} -j DROP"
    # Execute the command using the subprocess module
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"\n[+] IP address {ip_address} has been successfully blocked.")
        logging.info(f"IP address {ip_address} has been successfully blocked.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

def unblock_ip(interface=None):
    # Logic to unblock a blocked IP address
    ip_address = input("\n[+] Enter the IP address you want to unblock: ")
    # Command to remove the rule blocking the IP address
    command = f"iptables -D INPUT -i {interface} -s {ip_address} -j DROP"
    # Execute the command using the subprocess module
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"\n[+] IP address {ip_address} has been successfully unblocked.")
        logging.info(f"IP address {ip_address} has been successfully unblocked.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

def main_menu(traffic_capture):
    interfaces = get_available_interfaces()
    wan_interface = select_interface(interfaces)
    wan_ip = get_interface_ip(wan_interface)
    print(f"WAN Interface selected: {wan_interface}, IP Address: {wan_ip}")
    logging.info(f"WAN Interface selected: {wan_interface}, IP Address: {wan_ip}")  # Log the selected WAN interface
    # Add logic to select LAN interface and get its IP address
    while True:
        print("LAN Interface: ")
        lan_interface = input("Enter LAN Interface: ")
        lan_ip = get_interface_ip(lan_interface)
        if lan_ip:
            print(f"LAN Interface selected: {lan_interface}, IP Address: {lan_ip}")
            logging.info(f"LAN Interface selected: {lan_interface}, IP Address: {lan_ip}")  # Log the selected LAN interface
            break
        else:
            print("Invalid LAN Interface. Please enter a valid interface.")
    while True:
        print("\n[1] Enable SYN flood protection")
        print("[2] Disable SYN flood protection")
        print("[3] Enable SSH access limitation")
        print("[4] Disable SSH access limitation")
        print("[5] Prevent DoS attacks")
        print("[6] Prevent port scanning")
        print("[7] Block protocol")
        print("[8] Unblock protocol")
        print("[9] Block port")
        print("[10] Unblock port")
        print("[11] Block IP address")
        print("[12] Unblock IP address")
        print("[13] Start Traffic Capture")
        print("[14] Stop Traffic Capture")
        print("[15] Exit")

        option = input("\033[1m\n[+] Enter an option: \033[0m")

        if option == "1":
            protect_syn_flood(enable=True, interface=wan_interface)
        elif option == "2":
            protect_syn_flood(enable=False, interface=wan_interface)
        elif option == "3":
            limit_ssh_access(enable=True, interface=wan_interface)
        elif option == "4":
            limit_ssh_access(enable=False, interface=wan_interface)
        elif option == "5":
            prevent_dos_attacks(interface=wan_interface)
        elif option == "6":
            prevent_port_scanning(interface=wan_interface)
        elif option == "7":
            block_protocol(interface=wan_interface)
        elif option == "8":
            unblock_protocol(interface=wan_interface)
        elif option == "9":
            block_port(interface=wan_interface)
        elif option == "10":
            unblock_port(interface=wan_interface)
        elif option == "11":
            block_ip(interface=wan_interface)
        elif option == "12":
            unblock_ip(interface=wan_interface)
        elif option == "13":
            traffic_capture.start_capture()
            logging.info("Traffic capture started.")
        elif option == "14":
            traffic_capture.stop_capture()
            logging.info("Traffic capture stopped.")
        elif option == "15":
            os.system("clear")
            print("[+] Exiting the program.")
            sys.exit()
        else:
            print("\nInvalid option. Please select a valid option.")

# Configure logging
logging.basicConfig(filename='firewall.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create an instance of TrafficCapture
traffic_capture = TrafficCapture()

# Enter the main menu loop
if __name__ == "__main__":
    main_menu(traffic_capture)
