from flask import Flask, render_template, request
import os
import threading
import logging
import netifaces

app = Flask(__name__)

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
        ip_address = request.form['ssh_ip']  # Get trusted IP address from the form
        # Command to allow SSH access from the specified IP address using iptables
        command = f"iptables -A INPUT -i {interface} -p tcp --dport 22 -s {ip_address} -j ACCEPT"
        # Execute the command using the os.system function
        os.system(command)
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
    protocol = request.form['protocol']
    # Command to block the protocol using iptables
    command = f"iptables -A INPUT -i {interface} -p {protocol} -j DROP"
    # Execute the command using the os.system function
    os.system(command)
    print(f"\nProtocol {protocol} has been successfully blocked.")
    logging.info(f"Protocol {protocol} has been successfully blocked.")

def unblock_protocol(interface=None):
    # Logic to unblock a protocol
    protocol = request.form['protocol']
    # Command to unblock the protocol using iptables
    command = f"iptables -D INPUT -i {interface} -p {protocol} -j DROP"
    # Execute the command using the os.system function
    os.system(command)
    print(f"\nProtocol {protocol} has been successfully unblocked.")
    logging.info(f"Protocol {protocol} has been successfully unblocked.")

def block_port(interface=None):
    # Logic to block a port
    port = request.form['port']
    # Command to block the port using iptables
    command = f"iptables -A INPUT -i {interface} -p tcp --dport {port} -j DROP"
    # Execute the command using the os.system function
    os.system(command)
    print(f"\nPort {port} has been successfully blocked.")
    logging.info(f"Port {port} has been successfully blocked.")

def unblock_port(interface=None):
    # Logic to unblock a port
    port = request.form['port']
    # Command to unblock the port using iptables
    command = f"iptables -D INPUT -i {interface} -p tcp --dport {port} -j DROP"
    # Execute the command using the os.system function
    os.system(command)
    print(f"\nPort {port} has been successfully unblocked.")
    logging.info(f"Port {port} has been successfully unblocked.")

def block_ip(interface=None):
    # Logic to block an IP address
    ip_address = request.form['ip_address']
    # Command to block the IP address using iptables
    command = f"iptables -A INPUT -i {interface} -s {ip_address} -j DROP"
    # Execute the command using the os.system function
    os.system(command)
    print(f"\nIP address {ip_address} has been successfully blocked.")
    logging.info(f"IP address {ip_address} has been successfully blocked.")

def unblock_ip(interface=None):
    # Logic to unblock a blocked IP address
    ip_address = request.form['ip_address']
    # Command to remove the rule blocking the IP address
    command = f"iptables -D INPUT -i {interface} -s {ip_address} -j DROP"
    # Execute the command using the os.system function
    os.system(command)
    print(f"\nIP address {ip_address} has been successfully unblocked.")
    logging.info(f"IP address {ip_address} has been successfully unblocked.")

# Add more functions for other option handlers

# Create an instance of TrafficCapture
traffic_capture = TrafficCapture()

# Configure logging
logging.basicConfig(filename='firewall.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define routes for your web interface
@app.route('/')
def index():
    interfaces = get_available_interfaces()
    return render_template('index.html', interfaces=interfaces)

@app.route('/configure', methods=['POST'])
def configure():
    option = request.form['option']
    interface = request.form['interface']
    
    if option == "start_capture":
        traffic_capture.start_capture()
        logging.info("Traffic capture started.")
    elif option == "stop_capture":
        traffic_capture.stop_capture()
        logging.info("Traffic capture stopped.")
    elif option == "enable_syn_flood":
        protect_syn_flood(enable=True, interface=interface)
    elif option == "disable_syn_flood":
        protect_syn_flood(enable=False, interface=interface)
    elif option == "limit_ssh_access":
        limit_ssh_access(enable=True, interface=interface)
    elif option == "disable_ssh_access":
        limit_ssh_access(enable=False, interface=interface)
    elif option == "prevent_dos_attacks":
        prevent_dos_attacks(interface=interface)
    elif option == "prevent_port_scanning":
        prevent_port_scanning(interface=interface)
    elif option == "block_protocol":
        block_protocol(interface=interface)
    elif option == "unblock_protocol":
        unblock_protocol(interface=interface)
    elif option == "block_port":
        block_port(interface=interface)
    elif option == "unblock_port":
        unblock_port(interface=interface)
    elif option == "block_ip":
        block_ip(interface=interface)
    elif option == "unblock_ip":
        unblock_ip(interface=interface)
    # Add more option handlers here

    return "OK"

if __name__ == "__main__":
    app.run(debug=True)
