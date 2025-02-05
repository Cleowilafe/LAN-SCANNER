import argparse
import socket
import subprocess
import multiprocessing


# Creating argument parser
parser = argparse.ArgumentParser(description="Discover the opened ports")
parser.add_argument('-i', '--host', type=str, required=True, help="Enter the host (IP of router or machine)")

# Parse the arguments provided by the user
args = parser.parse_args()

# Variables from the arguments
host = args.host

def is_router(ip):
    # Try to execute the 'ip route' command to check for the default gateway
    try:
        # Execute the command to get the routing table
        result = subprocess.run(['ip', 'route'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Check if the output contains the provided IP as the default gateway
        if ip in result.stdout:
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error while checking route: {e}")
        return False

# Verifying the IPs in the network
ips = []

def ping(ip):
    # Using subprocess to run the ping command and check if the device is reachable
    output = subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return ip, output.returncode == 0  # Returns the IP and whether the ping was successful

def scan(network):
    with multiprocessing.Pool(processes=50) as pool:  # Creating a pool of 50 processes for parallel pinging
        ip_list = [f"{network}.{i}" for i in range(1, 255)]  # List of IPs in the network

        # Executing pings in parallel
        results = pool.map(ping, ip_list)  # Map applies the ping function to each item in the list

        # Iterating through the results to see which devices are active
        for ip, success in results:
            if success:
                ips.append(ip)  # Add active IP to the list

    print("\nFound IPs:")
    for ip in ips:
        print(ip)  # Displaying the active IPs found

# A list to store open ports
openports = []

def port_scanner(port, ip):
    # Create a new socket object to check port connectivity (one per process)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_obj:
        socket_obj.settimeout(1)  # Set timeout to avoid hanging on closed ports
        result = socket_obj.connect_ex((ip, port))  # Connect to the port
        return port, result == 0  # Returns the port and whether it's open (True if open, False otherwise)

def ips_port_scanner(ips):
    # List of common ports to check (1 to 1200)
    port_list = [i for i in range(1, 1200)]  # List of ports

    with multiprocessing.Pool(processes=50) as pool:  # Create a pool of 50 processes
        for ip in ips:
            print(f"Scanning ports for IP: {ip}")
            # Execute the port scanner for the list of ports
            results = pool.starmap(port_scanner, [(port, ip) for port in port_list])

            # Checking the results of each port scan
            for port, success in results:
                if success:
                    openports.append((ip, port))  # Storing the open port and its associated IP
                    
    print("\nOpen ports found:")
    for ip, port in openports:
        print(f"IP: {ip}, Open Port: {port}")


# Check if the host IP is from a local network (private range)
if is_router(host):

    print(f"Scanning network for devices in the same range as {host}.")  # Scan the network (e.g., 192.168.1.x)
    network = '.'.join(host.split('.')[:3])  # Get the first 3 octets (network part)
    scan(network)  # Scan the network
    ips_port_scanner(ips)

else:
    print(f"Local machine detected with IP: {host}, scanning ports only.")  # Directly scan ports for the given host
    ip, success = ping(host)
    if success:  # Using the success value from ping
        ips.append(host)  # Add the host IP to the list for port scanning
        ips_port_scanner(ips)
    else:
        print("Connection could not be established.")
