#!/usr/bin/env python3
import socket
import ipaddress
import subprocess
import platform
import re

def is_macos():
    """Check if running on macOS"""
    return platform.system() == 'Darwin'

def is_linux():
    """Check if running on Linux"""
    return platform.system() == 'Linux'

def get_ip_addresses():
    """Get all local IP addresses"""
    ips = []
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        ips.append(ip)
    except Exception as e:
        print(f"Error getting hostname IP: {e}")
    
    try:
        # Try to get all IPs
        addresses = socket.getaddrinfo(socket.gethostname(), None)
        for addr in addresses:
            ip = addr[4][0]
            if not ip.startswith('127.') and ':' not in ip:  # Skip loopback and IPv6
                ips.append(ip)
    except Exception as e:
        print(f"Error getting all IPs: {e}")
    
    # Use ifconfig/ip command as fallback
    try:
        if is_macos():
            output = subprocess.check_output(['ifconfig']).decode('utf-8')
            # Find all inet addresses
            for line in output.split('\n'):
                if 'inet ' in line and 'inet6' not in line and '127.0.0.1' not in line:
                    parts = line.strip().split()
                    for i, part in enumerate(parts):
                        if part == 'inet' and i+1 < len(parts):
                            ip = parts[i+1]
                            if ip not in ips:
                                ips.append(ip)
        elif is_linux():
            output = subprocess.check_output(['ip', '-4', 'addr', 'show']).decode('utf-8')
            # Find all inet addresses
            matches = re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+)', output)
            for ip in matches:
                if not ip.startswith('127.') and ip not in ips:
                    ips.append(ip)
    except Exception as e:
        print(f"Error using ifconfig/ip command: {e}")
    
    return ips

def get_networks_from_ips(ips):
    """Get network CIDRs from IP addresses"""
    networks = []
    for ip in ips:
        try:
            if ipaddress.IPv4Address(ip).is_private:
                # Assume a /24 network
                network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                networks.append(str(network))
        except Exception as e:
            print(f"Error processing IP {ip}: {e}")
    
    return networks

if __name__ == "__main__":
    print("Local IP addresses:")
    ips = get_ip_addresses()
    for ip in ips:
        print(f"  {ip}")
    
    print("\nLocal networks to scan:")
    networks = get_networks_from_ips(ips)
    for network in networks:
        print(f"  {network}") 