#!/usr/bin/env python3
"""
find_nas.py - A script to find and list NAS drives on both macOS and Ubuntu/Linux
"""

import os
import socket
import subprocess
import sys
import re
import ipaddress
import time
import platform
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import argparse
from functools import lru_cache

# Constants for scanning
DEFAULT_TIMEOUT = 0.2  # Reduced from 0.5s to 0.2s for faster scanning
DEFAULT_THREADS = 50   # Increased from 20 to 50 for better parallelization
DEFAULT_PORTS = [445, 139, 111, 2049, 548]  # Common NAS ports
COMMON_NAS_MAC_PREFIXES = [
    '00:11:32',  # Synology
    '00:90:A9',  # Western Digital
    '00:24:21',  # QNAP
    '00:1B:A9',  # Asustor
    '00:14:6C',  # Netgear ReadyNAS
    '00:25:31',  # TerraMaster
    '00:50:43',  # Buffalo
]

def is_macos():
    """Check if running on macOS"""
    return platform.system() == 'Darwin'

def is_linux():
    """Check if running on Linux"""
    return platform.system() == 'Linux'

def get_mounted_nas_drives():
    """
    Find all mounted NAS drives using mount command
    Works on both macOS and Ubuntu/Linux
    """
    result = []
    try:
        # Run the mount command to list all mounted filesystems
        mount_output = subprocess.check_output(['mount']).decode('utf-8')
        
        # Look for network filesystems
        for line in mount_output.splitlines():
            # For Linux CIFS/SMB mounts
            if is_linux() and ('cifs' in line or 'smbfs' in line):
                # Extract server and mount point information for Linux
                match = re.search(r'//([^/]+)/([^ ]+) on ([^ ]+) type (cifs|smbfs)', line)
                if match:
                    server, share, mount_point, fs_type = match.groups()
                    result.append({
                        'type': 'mounted',
                        'protocol': fs_type,
                        'server': server,
                        'share': share,
                        'mount_point': mount_point
                    })
            
            # For Linux NFS mounts
            elif is_linux() and 'nfs' in line:
                match = re.search(r'([^:]+):([^ ]+) on ([^ ]+) type nfs', line)
                if match:
                    server, share, mount_point = match.groups()
                    result.append({
                        'type': 'mounted',
                        'protocol': 'nfs',
                        'server': server,
                        'share': share,
                        'mount_point': mount_point
                    })
            
            # For macOS mounts
            elif is_macos() and any(fs_type in line for fs_type in ['nfs', 'smbfs', 'cifs', 'afp']):
                # Extract server and mount point information for macOS
                match = re.search(r'//([^/]+)/([^ ]+) on ([^ ]+)', line)
                if match:
                    server, share, mount_point = match.groups()
                    result.append({
                        'type': 'mounted',
                        'protocol': next((fs for fs in ['nfs', 'smbfs', 'cifs', 'afp'] if fs in line), 'unknown'),
                        'server': server,
                        'share': share,
                        'mount_point': mount_point
                    })
                else:
                    # For other formats like NFS on macOS
                    match = re.search(r'([^:]+):([^ ]+) on ([^ ]+)', line)
                    if match:
                        server, share, mount_point = match.groups()
                        result.append({
                            'type': 'mounted',
                            'protocol': 'nfs',
                            'server': server,
                            'share': share,
                            'mount_point': mount_point
                        })
    except Exception as e:
        print(f"Error getting mounted NAS drives: {e}", file=sys.stderr)
    
    return result

@lru_cache(maxsize=8)
def get_local_network_info():
    """
    Get information about the local network
    Compatible with both macOS and Ubuntu/Linux
    Uses caching to avoid repeated system calls
    """
    try:
        interfaces = []
        gateway = None
        
        # Different approach based on OS
        if is_macos():
            # macOS specific commands
            # Get default gateway
            route_output = subprocess.check_output(['route', '-n', 'get', 'default']).decode('utf-8')
            gateway_match = re.search(r'gateway: ([0-9.]+)', route_output)
            if gateway_match:
                gateway = gateway_match.group(1)
            
            # Get network interfaces using ifconfig
            ifconfig_output = subprocess.check_output(['ifconfig']).decode('utf-8')
            
            # Find the active interfaces with IPv4 addresses
            current_interface = None
            for line in ifconfig_output.splitlines():
                if ': ' in line:
                    current_interface = line.split(': ')[0]
                elif current_interface and 'inet ' in line and not 'inet6' in line:
                    parts = line.strip().split()
                    ip_index = parts.index('inet') + 1
                    mask_index = parts.index('netmask') + 1
                    ip = parts[ip_index]
                    # Convert hex netmask to CIDR notation
                    netmask_hex = parts[mask_index]
                    if netmask_hex.startswith('0x'):
                        netmask_hex = netmask_hex[2:]
                    # Convert hex to int to dotted decimal
                    netmask_int = int(netmask_hex, 16)
                    netmask = '.'.join([str((netmask_int >> i) & 0xFF) for i in [24, 16, 8, 0]])
                    # Calculate CIDR prefix
                    cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                    
                    # Create a network object
                    network = str(ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False))
                    
                    # Check if this network is already in our list (to avoid duplicates)
                    if not any(i['network'] == network for i in interfaces):
                        interfaces.append({
                            'name': current_interface,
                            'ip': ip,
                            'netmask': netmask,
                            'cidr': cidr,
                            'network': network
                        })
        
        elif is_linux():
            # Linux specific commands
            try:
                # Try to get default gateway with ip route (modern Linux)
                ip_route_output = subprocess.check_output(['ip', 'route', 'show', 'default']).decode('utf-8')
                gateway_match = re.search(r'default via ([0-9.]+)', ip_route_output)
                if gateway_match:
                    gateway = gateway_match.group(1)
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Fallback to route command (older Linux)
                try:
                    route_output = subprocess.check_output(['route', '-n']).decode('utf-8')
                    for line in route_output.splitlines():
                        if line.startswith('0.0.0.0'):
                            parts = line.split()
                            if len(parts) >= 2:
                                gateway = parts[1]
                                break
                except:
                    pass
            
            # Get network interfaces - try ip first (modern Linux), fallback to ifconfig
            try:
                # Try ip command first
                ip_addr_output = subprocess.check_output(['ip', '-4', 'addr', 'show']).decode('utf-8')
                
                # Parse the output to get interface info
                current_interface = None
                for line in ip_addr_output.splitlines():
                    if line[0].isdigit() and ':' in line:
                        # This is an interface line
                        match = re.search(r'^\d+: ([^:]+):', line)
                        if match:
                            current_interface = match.group(1)
                    elif current_interface and 'inet ' in line:
                        # This is an IPv4 address line
                        match = re.search(r'inet ([0-9.]+)/(\d+)', line)
                        if match:
                            ip = match.group(1)
                            cidr = int(match.group(2))
                            # Calculate netmask from CIDR
                            netmask_bits = (0xffffffff >> (32 - cidr)) << (32 - cidr)
                            netmask = '.'.join([str((netmask_bits >> i) & 0xFF) for i in [24, 16, 8, 0]])
                            
                            # Create a network object
                            network = str(ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False))
                            
                            # Check if this network is already in our list (to avoid duplicates)
                            if not any(i['network'] == network for i in interfaces):
                                interfaces.append({
                                    'name': current_interface,
                                    'ip': ip,
                                    'netmask': netmask,
                                    'cidr': cidr,
                                    'network': network
                                })
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Fallback to ifconfig
                try:
                    ifconfig_output = subprocess.check_output(['ifconfig']).decode('utf-8')
                    
                    # Find the active interfaces with IPv4 addresses
                    current_interface = None
                    for line in ifconfig_output.splitlines():
                        if ' Link' in line and ':' in line:
                            current_interface = line.split(':')[0]
                        elif current_interface and 'inet addr:' in line:
                            # Traditional Ubuntu 16.04 ifconfig format
                            ip_match = re.search(r'inet addr:([0-9.]+)', line)
                            mask_match = re.search(r'Mask:([0-9.]+)', line)
                            
                            if ip_match and mask_match:
                                ip = ip_match.group(1)
                                netmask = mask_match.group(1)
                                # Calculate CIDR prefix
                                cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                                
                                # Create a network object
                                network = str(ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False))
                                
                                # Check if this network is already in our list (to avoid duplicates)
                                if not any(i['network'] == network for i in interfaces):
                                    interfaces.append({
                                        'name': current_interface,
                                        'ip': ip,
                                        'netmask': netmask,
                                        'cidr': cidr,
                                        'network': network
                                    })
                except:
                    pass
        
        return {
            'gateway': gateway,
            'interfaces': interfaces
        }
    except Exception as e:
        print(f"Error getting network info: {e}", file=sys.stderr)
        return {
            'gateway': None,
            'interfaces': []
        }

def is_likely_nas_ip(ip):
    """
    Heuristic to determine if an IP is likely to be a NAS device
    based on common NAS IP patterns
    """
    # Common NAS IP patterns:
    # - Often ends with low numbers (1-20)
    # - Often in reserved ranges for servers
    # - Avoid common router/gateway IPs

    ip_obj = ipaddress.IPv4Address(ip)
    ip_parts = str(ip).split('.')
    last_octet = int(ip_parts[-1])
    
    # Skip gateway-like IPs (often end in .1, .254)
    if last_octet == 1 or last_octet == 254:
        return False
    
    # Higher priority for IPs that are likely to be servers (10-30, 100-200)
    if (10 <= last_octet <= 30) or (100 <= last_octet <= 200):
        return True
    
    return None  # Neutral priority

def find_active_hosts(subnet, max_hosts=254):
    """
    Quickly find active hosts on a subnet using ARP scanning when available
    Falls back to ping for smaller subnets
    """
    active_hosts = []
    subnet_obj = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(subnet_obj.hosts())
    
    # Limit scan size
    if len(hosts) > max_hosts:
        hosts = hosts[:max_hosts]
    
    try:
        # Try ARP-scan if available (much faster than ping)
        if is_linux():
            try:
                # Try using arp-scan if installed
                arp_output = subprocess.check_output(['arp-scan', '--localnet'], timeout=10).decode('utf-8')
                for line in arp_output.splitlines():
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)', line)
                    if match:
                        ip, mac = match.groups()
                        ip_obj = ipaddress.IPv4Address(ip)
                        
                        # Check if IP is in our target subnet
                        if ip_obj in subnet_obj:
                            # Check if MAC prefix matches known NAS vendors
                            is_known_nas = any(mac.lower().startswith(prefix.lower()) for prefix in COMMON_NAS_MAC_PREFIXES)
                            
                            active_hosts.append({
                                'ip': ip, 
                                'likely_nas': is_known_nas,
                                'priority': 1 if is_known_nas else 2
                            })
                
                if active_hosts:
                    return active_hosts
            except (subprocess.SubprocessError, FileNotFoundError):
                pass  # Fall through to next method if arp-scan fails
        
        # Try using system ARP table
        try:
            if is_macos():
                arp_output = subprocess.check_output(['arp', '-a'], timeout=5).decode('utf-8')
            else:
                arp_output = subprocess.check_output(['arp', '-n'], timeout=5).decode('utf-8')
            
            for line in arp_output.splitlines():
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)[^\w]+([0-9a-fA-F:]+)', line)
                if match:
                    ip, mac = match.groups()
                    ip_obj = ipaddress.IPv4Address(ip)
                    
                    # Check if IP is in our target subnet
                    if ip_obj in subnet_obj:
                        # Check if MAC prefix matches known NAS vendors
                        is_known_nas = any(mac.lower().startswith(prefix.lower()) for prefix in COMMON_NAS_MAC_PREFIXES)
                        
                        active_hosts.append({
                            'ip': ip, 
                            'likely_nas': is_known_nas,
                            'priority': 1 if is_known_nas else 2
                        })
            
            if active_hosts:
                return active_hosts
        except (subprocess.SubprocessError, FileNotFoundError):
            pass  # Fall through to ping method if ARP fails
    
    except Exception as e:
        print(f"Error during ARP scanning: {e}", file=sys.stderr)
    
    # If the subnet is small or we couldn't use ARP, use optimized ping scanning
    if len(hosts) <= 25 or not active_hosts:
        try:
            # For small networks, use ping
            with ThreadPoolExecutor(max_workers=25) as executor:
                # Create a list to store the futures
                futures = []
                
                # Submit ping tasks
                for ip in hosts:
                    ip_str = str(ip)
                    priority = is_likely_nas_ip(ip_str)
                    
                    # Submit task with a tuple of (ip, priority)
                    futures.append((executor.submit(ping_host, ip_str), ip_str, priority))
                
                # Process results as they complete
                for future, ip, priority in futures:
                    if future.result():
                        active_hosts.append({
                            'ip': ip, 
                            'likely_nas': priority is True,
                            'priority': 1 if priority is True else (2 if priority is None else 3)
                        })
        except Exception as e:
            print(f"Error during ping scanning: {e}", file=sys.stderr)
    
    # If we still don't have hosts, return a subset of IPs based on heuristics
    if not active_hosts:
        # Use heuristic selection to pick likely NAS IPs
        for ip in hosts:
            ip_str = str(ip)
            priority = is_likely_nas_ip(ip_str)
            
            if priority is not False:  # Include if not explicitly excluded
                active_hosts.append({
                    'ip': ip_str, 
                    'likely_nas': priority is True,
                    'priority': 1 if priority is True else 2
                })
    
    # Sort by priority (lower number = higher priority)
    active_hosts.sort(key=lambda x: x['priority'])
    
    return active_hosts

def ping_host(ip, timeout=0.5):
    """
    Check if a host is up using ping
    Returns True if host responds, False otherwise
    """
    try:
        # Different ping command parameters for different OSes
        if is_macos():
            cmd = ['ping', '-c', '1', '-W', str(int(timeout * 1000)), '-t', '1', ip]
        else:
            cmd = ['ping', '-c', '1', '-W', '1', ip]
        
        # Run the ping command
        subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
        return True
    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return False

def get_device_name(ip, timeout=DEFAULT_TIMEOUT):
    """
    Try multiple methods to get a meaningful device name.
    Returns a tuple of (name, name_source) where name_source indicates how the name was found.
    """
    # For SMB/NetBIOS devices, try extra hard to get device info
    # This is especially useful for NAS devices
    if is_likely_nas_ip(ip):
        # Try multiple methods with slightly longer timeouts
        timeout_nas = min(timeout * 2, 1.0)  # Don't wait too long, but give more time
    else:
        timeout_nas = timeout
    
    # First try standard DNS resolution (fastest)
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return (hostname, "DNS")
    except (socket.herror, socket.gaierror):
        pass
    
    # For Linux, try avahi/mDNS if available
    if is_linux():
        try:
            # Try avahi-resolve if available (mDNS resolution)
            avahi_output = subprocess.check_output(
                ['avahi-resolve', '-a', ip], 
                stderr=subprocess.DEVNULL, 
                timeout=timeout_nas
            ).decode('utf-8').strip()
            
            if avahi_output and ip in avahi_output:
                # Extract hostname from output (format is typically "ip hostname")
                parts = avahi_output.split()
                if len(parts) >= 2:
                    return (parts[1], "mDNS")
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
    
    # For macOS, try using dns-sd for mDNS lookup
    if is_macos():
        try:
            # Reverse DNS with dns-sd (mDNS on macOS)
            dns_sd_output = subprocess.check_output(
                ['dns-sd', '-Q', ip, '-timeout', '1'],
                stderr=subprocess.DEVNULL,
                timeout=timeout_nas+1
            ).decode('utf-8')
            
            # Parse the output for hostnames
            matches = re.findall(r'can be reached at ([^:]+)\.local', dns_sd_output)
            if matches:
                return (f"{matches[0]}.local", "mDNS")
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
    
    # Try NetBIOS name resolution for Windows/SMB devices
    try:
        # Use nmblookup on Linux or nbtscan if available
        if is_linux():
            try:
                # First try nmblookup (part of Samba)
                nmb_output = subprocess.check_output(
                    ['nmblookup', '-A', ip],
                    stderr=subprocess.DEVNULL,
                    timeout=timeout_nas
                ).decode('utf-8')
                
                # Look for NetBIOS name
                match = re.search(r'<00> B <ACTIVE>\s+([^\s]+)', nmb_output)
                if match:
                    return (match.group(1), "NetBIOS")
            except (subprocess.SubprocessError, FileNotFoundError):
                # Try nbtscan as fallback
                try:
                    nbt_output = subprocess.check_output(
                        ['nbtscan', ip],
                        stderr=subprocess.DEVNULL,
                        timeout=timeout_nas
                    ).decode('utf-8')
                    
                    match = re.search(ip + r'\s+([^\s]+)', nbt_output)
                    if match:
                        return (match.group(1), "NetBIOS")
                except (subprocess.SubprocessError, FileNotFoundError):
                    pass
        
        # On macOS, we might have to install nbtscan or equivalent
        # But we can try a basic SMB connection to get info
        if is_macos():
            # First try the smbutil lookup command
            try:
                # Use smbutil to get NetBIOS name on macOS
                smb_output = subprocess.check_output(
                    ['smbutil', 'lookup', ip],
                    stderr=subprocess.DEVNULL,
                    timeout=timeout_nas
                ).decode('utf-8')
                
                # Parse output for server name
                match = re.search(r'server name: ([^\s]+)', smb_output, re.IGNORECASE)
                if match:
                    return (match.group(1), "SMB-lookup")
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
            
            # Then try smbutil view which might work better with NAS devices
            try:
                view_cmd = ['smbutil', 'view', f'//{ip}']
                smb_view_output = subprocess.check_output(
                    view_cmd,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout_nas
                ).decode('utf-8')
                
                # Parse the output for the server name
                lines = smb_view_output.splitlines()
                if lines and len(lines) > 0:
                    # The first line often contains server info
                    server_line = lines[0]
                    match = re.search(r'Server: (.+?)$', server_line)
                    if match and match.group(1) != ip:
                        return (match.group(1), "SMB-view")
                
                    # Try another pattern sometimes seen
                    for line in lines:
                        if "WORKGROUP" in line or "Domain:" in line:
                            parts = line.split()
                            if len(parts) > 1 and parts[1] != ip:
                                return (parts[1], "SMB-domain")
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
    except Exception as e:
        # Silently handle any errors in name resolution
        pass
    
    # Try SNMP for device name if possible (requires net-snmp tools)
    try:
        # This will only work if snmpget is installed and device has SNMP enabled with default community
        snmp_output = subprocess.check_output(
            ['snmpget', '-v', '2c', '-c', 'public', '-t', str(timeout_nas), '-r', '1', ip, '1.3.6.1.2.1.1.5.0'],
            stderr=subprocess.DEVNULL,
            timeout=timeout_nas
        ).decode('utf-8')
        
        # Parse output for system name
        match = re.search(r'STRING: ([^\s"]+)', snmp_output)
        if match:
            return (match.group(1), "SNMP")
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    
    # Final attempt: if it's port 445 is open, try to get SMB info directly
    # using a raw socket (this doesn't require external tools)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_nas)
        if sock.connect_ex((ip, 445)) == 0:
            # We could implement a basic SMB protocol negotiation here
            # to get the server name, but that's quite complex
            # For now, we'll just indicate that it's an SMB server
            sock.close()
            return (ip, "SMB-Device")
    except:
        pass
    finally:
        try:
            sock.close()
        except:
            pass
    
    # If we reach here, we couldn't find a name
    return (ip, "IP")

def scan_for_nas(ip, ports=DEFAULT_PORTS, timeout=DEFAULT_TIMEOUT):
    """
    Scan an IP address for common NAS ports
    Optimized version with reduced timeout and early termination
    """
    # Create a hostname from the IP
    device_name, name_source = get_device_name(ip, timeout)
    
    # Test TCP ports - optimized to check most common ports first
    # Sort ports by likelihood of being a NAS service
    # SMB is most common for NAS, followed by NFS
    sorted_ports = sorted(ports, key=lambda p: (p != 445, p != 2049, p))
    
    open_ports = []
    
    # Early stop condition - if we detect a clear NAS signature, stop scanning
    smb_detected = False
    nfs_detected = False
    
    for port in sorted_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
                
                # Check if we've found obvious NAS services
                if port == 445 or port == 139:
                    smb_detected = True
                elif port == 2049 or port == 111:
                    nfs_detected = True
                
                # Early termination if we have clear evidence of NAS
                if smb_detected and nfs_detected and len(open_ports) >= 3:
                    break
        except:
            pass
        finally:
            sock.close()
    
    # If no open ports, return None
    if not open_ports:
        return None
    
    # Map ports to services
    services = {
        445: 'SMB',
        139: 'NetBIOS/SMB',
        111: 'NFS Portmapper',
        2049: 'NFS',
        548: 'AFP'
    }
    
    detected_services = [services.get(port, f"Unknown ({port})") for port in open_ports]
    
    return {
        'type': 'discovered',
        'ip': ip,
        'hostname': device_name,
        'name_source': name_source,
        'open_ports': open_ports,
        'services': detected_services
    }

def format_single_drive(drive, index=None, colorize=False):
    """
    Format a single NAS drive for display
    With optional colorization for terminal output
    """
    output = []
    
    # ANSI color codes for terminal output
    GREEN = '\033[92m' if colorize else ''
    YELLOW = '\033[93m' if colorize else ''
    BLUE = '\033[94m' if colorize else ''
    BOLD = '\033[1m' if colorize else ''
    CYAN = '\033[96m' if colorize else ''  # Added cyan color for variety
    MAGENTA = '\033[95m' if colorize else ''  # Added magenta for device names
    UNDERLINE = '\033[4m' if colorize else ''  # Added underline for emphasis
    END = '\033[0m' if colorize else ''
    
    if drive['type'] == 'mounted':
        if index is not None:
            output.append(f"{BOLD}{index}. Protocol: {GREEN}{drive['protocol'].upper()}{END}")
        else:
            output.append(f"{BOLD}Protocol: {GREEN}{drive['protocol'].upper()}{END}")
        output.append(f"{BOLD}   Server:   {BLUE}{drive['server']}{END}")
        output.append(f"{BOLD}   Share:    {drive['share']}{END}")
        output.append(f"{BOLD}   Mounted:  {drive['mount_point']}{END}")
    else:  # discovered
        if index is not None:
            output.append(f"{BOLD}{index}. IP:       {YELLOW}{drive['ip']}{END}")
        else:
            output.append(f"{BOLD}IP:       {YELLOW}{drive['ip']}{END}")
        
        # Add device name if we found one different from the IP
        if 'hostname' in drive and drive['hostname'] != drive['ip']:
            output.append(f"{BOLD}   Name:     {MAGENTA}{drive['hostname']}{END} {GREEN}({drive.get('name_source', 'DNS')}){END}")
        else:
            # If using name resolution debugging
            if 'name_source' in drive:
                output.append(f"{BOLD}   Name:     {YELLOW}Unknown {GREEN}(attempted {drive.get('name_source', 'DNS')}){END}")
            
        # Only show services line
        output.append(f"{BOLD}   Services: {GREEN}{', '.join(drive['services'])}{END}")
    
    return "\n".join(output)

def format_output(nas_drives):
    """
    Format the output of detected NAS drives
    """
    output = []
    
    if not nas_drives:
        return "No NAS drives found."
    
    output.append("=" * 80)
    output.append(f"NAS Drives Found: {len(nas_drives)}")
    output.append("=" * 80)
    
    # Group by type
    mounted = [d for d in nas_drives if d['type'] == 'mounted']
    discovered = [d for d in nas_drives if d['type'] == 'discovered']
    
    if mounted:
        output.append("\nMOUNTED NAS DRIVES:")
        output.append("-" * 80)
        for i, drive in enumerate(mounted, 1):
            output.append(format_single_drive(drive, i))
            output.append("")
    
    if discovered:
        output.append("\nDISCOVERED NAS DEVICES (NOT MOUNTED):")
        output.append("-" * 80)
        for i, device in enumerate(discovered, 1):
            output.append(format_single_drive(device, i))
            output.append("")
    
    return "\n".join(output)

def format_time(seconds):
    """
    Format seconds into a human-readable time string
    """
    minutes, seconds = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"

def find_nas_drives(threads=DEFAULT_THREADS, timeout=DEFAULT_TIMEOUT, use_color=True, sound_alert=False):
    """
    Main function to find and list NAS drives
    """
    start_time = time.time()
    print("Scanning for NAS drives, please wait...\n")
    
    # Get mounted drives
    print("Checking for mounted NAS drives...")
    mounted_drives = get_mounted_nas_drives()
    elapsed = time.time() - start_time
    print(f"Found {len(mounted_drives)} mounted drives. Elapsed time: {format_time(elapsed)}\n")
    
    # Display mounted drives progressively
    if mounted_drives:
        print(("\033[1m" if use_color else "") + "MOUNTED NAS DRIVES:" + ("\033[0m" if use_color else ""))
        print("-" * 80)
        for i, drive in enumerate(mounted_drives, 1):
            print(format_single_drive(drive, i, use_color))
            print()
    
    # Get network info
    print("Gathering network information...")
    network_info = get_local_network_info()
    
    # Networks to scan
    networks_to_scan = []
    for interface in network_info['interfaces']:
        # Skip localhost and non-private networks
        if interface['name'].startswith('lo') or not ipaddress.IPv4Address(interface['ip']).is_private:
            continue
        networks_to_scan.append(interface['network'])
    
    elapsed = time.time() - start_time
    print(f"Found {len(networks_to_scan)} networks to scan. Elapsed time: {format_time(elapsed)}\n")
    
    # Scan the networks for NAS devices
    discovered_devices = []
    scanned_ips = set()  # Keep track of IPs we've already scanned
    last_progress_update = time.time()
    
    # Bold title with color if enabled
    print(("\033[1m" if use_color else "") + "DISCOVERED NAS DEVICES (NOT MOUNTED):" + ("\033[0m" if use_color else ""))
    print("-" * 80)
    
    # Set to keep track of IPs we've already displayed
    displayed_ips = set()
    
    # Advanced host discovery first to optimize scanning
    print("Performing host discovery...")
    
    # Find active hosts across all networks first - much faster than scanning everything
    total_hosts = 0
    active_hosts_by_network = {}
    
    for network in networks_to_scan:
        print(f"Discovering active hosts on {network}...")
        active_hosts = find_active_hosts(network)
        active_hosts_by_network[network] = active_hosts
        total_hosts += len(active_hosts)
    
    # Sort hosts by likelihood of being NAS devices
    all_hosts = []
    for network, hosts in active_hosts_by_network.items():
        all_hosts.extend(hosts)
    
    scan_start_time = time.time()
    hosts_scanned = 0
    devices_found = 0
    
    # Use a larger thread pool for scanning
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit jobs prioritizing likely NAS devices first
        future_to_ip = {}
        for host in all_hosts:
            ip = host['ip']
            # Skip already scanned IPs
            if ip in scanned_ips:
                continue
            
            scanned_ips.add(ip)
            future_to_ip[executor.submit(scan_for_nas, ip, DEFAULT_PORTS, timeout)] = ip
        
        # Process results as they come in
        for future in future_to_ip:
            result = future.result()
            hosts_scanned += 1
            
            # Show progress every 5 seconds or after scanning 50 hosts
            current_time = time.time()
            if hosts_scanned % 50 == 0 or current_time - last_progress_update >= 3:
                elapsed = current_time - start_time
                scan_elapsed = current_time - scan_start_time
                percent_complete = (hosts_scanned / total_hosts) * 100 if total_hosts > 0 else 0
                scan_rate = hosts_scanned / scan_elapsed if scan_elapsed > 0 else 0
                
                # Estimate remaining time
                if scan_rate > 0 and hosts_scanned < total_hosts:
                    remaining_hosts = total_hosts - hosts_scanned
                    remaining_seconds = remaining_hosts / scan_rate
                    remaining_time = format_time(remaining_seconds)
                else:
                    remaining_time = "unknown"
                
                progress_msg = (
                    f"Progress: {hosts_scanned}/{total_hosts} hosts scanned ({percent_complete:.1f}%), "
                    f"Found {devices_found} NAS devices, "
                    f"Elapsed: {format_time(elapsed)}, "
                    f"Est. remaining: {remaining_time}"
                )
                
                # Clear line and print progress
                print("\r" + " " * 80, end="\r")  # Clear the line
                print(f"\r{progress_msg}", end="", flush=True)
                
                last_progress_update = current_time
            
            if result:
                discovered_devices.append(result)
                
                # Check if this IP is already in our mounted drives or displayed list
                if (result['ip'] not in displayed_ips and 
                    result['ip'] not in set(drive['server'] for drive in mounted_drives) and
                    result['hostname'] not in set(drive['server'] for drive in mounted_drives)):
                    
                    # Clear the progress line
                    print("\r" + " " * 100)  # Clear the line with a newline and extra spaces
                    
                    # Play alert sound if enabled (ASCII bell character)
                    if sound_alert:
                        print('\a', end='', flush=True)
                    
                    
                    # Print the new device with color highlighting
                    devices_found += 1
                    print(format_single_drive(result, devices_found, use_color))
                    print()
                    
                    # Add to displayed set
                    displayed_ips.add(result['ip'])
                    
                    # Print a separator
                    if not use_color:
                        print("-" * 80)
                    
                    # Restore progress display
                    progress_msg = (
                        f"Progress: {hosts_scanned}/{total_hosts} hosts scanned ({percent_complete:.1f}%), "
                        f"Found {devices_found} NAS devices, "
                        f"Elapsed: {format_time(elapsed)}, "
                        f"Est. remaining: {remaining_time}"
                    )
                    print(f"\r{progress_msg}", end="", flush=True)
    
    # Print a newline after the progress updates
    print()
    
    # Combine results and remove duplicates
    all_drives = mounted_drives
    
    # Add discovered devices that aren't already mounted
    mounted_ips = set(drive['server'] for drive in mounted_drives)
    added_ips = set()  # To avoid duplicate discovered devices
    
    for device in discovered_devices:
        if device['ip'] not in mounted_ips and device['hostname'] not in mounted_ips and device['ip'] not in added_ips:
            all_drives.append(device)
            added_ips.add(device['ip'])
    
    # Calculate and print total elapsed time
    total_elapsed = time.time() - start_time
    
    # Print summary with optional color
    print("\n" + "=" * 80)
    print(("\033[1m" if use_color else "") + "SCAN SUMMARY" + ("\033[0m" if use_color else ""))
    print("=" * 80)
    print(f"Total Hosts Scanned: {hosts_scanned}")
    print(f"Total NAS Devices Found: {len(all_drives)}")
    print(f"Mounted NAS Drives: {len(mounted_drives)}")
    print(f"Discovered NAS Devices: {len(added_ips)}")
    print(f"Total scan time: {format_time(total_elapsed)}")
    print("=" * 80)
    
    return all_drives

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Find NAS drives on your network')
    parser.add_argument('--threads', type=int, default=DEFAULT_THREADS,
                        help=f'Number of parallel scanning threads (default: {DEFAULT_THREADS})')
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT,
                        help=f'Socket connection timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    parser.add_argument('--sound', action='store_true',
                        help='Play a sound alert when a new NAS device is found')
    args = parser.parse_args()
    
    # Run the scan
    find_nas_drives(threads=args.threads, timeout=args.timeout, use_color=not args.no_color, sound_alert=args.sound) 