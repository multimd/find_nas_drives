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
import logging
from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange
import threading
import contextlib
from nmb.NetBIOS import NetBIOS
from smb.SMBConnection import SMBConnection

# Constants for scanning
DEFAULT_TIMEOUT = 0.2  # Reduced from 0.5s to 0.2s for faster scanning
DEFAULT_THREADS = 50   # Increased from 20 to 50 for better parallelization
DEFAULT_PORTS = [445, 139, 111, 2049, 548]  # Common NAS ports

# Common NAS vendor MAC address prefixes
NAS_MAC_PREFIXES = [
    '00:10:75',  # Synology
    '00:11:32',  # Synology
    '00:24:8C',  # QNAP
    '24:5E:BE',  # QNAP
    'E0:37:17',  # QNAP
    '00:1B:A9',  # Western Digital
    '00:90:A9',  # Western Digital
    '00:14:EE',  # Western Digital
    '00:0C:29',  # VMware (for NAS VMs)
    '00:50:56',  # VMware (for NAS VMs)
    '00:50:43',  # Buffalo
]

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('find_nas')
# Set to WARNING to suppress most logs by default
logger.setLevel(logging.WARNING)

# Global cache for device names to avoid redundant lookups
DEVICE_NAME_CACHE = {}

def is_macos():
    """Check if running on macOS"""
    return platform.system() == 'Darwin'

def is_linux():
    """Check if running on Linux"""
    return platform.system() == 'Linux'

def get_mounted_nas_drives():
    """Get mounted NAS drives on the system."""
    return find_mounted_drives()

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
    """Determine if an IP is likely to be a NAS based on various heuristics."""
    # Check against common NAS vendor MAC prefixes
    # Note: This will only work if the MAC is already in the ARP table
    try:
        # Get MAC address via ARP
        if is_macos():
            arp_output = subprocess.check_output(['arp', '-n', ip], stderr=subprocess.DEVNULL).decode('utf-8')
            mac_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', arp_output)
            if mac_match:
                mac = mac_match.group(1).lower()
                # Check against known NAS vendor MAC prefixes
                for prefix in NAS_MAC_PREFIXES:
                    if mac.startswith(prefix.lower().replace('-', ':')):
                        return True
        elif is_linux():
            # Get MAC address from ip neighbor
            ip_neigh_output = subprocess.check_output(['ip', 'neighbor', 'show', ip], 
                                                     stderr=subprocess.DEVNULL).decode('utf-8')
            mac_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', ip_neigh_output)
            if mac_match:
                mac = mac_match.group(1).lower()
                # Check against known NAS vendor MAC prefixes
                for prefix in NAS_MAC_PREFIXES:
                    if mac.startswith(prefix.lower().replace('-', ':')):
                        return True
    except:
        pass
    
    # Could add more heuristics here
    return False

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
                            is_known_nas = any(mac.lower().startswith(prefix.lower()) for prefix in NAS_MAC_PREFIXES)
                            
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
                        is_known_nas = any(mac.lower().startswith(prefix.lower()) for prefix in NAS_MAC_PREFIXES)
                        
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

@lru_cache(maxsize=256)
def get_device_name(ip, timeout=DEFAULT_TIMEOUT, debug=False):
    """
    Try multiple methods to get a meaningful device name.
    Returns a tuple of (name, name_source) where name_source indicates how the name was found.
    
    Enhanced with:
    - Zeroconf for mDNS resolution
    - NetBIOS via pysmb
    - SMB via pysmb
    - Better error handling and detailed logging
    - Results caching
    """
    # Enable debugging if requested
    if debug:
        logger.setLevel(logging.DEBUG)
    
    # Check cache first
    if ip in DEVICE_NAME_CACHE:
        logger.debug(f"Using cached name for {ip}: {DEVICE_NAME_CACHE[ip]}")
        return DEVICE_NAME_CACHE[ip]
        
    # For SMB/NetBIOS devices, try extra hard to get device info
    # This is especially useful for NAS devices
    if is_likely_nas_ip(ip):
        # Try multiple methods with slightly longer timeouts
        timeout_nas = min(timeout * 2, 1.0)  # Don't wait too long, but give more time
    else:
        timeout_nas = timeout
    
    # First try standard DNS resolution (fastest)
    try:
        logger.debug(f"Attempting DNS resolution for {ip}")
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            logger.debug(f"DNS resolution succeeded for {ip}: {hostname}")
            result = (hostname, "DNS")
            DEVICE_NAME_CACHE[ip] = result
            return result
    except (socket.herror, socket.gaierror) as e:
        logger.debug(f"DNS resolution failed for {ip}: {e}")
    
    # Try mDNS resolution using zeroconf
    try:
        logger.debug(f"Attempting mDNS resolution for {ip}")
        # Create a new event to signal when we've found a name
        found_event = threading.Event()
        mdns_name = [None]
        
        # Define listener callback
        def on_service_state_change(zeroconf, service_type, name, state_change=None, state=None):
            # Handle both old and new zeroconf API versions
            actual_state = state_change if state_change is not None else state
            if actual_state == ServiceStateChange.Added:
                info = zeroconf.get_service_info(service_type, name)
                if info and info.addresses:
                    for address in info.addresses:
                        addr = socket.inet_ntoa(address)
                        if addr == ip:
                            mdns_name[0] = name.split('.')[0]  # Get the first part of the name
                            found_event.set()
        
        # Services to look for (common NAS services)
        service_types = [
            "_smb._tcp.local.",
            "_afpovertcp._tcp.local.",
            "_nfs._tcp.local.",
            "_http._tcp.local.",
            "_https._tcp.local.",
        ]
        
        # Use zeroconf to browse for services
        zeroconf = Zeroconf()
        browsers = []
        
        try:
            for service_type in service_types:
                browsers.append(ServiceBrowser(zeroconf, service_type, handlers=[on_service_state_change]))
            
            # Wait for a short time to find the device
            found_event.wait(timeout_nas)
            
            if mdns_name[0]:
                logger.debug(f"mDNS resolution succeeded for {ip}: {mdns_name[0]}")
                result = (mdns_name[0], "mDNS-Zeroconf")
                DEVICE_NAME_CACHE[ip] = result
                return result
        finally:
            zeroconf.close()
    except Exception as e:
        logger.debug(f"mDNS resolution failed for {ip}: {e}")
    
    # Try NetBIOS name lookup using pysmb
    try:
        logger.debug(f"Attempting NetBIOS resolution for {ip}")
        netbios = NetBIOS()
        names = netbios.queryIPForName(ip, timeout=timeout_nas)
        if names and names[0]:
            logger.debug(f"NetBIOS resolution succeeded for {ip}: {names[0]}")
            result = (names[0], "NetBIOS-pysmb")
            DEVICE_NAME_CACHE[ip] = result
            return result
    except Exception as e:
        logger.debug(f"NetBIOS resolution failed for {ip}: {e}")
    
    # Try SMB connection for server information
    try:
        logger.debug(f"Attempting SMB connection to {ip}")
        # Create an SMB connection (no credentials, just checking the server name)
        conn = SMBConnection('', '', 'finder', '', use_ntlm_v2=True)
        
        # Try to connect with a short timeout
        with socket.socket() as s:
            s.settimeout(timeout_nas)
            if conn.connect(ip, 445, timeout=timeout_nas):
                server_name = conn.remote_name
                if server_name and server_name != ip:
                    logger.debug(f"SMB resolution succeeded for {ip}: {server_name}")
                    result = (server_name, "SMB-pysmb")
                    DEVICE_NAME_CACHE[ip] = result
                    return result
    except Exception as e:
        logger.debug(f"SMB resolution failed for {ip}: {e}")
    
    # Fallback to traditional command line methods if Python libraries fail
    
    # For Linux, try avahi/mDNS if available
    if is_linux():
        try:
            logger.debug(f"Attempting avahi-resolve for {ip}")
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
                    hostname = parts[1]
                    logger.debug(f"avahi-resolve succeeded for {ip}: {hostname}")
                    result = (hostname, "mDNS-avahi")
                    DEVICE_NAME_CACHE[ip] = result
                    return result
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.debug(f"avahi-resolve failed for {ip}: {e}")
    
    # For macOS, try using dns-sd for mDNS lookup
    if is_macos():
        try:
            logger.debug(f"Attempting dns-sd for {ip}")
            # Reverse DNS with dns-sd (mDNS on macOS)
            dns_sd_output = subprocess.check_output(
                ['dns-sd', '-Q', ip, '-timeout', '1'],
                stderr=subprocess.DEVNULL,
                timeout=timeout_nas+1
            ).decode('utf-8')
            
            # Parse the output for hostnames
            matches = re.findall(r'can be reached at ([^:]+)\.local', dns_sd_output)
            if matches:
                hostname = f"{matches[0]}.local"
                logger.debug(f"dns-sd succeeded for {ip}: {hostname}")
                result = (hostname, "mDNS-dns-sd")
                DEVICE_NAME_CACHE[ip] = result
                return result
        except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
            logger.debug(f"dns-sd failed for {ip}: {e}")
    
    # Fallback to legacy methods only if the newer methods fail
    
    # Try NetBIOS name resolution (legacy methods)
    try:
        logger.debug(f"Attempting legacy NetBIOS methods for {ip}")
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
                    hostname = match.group(1)
                    logger.debug(f"nmblookup succeeded for {ip}: {hostname}")
                    result = (hostname, "NetBIOS-nmblookup")
                    DEVICE_NAME_CACHE[ip] = result
                    return result
            except (subprocess.SubprocessError, FileNotFoundError) as e:
                logger.debug(f"nmblookup failed for {ip}: {e}")
                # Try nbtscan as fallback
                try:
                    nbt_output = subprocess.check_output(
                        ['nbtscan', ip],
                        stderr=subprocess.DEVNULL,
                        timeout=timeout_nas
                    ).decode('utf-8')
                    
                    match = re.search(ip + r'\s+([^\s]+)', nbt_output)
                    if match:
                        hostname = match.group(1)
                        logger.debug(f"nbtscan succeeded for {ip}: {hostname}")
                        result = (hostname, "NetBIOS-nbtscan")
                        DEVICE_NAME_CACHE[ip] = result
                        return result
                except (subprocess.SubprocessError, FileNotFoundError) as e:
                    logger.debug(f"nbtscan failed for {ip}: {e}")
        
        # On macOS, try smbutil commands
        if is_macos():
            # First try the smbutil lookup command
            try:
                logger.debug(f"Attempting smbutil lookup for {ip}")
                # Use smbutil to get NetBIOS name on macOS
                smb_output = subprocess.check_output(
                    ['smbutil', 'lookup', ip],
                    stderr=subprocess.DEVNULL,
                    timeout=timeout_nas
                ).decode('utf-8')
                
                # Parse output for server name
                match = re.search(r'server name: ([^\s]+)', smb_output, re.IGNORECASE)
                if match:
                    hostname = match.group(1)
                    logger.debug(f"smbutil lookup succeeded for {ip}: {hostname}")
                    result = (hostname, "SMB-lookup")
                    DEVICE_NAME_CACHE[ip] = result
                    return result
            except (subprocess.SubprocessError, FileNotFoundError) as e:
                logger.debug(f"smbutil lookup failed for {ip}: {e}")
            
            # Then try smbutil view
            try:
                logger.debug(f"Attempting smbutil view for {ip}")
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
                        hostname = match.group(1)
                        logger.debug(f"smbutil view succeeded for {ip}: {hostname}")
                        result = (hostname, "SMB-view")
                        DEVICE_NAME_CACHE[ip] = result
                        return result
                
                    # Try another pattern sometimes seen
                    for line in lines:
                        if "WORKGROUP" in line or "Domain:" in line:
                            parts = line.split()
                            if len(parts) > 1 and parts[1] != ip:
                                hostname = parts[1]
                                logger.debug(f"smbutil view (domain) succeeded for {ip}: {hostname}")
                                result = (hostname, "SMB-domain")
                                DEVICE_NAME_CACHE[ip] = result
                                return result
            except (subprocess.SubprocessError, FileNotFoundError) as e:
                logger.debug(f"smbutil view failed for {ip}: {e}")
    except Exception as e:
        # Handle any unexpected errors in the whole NetBIOS block
        logger.debug(f"All NetBIOS/SMB methods failed for {ip}: {e}")
    
    # Try SNMP for device name if possible
    try:
        logger.debug(f"Attempting SNMP query for {ip}")
        # This will only work if snmpget is installed and device has SNMP enabled with default community
        snmp_output = subprocess.check_output(
            ['snmpget', '-v', '2c', '-c', 'public', '-t', str(timeout_nas), '-r', '1', ip, '1.3.6.1.2.1.1.5.0'],
            stderr=subprocess.DEVNULL,
            timeout=timeout_nas
        ).decode('utf-8')
        
        # Parse output for system name
        match = re.search(r'STRING: ([^\s"]+)', snmp_output)
        if match:
            hostname = match.group(1)
            logger.debug(f"SNMP query succeeded for {ip}: {hostname}")
            result = (hostname, "SNMP")
            DEVICE_NAME_CACHE[ip] = result
            return result
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logger.debug(f"SNMP query failed for {ip}: {e}")
    
    # Final check: if it's port 445 is open, try to get SMB info directly
    try:
        logger.debug(f"Final check: Testing if {ip} has SMB port open")
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(timeout_nas)
            if sock.connect_ex((ip, 445)) == 0:
                # We know it's an SMB server but couldn't get its name
                logger.debug(f"Confirmed {ip} is an SMB server, but couldn't get name")
                result = (ip, "SMB-Device")
                DEVICE_NAME_CACHE[ip] = result
                return result
    except Exception as e:
        logger.debug(f"Final SMB socket check failed for {ip}: {e}")
    
    # If we reach here, we couldn't find a name
    logger.debug(f"All name resolution methods failed for {ip}")
    result = (ip, "IP")
    DEVICE_NAME_CACHE[ip] = result
    return result

def scan_for_nas(ip, ports=DEFAULT_PORTS, timeout=DEFAULT_TIMEOUT):
    """Scan an IP address for NAS services."""
    services = []
    
    # Common NAS service ports:
    # 445 - SMB
    # 139 - NetBIOS/SMB
    # 111 - NFS portmapper
    # 2049 - NFS
    # 548 - AFP
    
    try:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                if port == 445:
                    services.append("SMB")
                elif port == 139:
                    services.append("NetBIOS/SMB")
                elif port == 111 or port == 2049:
                    services.append("NFS")
                elif port == 548:
                    services.append("AFP")
                else:
                    services.append(f"Port {port}")
    except Exception as e:
        pass  # Ignore errors like refused connections, timeouts, etc.
    
    if services:
        # Only try to identify the hostname/device name if we have services
        # This will use the enhanced resolution that attempts multiple methods
        name_info = get_device_name(ip, timeout=timeout, debug=logger.level <= logging.DEBUG)
        device_name = name_info[0]
        name_source = name_info[1]
        
        return {
            'ip': ip,
            'name': device_name,
            'name_source': name_source,
            'services': services
        }
    
    return None

def format_single_drive(drive, use_color=True):
    """Format a single drive for display"""
    
    # ANSI color codes
    if use_color:
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        BOLD = '\033[1m'
        END = '\033[0m'
    else:
        GREEN = YELLOW = BLUE = CYAN = BOLD = END = ''
    
    if drive.get('mounted'):
        output = [f"{BOLD}{GREEN}Mounted Drive:{END}"]
        output.append(f"  Protocol: {drive['protocol']}")
        output.append(f"  Server:   {drive['server']}")
        output.append(f"  Share:    {drive['share']}")
        output.append(f"  Mounted:  {drive['mountpoint']}")
    else:
        output = [f"{BOLD}{YELLOW}NAS Device:{END}"]
        
        # Handle the name display
        device_name = drive['name']
        name_source = drive.get('name_source', 'Unknown')
        
        if device_name != drive['ip']:
            # Always show both name and IP address
            output.append(f"  Name:     {CYAN}{device_name}{END} ({name_source})")
            output.append(f"  IP:       {drive['ip']}")
        else:
            # Just IP address (no name was found)
            output.append(f"  IP:       {drive['ip']}")
        
        # Format services
        services = ', '.join(drive['services'])
        output.append(f"  Services: {BLUE}{services}{END}")
    
    return '\n'.join(output)

def format_output(nas_drives):
    """Format NAS drive output for display."""
    output = []
    
    # Sort drives: first mounted, then discovered
    # Sort mounted drives by protocol, then server
    mounted_drives = [d for d in nas_drives if d.get('mounted')]
    discovered_drives = [d for d in nas_drives if not d.get('mounted')]
    
    # Sort mounted drives by protocol, then server
    mounted_drives.sort(key=lambda d: (d['protocol'], d['server']))
    
    # Sort discovered drives by IP address
    discovered_drives.sort(key=lambda d: socket.inet_aton(d['ip']))
    
    # Concatenate the sorted lists
    sorted_drives = mounted_drives + discovered_drives
    
    # Format each drive
    for i, drive in enumerate(sorted_drives, 1):
        output.append(format_single_drive(drive))
        output.append("")  # Add a blank line between entries
    
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
    """Find all NAS drives on the local network."""
    total_start_time = time.time()
    
    print("Scanning for NAS drives...\n")
    
    # Display initial elapsed time
    def display_elapsed():
        elapsed = time.time() - total_start_time
        print(f"Elapsed time: {format_time(elapsed)}", end="\r", flush=True)
    
    # First, find mounted network drives
    display_elapsed()
    mounted_drives = get_mounted_nas_drives()
    
    if mounted_drives:
        # Clear the elapsed time line
        print(" " * 30, end="\r")
        print(f"Found {len(mounted_drives)} mounted drive(s):\n")
        for drive in mounted_drives:
            print(format_single_drive(drive, use_color=use_color))
            print()
    else:
        # Clear the elapsed time line
        print(" " * 30, end="\r")
        print("No mounted network drives found.\n")
    
    # Next, scan the network for NAS devices
    display_elapsed()
    print("Gathering network information...")
    
    # Get all available networks
    networks = get_local_networks()
    
    if not networks:
        # Clear the elapsed time line
        print(" " * 30, end="\r")
        print("No networks found to scan.\n")
        return
    
    # Clear the elapsed time line
    print(" " * 30, end="\r")
    print(f"Found {len(networks)} network(s) to scan.\n")
    
    # Track IPs we've scanned to avoid duplicates
    scanned_ips = set()
    # Track all discovered devices
    discovered_devices = []
    
    total_hosts_scanned = 0
    devices_found = len(mounted_drives)
    
    # Function to play a sound notification when a NAS is found
    def play_sound():
        if sound_alert:
            if is_macos():
                subprocess.run(['afplay', '/System/Library/Sounds/Ping.aiff'], stderr=subprocess.DEVNULL)
            elif is_linux():
                subprocess.run(['paplay', '/usr/share/sounds/freedesktop/stereo/complete.oga'], stderr=subprocess.DEVNULL)
    
    # Process each network in the list
    for network in networks:
        net = ipaddress.IPv4Network(network)
        display_elapsed()
        print(f"Performing host discovery on {network}...")
        hosts = discover_hosts(net, threads=threads)
        
        if not hosts:
            # Clear the elapsed time line
            print(" " * 30, end="\r")
            print(f"No hosts found on {network}.\n")
            continue
        
        # Clear the elapsed time line
        print(" " * 30, end="\r")
        print(f"Found {len(hosts)} host(s) on {network}.")
        print(f"Scanning hosts for NAS services...")
        
        # Used to store already discovered IPs for this network to avoid duplicates
        displayed_ips = set()
        
        # Keep track of progress
        current_host = 0
        total_hosts = len(hosts)
        
        # Function to scan a single host for NAS services
        def scan_host(ip):
            nonlocal current_host, total_hosts_scanned
            
            if ip in scanned_ips:
                return None
            
            scanned_ips.add(ip)
            total_hosts_scanned += 1
            current_host += 1
            
            # Print progress update with elapsed time
            if current_host % 5 == 0 or current_host == total_hosts:
                elapsed_time = time.time() - total_start_time
                progress_msg = f"Progress: {current_host}/{total_hosts} hosts scanned ({total_hosts_scanned} total) | Elapsed: {format_time(elapsed_time)}"
                print(progress_msg, end='\r', flush=True)
            
            # Scan the host for NAS services
            result = scan_for_nas(ip, timeout=timeout)
            return result
        
        # Use ThreadPoolExecutor for parallel scanning
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit all jobs
            future_results = [executor.submit(scan_host, str(ip)) for ip in hosts]
            
            # Process results as they complete
            for future in future_results:
                try:
                    result = future.result()
                    
                    # Skip non-NAS hosts
                    if result is None:
                        continue
                        
                    # Check if this is a new unique device
                    if (result['ip'] not in displayed_ips and 
                        result['ip'] not in set(drive['server'] for drive in mounted_drives) and
                        result['name'] not in set(drive['server'] for drive in mounted_drives)):
                        
                        # Clear the progress line
                        print(" " * 100, end="\r")
                        
                        # Add to the list of discovered devices
                        discovered_devices.append(result)
                        displayed_ips.add(result['ip'])
                        
                        # Play sound
                        play_sound()
                        
                        # Print the new device with color highlighting
                        devices_found += 1
                        print(format_single_drive(result, use_color=use_color))
                        print()
                        
                        # Show updated elapsed time after printing device
                        elapsed_time = time.time() - total_start_time
                        progress_msg = f"Progress: {current_host}/{total_hosts} hosts scanned ({total_hosts_scanned} total) | Elapsed: {format_time(elapsed_time)}"
                        print(progress_msg, end='\r', flush=True)
                        
                except Exception as e:
                    print(f"Error processing scan result: {e}")
    
    # Clear progress line
    print(" " * 100, end="\r")
    
    # Print summary
    total_time = time.time() - total_start_time
    print(f"\nScan Summary:")
    print(f"- Total hosts scanned: {total_hosts_scanned}")
    print(f"- Total NAS devices found: {devices_found}")
    print(f"- Total scan time: {format_time(total_time)}")
    
    # Combine mounted and discovered drives for easy reference
    all_drives = mounted_drives.copy()
    added_ips = set(drive['server'] for drive in mounted_drives)
    
    for device in discovered_devices:
        if device['ip'] not in added_ips and device['name'] not in added_ips and device['ip'] not in added_ips:
            all_drives.append(device)
            added_ips.add(device['ip'])
    
    return all_drives

def get_local_networks():
    """Get a list of local networks to scan."""
    networks = []
    
    try:
        print("DEBUG: Detecting local networks...")
        
        # Get IP addresses from hostname
        hostname = socket.gethostname()
        ips = []
        
        try:
            print(f"DEBUG: Getting IP for hostname: {hostname}")
            ip = socket.gethostbyname(hostname)
            if not ip.startswith('127.'):
                ips.append(ip)
                print(f"DEBUG: Found IP: {ip}")
        except Exception as e:
            print(f"DEBUG: Error getting hostname IP: {e}")
        
        # Try to get all IPs from socket
        try:
            print("DEBUG: Getting all IPs from socket.getaddrinfo")
            addresses = socket.getaddrinfo(socket.gethostname(), None)
            for addr in addresses:
                ip = addr[4][0]
                if not ip.startswith('127.') and ':' not in ip:  # Skip loopback and IPv6
                    if ip not in ips:
                        ips.append(ip)
                        print(f"DEBUG: Found IP: {ip}")
        except Exception as e:
            print(f"DEBUG: Error getting all IPs: {e}")
        
        # Use ifconfig/ip command as fallback
        try:
            if is_macos():
                print("DEBUG: Using ifconfig to get IPs")
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
                                    print(f"DEBUG: Found IP from ifconfig: {ip}")
            elif is_linux():
                print("DEBUG: Using ip command to get IPs")
                output = subprocess.check_output(['ip', '-4', 'addr', 'show']).decode('utf-8')
                # Find all inet addresses
                matches = re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+)', output)
                for ip in matches:
                    if not ip.startswith('127.') and ip not in ips:
                        ips.append(ip)
                        print(f"DEBUG: Found IP from ip command: {ip}")
        except Exception as e:
            print(f"DEBUG: Error using ifconfig/ip command: {e}")
        
        # Convert IPs to networks
        for ip in ips:
            try:
                if ipaddress.IPv4Address(ip).is_private:
                    # Assume a /24 network
                    network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                    if str(network) not in networks:
                        networks.append(str(network))
                        print(f"DEBUG: Added network: {network}")
            except Exception as e:
                print(f"DEBUG: Error processing IP {ip}: {e}")
        
    except Exception as e:
        logger.error(f"Error getting local networks: {e}")
        print(f"DEBUG: Exception in get_local_networks: {str(e)}")
        import traceback
        print(f"DEBUG: {traceback.format_exc()}")
    
    print(f"DEBUG: Returning networks: {networks}")
    return networks

def discover_hosts(network, threads=DEFAULT_THREADS):
    """
    Discover active hosts on a network using various methods.
    Returns a list of active host IPs.
    """
    hosts = []
    
    try:
        # Use ARP scan for host discovery (faster than ping sweep)
        if is_macos():
            # On macOS use arp-scan if available, otherwise ping sweep
            try:
                output = subprocess.check_output(['arp', '-a'], stderr=subprocess.DEVNULL).decode('utf-8')
                
                # Parse arp -a output
                for line in output.splitlines():
                    if '(' in line and ')' in line:
                        ip = line.split('(')[1].split(')')[0]
                        try:
                            if (ipaddress.IPv4Address(ip).is_private and
                                ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(network)):
                                hosts.append(ip)
                        except:
                            continue
            except (subprocess.SubprocessError, FileNotFoundError):
                # Fallback to ping sweep
                hosts = ping_sweep(network, threads)
        elif is_linux():
            # On Linux use arp-scan if available
            try:
                output = subprocess.check_output(['arp-scan', '--localnet'], stderr=subprocess.DEVNULL).decode('utf-8')
                
                # Parse arp-scan output
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            ip = parts[0]
                            if (ipaddress.IPv4Address(ip).is_private and
                                ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(network)):
                                hosts.append(ip)
                        except:
                            continue
            except (subprocess.SubprocessError, FileNotFoundError):
                # Fallback to ip neighbor
                try:
                    output = subprocess.check_output(['ip', 'neighbor'], stderr=subprocess.DEVNULL).decode('utf-8')
                    
                    # Parse ip neighbor output
                    for line in output.splitlines():
                        parts = line.split()
                        if len(parts) >= 1:
                            try:
                                ip = parts[0]
                                if (ipaddress.IPv4Address(ip).is_private and
                                    ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(network)):
                                    hosts.append(ip)
                            except:
                                continue
                except:
                    # Final fallback to ping sweep
                    hosts = ping_sweep(network, threads)
    except Exception as e:
        logger.error(f"Error discovering hosts: {e}")
        # Fallback to ping sweep
        hosts = ping_sweep(network, threads)
    
    # If we found no hosts, try a ping sweep
    if not hosts:
        hosts = ping_sweep(network, threads)
    
    return hosts

def ping_sweep(network, threads=DEFAULT_THREADS):
    """Perform a ping sweep to find active hosts on a network."""
    net = ipaddress.IPv4Network(network)
    active_hosts = []
    
    # Function to ping a single host
    def ping_host(ip):
        ip_str = str(ip)
        
        # Use different ping command formats based on OS
        if is_macos():
            cmd = ['ping', '-c', '1', '-W', '100', '-t', '1', ip_str]
        else:  # Linux
            cmd = ['ping', '-c', '1', '-W', '1', ip_str]
            
        try:
            subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            return ip_str
        except:
            return None
    
    # Use ThreadPoolExecutor for parallel pinging
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all jobs
        future_results = {executor.submit(ping_host, ip): ip for ip in net.hosts()}
        
        # Process results as they complete
        for future in future_results:
            result = future.result()
            if result:
                active_hosts.append(result)
    
    return active_hosts

def find_mounted_drives():
    """Find mounted network drives on the system."""
    mounted_drives = []
    
    try:
        if is_macos():
            # On macOS, use mount command
            output = subprocess.check_output(['mount']).decode('utf-8')
            
            # Look for AFP, SMB, NFS mounts
            for line in output.splitlines():
                mount_info = {}
                
                if 'afp://' in line:
                    # AFP mount
                    server_share = line.split('afp://')[1].split(' ')[0]
                    mount_point = line.split(' on ')[1].split(' (')[0]
                    
                    # Split server and share
                    if '/' in server_share:
                        server = server_share.split('/')[0]
                        share = '/'.join(server_share.split('/')[1:])
                    else:
                        server = server_share
                        share = '/'
                    
                    mount_info = {
                        'protocol': 'AFP',
                        'server': server,
                        'share': share,
                        'mountpoint': mount_point,
                        'mounted': True
                    }
                    
                # Enhanced SMB detection logic to handle more formats
                elif 'smb://' in line or 'smbfs' in line or ('//' in line and '@' in line):
                    # SMB mount
                    if 'smb://' in line:
                        server_share = line.split('smb://')[1].split(' ')[0]
                        mount_point = line.split(' on ')[1].split(' (')[0]
                    else:
                        # Handle //username@server/share format
                        server_share_part = line.split('//')[1].split(' on ')[0]
                        mount_point = line.split(' on ')[1].split(' (')[0]
                        
                        # Handle username in the server part
                        if '@' in server_share_part:
                            username, server_share = server_share_part.split('@', 1)
                        else:
                            server_share = server_share_part
                    
                    # Clean up server name (remove _smb._tcp.local suffix if present)
                    if '/' in server_share:
                        server = server_share.split('/')[0]
                        share = '/'.join(server_share.split('/')[1:])
                    else:
                        server = server_share
                        share = '/'
                        
                    # Remove ._smb._tcp.local suffix if present
                    if '._smb._tcp.local' in server:
                        server = server.replace('._smb._tcp.local', '')
                    
                    mount_info = {
                        'protocol': 'SMB',
                        'server': server,
                        'share': share,
                        'mountpoint': mount_point,
                        'mounted': True
                    }
                    
                elif ' nfs ' in line or ' nfs, ' in line:
                    # NFS mount
                    server_share = line.split(' from ')[1].split(' ')[0]
                    mount_point = line.split(' on ')[1].split(' ')[0]
                    
                    # Split server and share
                    if ':' in server_share:
                        server, share = server_share.split(':', 1)
                    else:
                        server = server_share
                        share = '/'
                    
                    mount_info = {
                        'protocol': 'NFS',
                        'server': server,
                        'share': share,
                        'mountpoint': mount_point,
                        'mounted': True
                    }
                
                # Add the mount if we found one
                if mount_info:
                    mounted_drives.append(mount_info)
                    
        elif is_linux():
            # On Linux, check both mount command and /proc/mounts
            output = subprocess.check_output(['mount']).decode('utf-8')
            
            # Add debug output to see what we're working with
            print("DEBUG: Mount output:")
            for line in output.splitlines():
                if "cifs" in line or "nfs" in line or "smb" in line:
                    print(f"DEBUG: Found network mount: {line}")
            
            # Look for cifs (SMB), nfs mounts with more flexible parsing
            for line in output.splitlines():
                mount_info = {}
                
                # More flexible check for SMB/CIFS mounts
                if 'type cifs' in line or 'cifs,' in line or 'smb' in line:
                    try:
                        # Try to extract source and mountpoint with more flexible parsing
                        parts = line.split(' on ' if ' on ' in line else ' ')
                        source = parts[0]
                        # Get mount point (different format handling)
                        if ' on ' in line:
                            mount_point = line.split(' on ')[1].split(' ')[0]
                        else:
                            # Try to find the mount point in the parts
                            mount_point = None
                            for i, part in enumerate(parts):
                                if part == 'on' and i+1 < len(parts):
                                    mount_point = parts[i+1]
                                    break
                            
                            # If we still couldn't find it, try a different approach
                            if not mount_point:
                                mount_point = parts[2]
                        
                        # Parse server and share from something like //server/share
                        if '//' in source:
                            server_share = source.split('//')[1]
                            if '/' in server_share:
                                server = server_share.split('/')[0]
                                share = '/'.join(server_share.split('/')[1:])
                            else:
                                server = server_share
                                share = '/'
                            
                            mount_info = {
                                'protocol': 'SMB',
                                'server': server,
                                'share': share,
                                'mountpoint': mount_point,
                                'mounted': True
                            }
                    except Exception as e:
                        print(f"DEBUG: Error parsing SMB mount: {e} | Line: {line}")
                
                # More flexible check for NFS mounts
                elif 'type nfs' in line or 'nfs,' in line or 'nfs4' in line:
                    try:
                        # Try to extract source and mountpoint with more flexible parsing
                        parts = line.split(' on ' if ' on ' in line else ' ')
                        source = parts[0]
                        # Get mount point (different format handling)
                        if ' on ' in line:
                            mount_point = line.split(' on ')[1].split(' ')[0]
                        else:
                            # Try to find the mount point in the parts
                            mount_point = None
                            for i, part in enumerate(parts):
                                if part == 'on' and i+1 < len(parts):
                                    mount_point = parts[i+1]
                                    break
                            
                            # If we still couldn't find it, try a different approach
                            if not mount_point:
                                mount_point = parts[2]
                        
                        # Parse server and share from something like server:/share
                        if ':' in source:
                            server, share = source.split(':', 1)
                        else:
                            server = source
                            share = '/'
                        
                        mount_info = {
                            'protocol': 'NFS',
                            'server': server,
                            'share': share,
                            'mountpoint': mount_point,
                            'mounted': True
                        }
                    except Exception as e:
                        print(f"DEBUG: Error parsing NFS mount: {e} | Line: {line}")
                
                # Add the mount if we found one
                if mount_info:
                    mounted_drives.append(mount_info)
                    print(f"DEBUG: Added mounted drive: {mount_info}")
            
            # If we didn't find any mounts, try checking /proc/mounts directly
            if not mounted_drives:
                try:
                    with open('/proc/mounts', 'r') as f:
                        mounts_content = f.read()
                    
                    print("DEBUG: /proc/mounts content for network shares:")
                    for line in mounts_content.splitlines():
                        if "cifs" in line or "nfs" in line:
                            print(f"DEBUG: {line}")
                    
                    for line in mounts_content.splitlines():
                        if "cifs" in line:
                            parts = line.split()
                            source = parts[0]
                            mount_point = parts[1]
                            
                            # Check for SMB/CIFS format
                            if '//' in source:
                                server_share = source.split('//')[1]
                                if '/' in server_share:
                                    server = server_share.split('/')[0]
                                    share = '/'.join(server_share.split('/')[1:])
                                else:
                                    server = server_share
                                    share = '/'
                                
                                mounted_drives.append({
                                    'protocol': 'SMB',
                                    'server': server,
                                    'share': share,
                                    'mountpoint': mount_point,
                                    'mounted': True
                                })
                                print(f"DEBUG: Added SMB mount from /proc/mounts: {server}:{share}")
                        
                        elif "nfs" in line:
                            parts = line.split()
                            source = parts[0]
                            mount_point = parts[1]
                            
                            # Check for NFS format
                            if ':' in source:
                                server, share = source.split(':', 1)
                            else:
                                server = source
                                share = '/'
                            
                            mounted_drives.append({
                                'protocol': 'NFS',
                                'server': server,
                                'share': share,
                                'mountpoint': mount_point,
                                'mounted': True
                            })
                            print(f"DEBUG: Added NFS mount from /proc/mounts: {server}:{share}")
                except Exception as e:
                    print(f"DEBUG: Error checking /proc/mounts: {e}")
    
    except Exception as e:
        logger.error(f"Error finding mounted drives: {e}")
        print(f"DEBUG: Exception in find_mounted_drives: {str(e)}")
    
    return mounted_drives

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
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging for name resolution')
                        
    args = parser.parse_args()
    
    # Enable debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        
    # Run the scan
    find_nas_drives(threads=args.threads, timeout=args.timeout, use_color=not args.no_color, sound_alert=args.sound) 