# Find NAS Drives

A Python utility to find and list Network Attached Storage (NAS) drives on your system.

## Features

- Detects mounted NAS drives (SMB, NFS, AFP)
- Scans your local network for potential NAS devices
- Shows detailed information about discovered NAS drives
- Multi-threaded network scanning for faster results
- Cross-platform support for macOS and Ubuntu/Linux
- Optimized scanning with smart host discovery
- Progressive display of discovered devices

## Requirements

- Python 3.6+
- Supported operating systems:
  - macOS
  - Ubuntu 16.04 or newer
  - Other Linux distributions (may work but not fully tested)

## Installation

1. Make sure you have Python installed.
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Simply run the script:

```bash
python find_nas.py
```

### Command-line Options

The script supports the following command-line options:

```
--threads NUMBER  Number of parallel scanning threads (default: 50)
--timeout SECONDS  Socket connection timeout in seconds (default: 0.2)
```

Example with custom options:

```bash
python find_nas.py --threads 100 --timeout 0.1
```

## How It Works

- **Platform Detection**: Automatically detects if you're running on macOS or Linux
- **Mounted NAS Detection**: Uses the appropriate commands for your OS to detect network filesystems
- **Smart Host Discovery**: Uses ARP scanning and heuristics to identify likely NAS devices
- **Prioritized Scanning**: Scans devices more likely to be NAS drives first
- **Optimized Port Checking**: Tests the most common NAS services first with early termination
- **Multi-threaded Scanning**: Uses parallel processing for fast network scanning
- **MAC Address Recognition**: Identifies devices from known NAS manufacturers

## Performance Optimizations

- **ARP Scanning**: Uses ARP tables to quickly identify active hosts (much faster than pinging)
- **NAS Heuristics**: Prioritizes scanning IP addresses likely to be NAS devices based on common patterns
- **Early Termination**: Stops port scanning once a device is clearly identified as a NAS
- **Reduced Timeouts**: Uses shorter connection timeouts (0.2s default vs 0.5s previously)
- **Increased Parallelism**: Uses more worker threads (50 by default vs 20 previously)
- **Vendor MAC Recognition**: Identifies known NAS manufacturers by MAC address prefix
- **Result Caching**: Caches network information to avoid redundant system calls

## Example Output

```
================================================================================
NAS Drives Found: 3
================================================================================

MOUNTED NAS DRIVES:
--------------------------------------------------------------------------------
1. Protocol: SMB
   Server:   nas.local
   Share:    Documents
   Mounted:  /Volumes/Documents

2. Protocol: NFS
   Server:   192.168.1.100
   Share:    /export/media
   Mounted:  /Volumes/Media

DISCOVERED NAS DEVICES (NOT MOUNTED):
--------------------------------------------------------------------------------
1. IP:       192.168.1.115
   Hostname: synology.local
   Services: SMB, NFS
```

## Limitations

- Only scans networks that your computer is directly connected to
- Limited to 254 hosts per network to prevent excessive scanning
- ARP scanning requires appropriate permissions, falling back to slower methods if unavailable
- Some optimizations may not be available on all systems

## OS-Specific Notes

### macOS
- Uses native commands like `route -n get default` and `ifconfig`
- Detects AFP shares in addition to SMB and NFS
- Uses the `arp -a` command for network discovery

### Ubuntu/Linux
- Uses commands like `ip` (modern Linux) with fallback to `route` and `ifconfig` (older Linux)
- Compatible with Ubuntu 16.04's networking stack
- Can use `arp-scan` for faster discovery if installed 