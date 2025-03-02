#!/usr/bin/env python3
"""
Quick test script to check the find_mounted_drives function
"""

from find_nas import find_mounted_drives

if __name__ == "__main__":
    print("Testing mounted drive detection...")
    mounted_drives = find_mounted_drives()
    
    if mounted_drives:
        print(f"\nFound {len(mounted_drives)} mounted network drive(s):")
        for drive in mounted_drives:
            print(f"\nProtocol: {drive['protocol']}")
            print(f"Server:   {drive['server']}")
            print(f"Share:    {drive['share']}")
            print(f"Mounted:  {drive['mountpoint']}")
    else:
        print("\nNo mounted network drives found.") 