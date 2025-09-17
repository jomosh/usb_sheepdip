import os
import hashlib
import time
import json
import requests
from pathlib import Path
import psutil
import threading
import sys

class USBVirusScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.vt_url = "https://www.virustotal.com/api/v3/files/"
        self.headers = {
            "x-apikey": api_key,
            "Content-Type": "application/json"
        }
        self.current_usb = None
        
    def wait_for_usb_insertion(self):
        """Wait for a USB device to be inserted"""
        print("Waiting for USB device insertion...")
        
        initial_drives = self.get_removable_drives()
        
        while True:
            current_drives = self.get_removable_drives()
            new_drives = [d for d in current_drives if d not in initial_drives]
            
            if new_drives:
                self.current_usb = new_drives[0]
                print(f"USB device detected: {self.current_usb}")
                return True
            
            time.sleep(2)
    
    def get_removable_drives(self):
        """Get list of removable drives"""
        removable_drives = []
        for partition in psutil.disk_partitions():
            if 'removable' in partition.opts or self.is_usb_drive(partition.device):
                removable_drives.append(partition.mountpoint)
        return removable_drives
    
    def is_usb_drive(self, device_path):
        """Check if device is likely a USB drive"""
        # This is a simple heuristic - you might need to adjust for your OS
        if sys.platform == "win32":
            return "USB" in device_path.upper()
        else:
            return "sd" in device_path.lower() and len(device_path) <= 5
    
    def ask_confirmation(self):
        """Ask user for confirmation to scan"""
        print(f"\nUSB device detected at: {self.current_usb}")
        response = input("Do you want to scan this USB device for viruses? (yes/no): ")
        return response.lower() in ['yes', 'y', '1']
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Read file in chunks to handle large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (IOError, OSError, PermissionError):
            return None
    
    def get_all_file_hashes(self):
        """Get SHA256 hashes for all files on the USB drive"""
        file_hashes = {}
        total_files = 0
        processed_files = 0
        
        print(f"\nScanning files on {self.current_usb}...")
        
        # First count total files
        for root, dirs, files in os.walk(self.current_usb):
            total_files += len(files)
        
        for root, dirs, files in os.walk(self.current_usb):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    if os.path.isfile(file_path):
                        file_hash = self.calculate_file_hash(file_path)
                        if file_hash:
                            file_hashes[file_path] = file_hash
                        processed_files += 1
                        
                        # Show progress
                        if processed_files % 10 == 0:
                            progress = (processed_files / total_files) * 100
                            print(f"Progress: {progress:.1f}% ({processed_files}/{total_files} files)")
                            
                except (OSError, PermissionError):
                    continue
        
        print(f"Collected {len(file_hashes)} file hashes")
        return file_hashes
    
    def check_virustotal(self, file_hash):
        """Check file hash against VirusTotal"""
        try:
            response = requests.get(f"{self.vt_url}{file_hash}", headers=self.headers)
            
            if response.status_code == 200:
                result = response.json()
                return result
            elif response.status_code == 404:
                # File not found in VirusTotal database
                return {"found": False}
            else:
                print(f"Error checking hash {file_hash}: {response.status_code}")
                return None
                
        except requests.RequestException as e:
            print(f"Network error: {e}")
            return None
    
    def is_file_malicious(self, vt_report):
        """Check if file is malicious based on VirusTotal report"""
        if not vt_report or "data" not in vt_report:
            return False
            
        attributes = vt_report["data"].get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        # Consider file malicious if more than 1 engine detects it
        malicious_count = stats.get("malicious", 0)
        return malicious_count > 1
    
    def remove_infected_file(self, file_path):
        """Safely remove infected file"""
        try:
            os.remove(file_path)
            print(f"Removed infected file: {file_path}")
            return True
        except (OSError, PermissionError) as e:
            print(f"Could not remove file {file_path}: {e}")
            return False
    
    def scan_usb(self):
        """Main scanning procedure"""
        # Get all file hashes
        file_hashes = self.get_all_file_hashes()
        
        if not file_hashes:
            print("No files found or accessible on the USB drive")
            return
        
        infected_files = []
        clean_files = 0
        unknown_files = 0
        
        print("\nChecking files against VirusTotal...")
        
        # Check each file against VirusTotal
        for i, (file_path, file_hash) in enumerate(file_hashes.items()):
            print(f"Checking file {i+1}/{len(file_hashes)}: {os.path.basename(file_path)}")
            
            vt_report = self.check_virustotal(file_hash)
            
            if vt_report and "data" in vt_report:
                if self.is_file_malicious(vt_report):
                    print(f"INFECTED: {file_path}")
                    infected_files.append(file_path)
                else:
                    clean_files += 1
            else:
                unknown_files += 1
            
            # Be respectful of API rate limits
            time.sleep(0.2)
        
        # Handle infected files
        if infected_files:
            print(f"\nFound {len(infected_files)} infected files!")
            print("Removing infected files...")
            
            removed_count = 0
            for file_path in infected_files:
                if self.remove_infected_file(file_path):
                    removed_count += 1
            
            print(f"\nRemoved {removed_count} infected files")
            print("Please check your system with a full antivirus scan!")
            
        else:
            print(f"\nAll files are clean!")
            print(f"Clean files: {clean_files}")
            print(f"Unknown files (not in VirusTotal): {unknown_files}")
            print("\nYou can safely remove the USB drive")
    
    def run(self):
        """Main execution loop"""
        try:
            while True:
                if self.wait_for_usb_insertion():
                    if self.ask_confirmation():
                        self.scan_usb()
                    else:
                        print("Scan cancelled by user.")
                
                # Reset for next USB
                self.current_usb = None
                print("\n" + "="*50)
                print("Waiting for next USB device...")
                print("="*50 + "\n")
                
        except KeyboardInterrupt:
            print("\nScanner stopped by user")
        except Exception as e:
            print(f"Unexpected error: {e}")

def main():
    # Replace with your actual VirusTotal API key
    API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
    
    if API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        print("Please replace 'YOUR_VIRUSTOTAL_API_KEY_HERE' with your actual VirusTotal API key")
        print("You can get an API key from: https://www.virustotal.com/gui/join-us")
        return
    
    print("USB Virus Scanner")
    print("=================")
    print("This program will:")
    print("1. Wait for USB insertion")
    print("2. Ask for confirmation to scan")
    print("3. Scan all files on the USB")
    print("4. Check files against VirusTotal")
    print("5. Remove any infected files found")
    print("6. Notify you when safe to remove USB")
    print("\nPress Ctrl+C to stop the scanner\n")
    
    scanner = USBVirusScanner(API_KEY)
    scanner.run()

if __name__ == "__main__":
    # Install required packages if not already installed
    try:
        import psutil
        import requests
    except ImportError:
        print("Installing required packages...")
        os.system("pip install psutil requests")
        import psutil
        import requests
    
    main()
