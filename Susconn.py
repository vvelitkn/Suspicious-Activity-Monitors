import os
import sys
import time
import argparse
import psutil

# Parse the command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interval", type=int, default=5, help="interval at which to check for malicious activities (in seconds)")
parser.add_argument("-x", "--exclude", nargs="*", default=[], help="processes to exclude from the check for malicious activities")
args = parser.parse_args()

# Keep track of the number of times the code has checked for malicious activities

while True:
    # Get the list of currently running processes
    processes = psutil.process_iter()

    # Check each process for malicious behavior
    for proc in processes:
        try:
            # Check if the process is in the exclude list
            if proc.name() in args.exclude:
                continue

            # Check if the process is running from a suspicious location
            exe = proc.exe()
            if exe.startswith("C:\\Windows\\") or exe.startswith("C:\\Program Files\\") or exe.startswith("C:\\Program Files (x86)\\"):
                continue

            # Check if the process has any suspicious command line arguments
            cmdline = proc.cmdline()
            if cmdline:
                for arg in cmdline:
                    if "download" in arg or "update" in arg or "install" in arg:
                        print("Suspicious process detected:")
                        print("  PID:", proc.pid)
                        print("  Name:", proc.name())
                        print("  Command line:", " ".join(cmdline))
                        print()

            # Check if the process has any open network connections
            connections = proc.connections()
            if connections:
                for conn in connections:
                    if conn.status == "ESTABLISHED" and conn.raddr and ":" in conn.raddr[0]:
                        print("Suspicious network connection detected:")
                        print("  PID:", proc.pid)
                        print("  Name:", proc.name())
                        print("  Remote address:", conn.raddr)
                        print("  Remote port:", conn.rport)
                        print()

        except (psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # Sleep for 5 seconds before checking again
    time.sleep(args.interval)
