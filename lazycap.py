import argparse
import sys
import arp_scan
import arp_spoof
import capture

description = "LazyCap is a tool for a lazy man-in-the-middle attack. It start by scanning the local network for hosts." \
              "Then it starts an arp spoofing attack. Finally it captures http packets from the host. If installed, " \
              "sslstrip can be used to capture https requests as well."
parser = argparse.ArgumentParser(description=description)
args = parser.parse_args()


def main():
    print("Hello to the LazyCap. Let's get started!")
    ip_range = input("Target IP range to scan: ")
    scanner = arp_scan.Scanner(ip_range)
    scanner.scanner_main()
    return 1


if __name__ == '__main__':
    main()
