from colorama import Fore, init
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
from scapy.packet import Raw
from scapy.sendrecv import sniff

# Initialize colorama for pretty outputs with color!!
init(
    autoreset=True)  # Every print statement will have it's own color. In other words it resets color after every print.

# Define colors for colorama
GREEN = Fore.GREEN
RED = Fore.RED
BLUE = Fore.BLUE
CYAN = Fore.CYAN
YELLOW = Fore.YELLOW

sniff_forms = False


def process_packet(packet):
    """
    Processes the sniffed packet. Executed whenever a packet is sniffed.
    :param packet: Packet that was sniffed
    """
    if packet.haslayer(HTTPRequest):
        # If this packet is a HTTP Request
        # Get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()

        # Get the requester IP address ie. victim
        ip = packet[IP].src

        # Get the request method
        method = packet[HTTPRequest].Method.decode()

        # Print some information
        print(GREEN + "{} -> {}: {}".format(ip, method, url))

        if sniff_forms and packet.haslayer(Raw) and method == "POST":
            # If Sniff forms? is answered YES sniff POST request and print the raw packet data.
            print(RED + "[*] Possible form submission detected: {}".format(packet[Raw].load))


def sniff_packets(iface=None):
    """
    Sniff HTTP packets using the given interface. If no interface is given use Scapy default interface.
    :param iface: Interface top sniff on
    """
    if iface:
        # Port 80 is for HTTP
        # process_packet is the callback
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
    else:
        # Sniff using the default interface
        sniff(filter="port 80", prn=process_packet, store=False)


def sniffer_main():
    # Look out for POST request?
    will_sniff = input(BLUE + "Would you like to sniff possible form submissions? y/n: ")
    if will_sniff.lower() == "y" or will_sniff.lower() == "yes":
        global sniff_forms
        sniff_forms = True

    interface = input(BLUE + "Which interface would you like to use? Leave blank for default.: ")

    print(CYAN + "Sniffer started...")
    print(CYAN + "Sniffing...")

    if interface == "":
        sniff_packets()
    else:
        sniff_packets(iface=interface)
