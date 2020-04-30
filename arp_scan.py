from scapy.layers.l2 import ARP, Ether, srp


def send_packets(packet):
    """
    Sends the packet using srp from Scapy.
    :param packet: Packet to be sent
    :return: A dictionary of results key:value = (sent:received)
    """
    # Send the packets
    result = srp(packet, timeout=3, verbose=0)[0]

    return result


def print_hosts(results):
    """
    Prints the hosts that responded to packet sent in send_packets
    :param results: Dictionary containing the hosts
    :return: None
    """
    clients = []

    for sent, received in results:
        # for each response, saved IP and MAC addresses to the clients dictionary. (IP:MAC)
        clients.append({"ip": received.psrc, "mac": received.hwsrc})

    # Print clients
    print("Available clients in the network:")
    print("IP" + " " * 18 + "MAC")  # Spaces are purely cosmetic
    for client in clients:
        print("{:16} {}".format(client["ip"], client["mac"]))


class Scanner:

    def __init__(self, ip_range):
        self.ip_range = ip_range

    def create_packet(self):
        """
        Create an ARP packet to be sent to the target IP range.
        :return: stacked ARP packet
        """

        # Create ARP packet
        arp = ARP(pdst=self.ip_range)

        # Create the Ether bcast packet
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")

        # Stack them to create a single packet
        packet = ether / arp

        return packet

    def scanner_main(self):
        # Create packet
        packet = self.create_packet()

        # Send packet
        result = send_packets(packet)

        # Print clients
        print_hosts(result)
