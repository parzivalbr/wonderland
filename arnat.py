import scapy.all as scapy


HOME_IFACE = "enp0s8"
NAT_IFACE = "enp0s9"
NAT_IP = scapy.get_if_addr(NAT_IFACE)
NAT_MAC = scapy.get_if_hwaddr(NAT_IFACE)
HOME_IF_MAC = scapy.get_if_hwaddr(HOME_IFACE)
ROUTING_TABLE = {
    "192.168.56": NAT_IFACE
}
DEFAULT_GATEWAY = NAT_IFACE
CONNECTIONS = []


class Connection:
    current_port = 1
    def __init__(self, packet: scapy.packet):
        self.HOME_IP = packet[scapy.IP].src
        self.ICMP_CONNECTION = False
        if scapy.ICMP in packet:
            self.ICMP_CONNECTION = True
            self.SEQ_NUM = packet[scapy.ICMP].seq
        else:
            self.HOME_PORT = packet.sport
            self.NAT_PORT = Connection.current_port
            Connection.current_port += 1
        self.check_packet(packet)

    def check_packet(self, packet: scapy.packet) -> bool:
        """
        check packet type and direction
        """
        if scapy.ICMP in packet:
            return self.icmp_handler(packet)
        if self.ICMP_CONNECTION:
            return
        if packet.sniffed_on == NAT_IFACE and packet.dport == self.NAT_PORT:
            return self.nat_to_home(packet)
        elif packet.sport == self.HOME_PORT and packet[scapy.IP].src == self.HOME_IP:
            return self.home_to_nat(packet)
        else:
            return False
    
    def icmp_handler(self, packet: scapy.packet) -> bool:
        """
        handle icmp packets for icmp connections
        """
        if not self.ICMP_CONNECTION:
            return
        if packet.sniffed_on == NAT_IFACE and self.SEQ_NUM == packet[scapy.ICMP].seq:
            packet[scapy.IP].dst = self.HOME_IP
            packet.src = HOME_IF_MAC
            packet[scapy.IP].ttl -= 1
            scapy.sendp(packet, iface=HOME_IFACE)
            self.SEQ_NUM += 1
            return True
        elif packet.sniffed_on == HOME_IFACE and packet[scapy.ICMP].seq == self.SEQ_NUM:
            packet[scapy.IP].src = NAT_IP
            packet.src = NAT_MAC
            packet[scapy.IP].ttl -= 1
            scapy.sendp(packet, iface=NAT_IFACE)
            return True
        else:
            return False

    def nat_to_home(self, packet: scapy.packet) -> bool:
        packet[scapy.IP].dst = self.HOME_IP
        packet.dport = self.HOME_PORT
        packet.src = HOME_IF_MAC
        packet[scapy.IP].ttl -= 1
        scapy.sendp(packet, iface=HOME_IFACE)
        return True
    
    def home_to_nat(self, packet: scapy.packet) -> bool:
        packet.src = NAT_MAC
        packet[scapy.IP].ttl -= 1
        packet[scapy.IP].src = NAT_IP
        packet.sport = self.NAT_PORT
        scapy.sendp(packet, iface=NAT_IFACE)
        return True


def get_dst_iface(packet: scapy.packet) -> str:
    for addr in ROUTING_TABLE:
        if addr in packet[scapy.IP].dst:
            return ROUTING_TABLE[addr]
    return DEFAULT_GATEWAY


def handle_packet(packet: scapy.packet) -> None:
    DST_IF = get_dst_iface(packet)
    if packet.sniffed_on == NAT_IFACE and packet[scapy.IP].dst != NAT_IP:
        return
    in_connection = False
    for connection in CONNECTIONS:
        if connection.check_packet(packet):
            in_connection = True
    if not in_connection and DST_IF == NAT_IFACE and not packet.sniffed_on == NAT_IFACE:
        CONNECTIONS.append(Connection(packet))


def main() -> None:
    scapy.sniff(iface=[HOME_IFACE, NAT_IFACE], filter="ip and (udp or tcp or icmp) and inbound", prn=handle_packet)


if __name__ == "__main__":
    main()