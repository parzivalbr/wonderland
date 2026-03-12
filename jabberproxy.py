import scapy.all as scapy


HOME_IFACE = "enp0s8"
PROXY_IFACE = "enp0s9"
HOME_IP = "192.168.56.1"
HOME_MAC = "0a:00:27:00:00:2e"
ROUTING_TABLE = {
    "192.168.56": PROXY_IFACE
}
DEFAULT_GATEWAY = PROXY_IFACE



def get_dst_iface(packet: scapy.packet) -> str:
    for addr in ROUTING_TABLE:
        if addr in packet[scapy.IP].dst:
            return ROUTING_TABLE[addr]
    return DEFAULT_GATEWAY


def handle_packet(packet: scapy.packet) -> None:
    if packet.sniffed_on == HOME_IFACE and packet[scapy.IP].src == HOME_IP:
        DST_IF = get_dst_iface(packet)
        packet[scapy.IP].ttl -= 1
        packet.src = scapy.get_if_hwaddr(DST_IF)
        packet[scapy.IP].src = scapy.get_if_addr(DST_IF)
        scapy.sendp(packet, iface=DST_IF)
    elif packet.sniffed_on == PROXY_IFACE and packet[scapy.IP].dst == scapy.get_if_addr(PROXY_IFACE):
        packet.dst = HOME_MAC
        packet[scapy.IP].ttl -= 1
        packet[scapy.IP].dst = HOME_IP
        scapy.sendp(packet, iface=HOME_IFACE)


def main() -> None:
    scapy.sniff(iface=[HOME_IFACE, PROXY_IFACE], filter="ip and inbound", prn=handle_packet)


if __name__ == "__main__":
    main()