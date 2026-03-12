import scapy.all as scapy


IF1 = "enp0s8"
IF2 = "enp0s9"
ROUTING_TABLE = {
    "192.168.56": IF2
}
DEFAULT_GATEWAY = IF2


def get_dst_iface(packet: scapy.packet) -> str:
    for addr in ROUTING_TABLE:
        if addr in packet[scapy.IP].dst:
            return ROUTING_TABLE[addr]
    return DEFAULT_GATEWAY


def handle_packet(packet: scapy.packet) -> None:
    DST_IF = get_dst_iface(packet)
    packet[scapy.IP].ttl -= 1
    packet.src = scapy.get_if_hwaddr(DST_IF)
    scapy.sendp(packet, iface=DST_IF)


def main() -> None:
    scapy.sniff(iface=IF1, filter="ip and inbound", prn=handle_packet)


if __name__ == "__main__":
    main()