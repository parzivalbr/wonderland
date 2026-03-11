import scapy.all as scapy


IF1 = "enp0s8"
IF2 = "enp0s9"
IFACE2_SUBNET = "192.168.56"
IF2_MAC_ADDR = "08:00:27:f2:2c:d3"


def handle_packet(packet: scapy.packet) -> None:
    if IFACE2_SUBNET in packet[scapy.IP].dst:
        packet[scapy.IP].ttl -= 1
        packet.src = IF2_MAC_ADDR
        scapy.sendp(packet, iface=IF2)


def main() -> None:
    scapy.sniff(iface=IF1, filter="ip and inbound", prn=handle_packet)


if __name__ == "__main__":
    main()