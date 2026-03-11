import scapy.all as scapy


IF1 = "enp0s8"
IF2 = "enp0s9"


def handle_packet(packet: scapy.packet) -> None:
    if packet.sniffed_on == IF1:
        scapy.sendp(packet, iface=IF2)
    else:
        scapy.sendp(packet, iface=IF1)


def main() -> None:
    scapy.sniff(iface=[IF2, IF1], filter="ip and inbound", prn=handle_packet)


if __name__ == "__main__":
    main()