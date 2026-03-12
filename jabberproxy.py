import scapy.all as scapy


HOME_IFACE = "enp0s8"
PROXY_IFACE = "enp0s9"
HOME_IP_ADDR = "192.168.56.1"
HOME_MAC_ADDR = "0a:00:27:00:00:2e"
PROXY_IP_ADDR = "192.168.29.5"
PROXY_MAC_ADDR = "22:88:22:09:33:09"


def handle_packet(packet: scapy.packet) -> None:
    if packet[scapy.IP].src == HOME_IP_ADDR:
        packet.src = PROXY_MAC_ADDR
        packet[scapy.IP].src = PROXY_IP_ADDR
        print(packet)
        scapy.sendp(packet, iface=PROXY_IFACE)
        return
    elif packet[scapy.IP].src == PROXY_IP_ADDR:
        packet.src = HOME_MAC_ADDR
        packet[scapy.IP].src = HOME_IP_ADDR
        scapy.sendp(packet, iface=HOME_IFACE)


def main() -> None:
    scapy.sniff(iface=[HOME_IFACE, PROXY_IFACE], filter="ip and inbound", prn=handle_packet)


if __name__ == "__main__":
    main()