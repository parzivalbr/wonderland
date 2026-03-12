import scapy.all as scapy


HOME_IFACE = "enp0s8"
PROXY_IFACE = "enp0s9"
PROXY_SUBNET = "192.168.56"
PROXY_MAC = "08:00:27:f2:2c:d3"
HOME_IP = "192.168.56.1"
HOME_MAC = "0a:00:27:00:00:2e"
PROXY_IP = "192.168.29.5"


def handle_packet(packet: scapy.packet) -> None:
    if packet.sniffed_on == HOME_IFACE and packet[scapy.IP].src == HOME_IP and PROXY_SUBNET in packet[scapy.IP].dst:
        packet.src = PROXY_MAC
        packet[scapy.IP].ttl -= 1
        packet[scapy.IP].src = PROXY_IP
        scapy.sendp(packet, iface=PROXY_IFACE)
    elif packet.sniffed_on == PROXY_IFACE and packet[scapy.IP].dst == PROXY_IP:
        packet.dst = HOME_MAC
        packet[scapy.IP].ttl -= 1
        packet[scapy.IP].dst = HOME_IP
        scapy.sendp(packet, iface=HOME_IFACE)


def main() -> None:
    scapy.sniff(iface=[HOME_IFACE, PROXY_IFACE], filter="ip and inbound", prn=handle_packet)


if __name__ == "__main__":
    main()