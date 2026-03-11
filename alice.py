import scapy.all as scapy


IF1 = "enp0s8"
IF2 = "enp0s9"
IFACE2_SUBNET = "192.168.56"
IF2_MAC_ADDR = "08:00:27:f2:2c:d3"
IP_MAC = {
    "192.168.56.1": "0A:00:27:00:00:19"
}

def handle_packet(packet: scapy.packet) -> None:
    if IFACE2_SUBNET in packet[scapy.IP].dst:
        packet[scapy.IP].ttl -= 1
        packet.src = IF2_MAC_ADDR
        if packet[scapy.IP].dst in IP_MAC:
            packet.dst = IP_MAC[packet[scapy.IP].dst]
        else:
            packet.dst = "ff:ff:ff:ff:ff:ff"
        scapy.sendp(packet, iface=IF2)


def main() -> None:
    scapy.sniff(iface=IF1, filter="ip and inbound", prn=handle_packet)


if __name__ == "__main__":
    main()