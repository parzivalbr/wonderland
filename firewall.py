import scapy.all as scapy


RULES_FILE = "rules.txt"


def check_udp(packet: scapy.packet) -> bool:
    return packet.haslayer(scapy.UDP)

def check_tcp(packet: scapy.packet) -> bool:
    return packet.haslayer(scapy.TCP)

def check_icmp(packet: scapy.packet) -> bool:
    return packet.haslayer(scapy.ICMP)

def check_sport(sport, packet: scapy.packet) -> bool:
    return not packet.haslayer(scapy.ICMP) and packet.sport == sport

def check_dport(dport, packet: scapy.packet) -> bool:
    return not packet.haslayer(scapy.ICMP) and packet.dport == dport

def check_src_ip(src_ip, packet: scapy.packet) -> bool:
    return packet[scapy.IP].src == src_ip

def check_dst_ip(dst_ip, packet: scapy.packet) -> bool:
    return packet[scapy.IP].dst == dst_ip

def check_dst_mac(dst_mac, packet: scapy.packet) -> bool:
    return packet.dst == dst_mac

def check_src_mac(src_mac, packet: scapy.packet) -> bool:
    return packet.src == src_mac


firewall_to_scapy = {
    "udp": check_udp,
    "tcp": check_tcp,
    "icmp": check_icmp,
    "sport": check_sport,
    "dport": check_dport,
    "src_ip": check_src_ip,
    "dst_ip": check_dst_ip,
    "src_mac": check_src_mac,
    "dst_mac": check_dst_mac
}


def check_packet_FW(packet: scapy.packet) -> bool:
    with open(RULES_FILE, 'r') as f:
        for rule in f:
            if check_rule(packet, rule):
                return True
    return False


def check_rule(packet: scapy.packet, rule: str) -> bool:
    attrs = rule.split()
    current_index = 0
    try:
        if attrs[current_index] == "prot":
            current_index += 1
            if firewall_to_scapy[attrs[current_index]](packet):
                return True
            current_index += 1
        while current_index != len(attrs):
            if firewall_to_scapy[attrs[current_index]](attrs[current_index + 1], packet):
                return True
            current_index += 2
    except IndexError or KeyError:
        print("rule not valid")
    return False
    