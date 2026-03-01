import scapy.all as scapy


IF1 = "enp0s8"
IF2 = "enp0s9"


def create_socket(iface_to_sock: str):
    return scapy.conf.L2socket(iface = iface_to_sock)


def main() -> None:
    s1 = create_socket(IF1)
    s2 = create_socket(IF2)
    while(True):
        packet = s1.recv()
        if packet:
            s2.send(packet)


if __name__ == "__main__":
    main()