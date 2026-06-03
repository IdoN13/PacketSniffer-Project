from scapy.all import get_if_list, rdpcap, sniff


def list_interfaces():
    return get_if_list()


def capture_live(interface=None, count=20):
    return sniff(iface=interface, count=count, store=True)


def read_pcap(path):
    return rdpcap(path)
