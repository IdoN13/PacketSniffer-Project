from datetime import datetime

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP

from models import PacketSummary


def parse_packet(packet) -> PacketSummary:
    seen_at = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S")
    packet_len = len(packet)

    if packet.haslayer(IP):
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            return PacketSummary(seen_at, src_ip, dst_ip, "TCP", tcp.sport, tcp.dport, packet_len, tcp_flags(tcp))

        if packet.haslayer(UDP):
            udp = packet[UDP]
            return PacketSummary(seen_at, src_ip, dst_ip, "UDP", udp.sport, udp.dport, packet_len)

        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            return PacketSummary(seen_at, src_ip, dst_ip, "ICMP", None, None, packet_len, f"type={icmp.type} code={icmp.code}")

        return PacketSummary(seen_at, src_ip, dst_ip, "IP", None, None, packet_len)

    if packet.haslayer(ARP):
        arp = packet[ARP]
        return PacketSummary(seen_at, arp.psrc, arp.pdst, "ARP", None, None, packet_len, f"op={arp.op}")

    return PacketSummary(seen_at, None, None, packet.__class__.__name__, None, None, packet_len)


def tcp_flags(tcp) -> str:
    flags = []
    if tcp.flags.S:
        flags.append("SYN")
    if tcp.flags.A:
        flags.append("ACK")
    if tcp.flags.F:
        flags.append("FIN")
    if tcp.flags.R:
        flags.append("RST")
    if tcp.flags.P:
        flags.append("PSH")
    return ",".join(flags)
