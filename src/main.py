import argparse
import sys

from capture import capture_live, list_interfaces, read_pcap
from filters import PacketFilter
from output import print_table, save_csv
from parser import parse_packet
from stats import PacketStats


def main():
    args = parse_args()

    if args.interfaces:
        for interface in list_interfaces():
            print(interface)
        return 0

    if not args.live and not args.pcap:
        print("choose --interfaces, --live, or --pcap")
        return 1

    try:
        raw_packets = capture_live(args.interface, args.count) if args.live else read_pcap(args.pcap)
    except PermissionError:
        print("capture failed: live capture may require administrator/root permissions")
        return 1
    except Exception as exc:
        print(f"capture failed: {exc}")
        return 1

    active_filter = PacketFilter(args.protocol, args.src, args.dst, args.port)
    shown_packets = []
    stats = PacketStats()

    for packet in raw_packets:
        summary = parse_packet(packet)
        if active_filter.matches(summary):
            shown_packets.append(summary)
            stats.add(summary)

    print_table(shown_packets, args.verbose)
    print()
    print(stats.render())

    if args.save:
        save_csv(args.save, shown_packets)
        print(f"saved {len(shown_packets)} packet summaries to {args.save}")

    return 0


def parse_args():
    parser = argparse.ArgumentParser(description="Small local packet sniffer and pcap reader")
    parser.add_argument("--interfaces", action="store_true", help="list capture interfaces")
    parser.add_argument("--live", action="store_true", help="capture live packets")
    parser.add_argument("--interface", help="network interface for live capture")
    parser.add_argument("--pcap", help="read packets from a pcap file")
    parser.add_argument("--count", type=int, default=20, help="number of live packets to capture")
    parser.add_argument("--protocol", choices=["tcp", "udp", "icmp", "arp", "ip"], help="filter by protocol")
    parser.add_argument("--src", help="filter by source IP")
    parser.add_argument("--dst", help="filter by destination IP")
    parser.add_argument("--port", type=int, help="filter by source or destination port")
    parser.add_argument("--verbose", action="store_true", help="show extra packet details when available")
    parser.add_argument("--save", help="save packet summaries to CSV")
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(main())
