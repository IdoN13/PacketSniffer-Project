import csv


def print_table(packets, verbose=False):
    headers = ["time", "protocol", "source", "destination", "sport", "dport", "length"]
    rows = []
    for packet in packets:
        rows.append([
            packet.timestamp,
            packet.protocol,
            packet.src_ip or "-",
            packet.dst_ip or "-",
            str(packet.src_port or "-"),
            str(packet.dst_port or "-"),
            str(packet.length),
        ])

    widths = [len(header) for header in headers]
    for row in rows:
        for i, value in enumerate(row):
            widths[i] = max(widths[i], len(value))

    print(format_row(headers, widths))
    print("-" * (sum(widths) + 3 * (len(widths) - 1)))
    for packet, row in zip(packets, rows):
        print(format_row(row, widths))
        if verbose and packet.info:
            print(f"  {packet.info}")


def format_row(row, widths):
    return " | ".join(value.ljust(widths[i]) for i, value in enumerate(row))


def save_csv(path, packets):
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "length", "info"])
        for packet in packets:
            writer.writerow([
                packet.timestamp,
                packet.src_ip,
                packet.dst_ip,
                packet.protocol,
                packet.src_port,
                packet.dst_port,
                packet.length,
                packet.info,
            ])
