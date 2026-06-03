from collections import Counter


class PacketStats:
    def __init__(self):
        self.total = 0
        self.protocols = Counter()
        self.sources = Counter()
        self.destinations = Counter()
        self.ports = Counter()

    def add(self, packet):
        self.total += 1
        self.protocols[packet.protocol] += 1
        if packet.src_ip:
            self.sources[packet.src_ip] += 1
        if packet.dst_ip:
            self.destinations[packet.dst_ip] += 1
        if packet.src_port:
            self.ports[packet.src_port] += 1
        if packet.dst_port:
            self.ports[packet.dst_port] += 1

    def render(self) -> str:
        lines = [f"Total packets: {self.total}"]
        lines.append("Protocols: " + format_counter(self.protocols))
        lines.append("Top sources: " + format_counter(self.sources))
        lines.append("Top destinations: " + format_counter(self.destinations))
        lines.append("Common ports: " + format_counter(self.ports))
        return "\n".join(lines)


def format_counter(counter: Counter) -> str:
    if not counter:
        return "none"
    return ", ".join(f"{name}={amount}" for name, amount in counter.most_common(5))
