from models import PacketSummary


class PacketFilter:
    def __init__(self, protocol=None, src=None, dst=None, port=None):
        self.protocol = protocol.upper() if protocol else None
        self.src = src
        self.dst = dst
        self.port = port

    def matches(self, packet: PacketSummary) -> bool:
        if self.protocol and packet.protocol.upper() != self.protocol:
            return False
        if self.src and packet.src_ip != self.src:
            return False
        if self.dst and packet.dst_ip != self.dst:
            return False
        if self.port is not None and packet.src_port != self.port and packet.dst_port != self.port:
            return False
        return True
