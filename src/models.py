from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PacketSummary:
    timestamp: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    info: str = ""
