import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from filters import PacketFilter
from models import PacketSummary


def packet(protocol="TCP", src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80):
    return PacketSummary("now", src, dst, protocol, sport, dport, 60)


def test_protocol_filter_matches_case_insensitively():
    assert PacketFilter(protocol="tcp").matches(packet(protocol="TCP"))


def test_source_filter_rejects_other_sources():
    assert not PacketFilter(src="192.168.1.5").matches(packet(src="10.0.0.1"))


def test_port_filter_checks_both_sides():
    assert PacketFilter(port=80).matches(packet(sport=50000, dport=80))
    assert PacketFilter(port=443).matches(packet(sport=443, dport=50000))
