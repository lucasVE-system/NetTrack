import json
import os
import struct
import tempfile
import unittest

import dns_sniffer
from dns_sniffer import DNSSniffer, _categorise, _parse_dns_query


def _build_dns_query(domain, flags=0x0100, qdcount=1):
    """Build a minimal DNS query payload (UDP payload only)."""
    header = struct.pack("!HHHHHH", 0x1234, flags, qdcount, 0, 0, 0)
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)  # A, IN


class ParseDnsQueryTests(unittest.TestCase):
    def test_parses_standard_query(self):
        self.assertEqual(
            _parse_dns_query(_build_dns_query("www.example.com")),
            "www.example.com")

    def test_rejects_response_packets(self):
        # QR=1 means response, not query
        self.assertIsNone(
            _parse_dns_query(_build_dns_query("www.example.com", flags=0x8180)))

    def test_rejects_zero_question_count(self):
        self.assertIsNone(
            _parse_dns_query(_build_dns_query("www.example.com", qdcount=0)))

    def test_rejects_short_packet(self):
        self.assertIsNone(_parse_dns_query(b"\x00\x01"))

    def test_rejects_single_label(self):
        self.assertIsNone(_parse_dns_query(_build_dns_query("localhost")))


class CategoriseTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertEqual(_categorise("netflix.com"), "Streaming")

    def test_subdomain_suffix_match(self):
        self.assertEqual(_categorise("api.netflix.com"), "Streaming")

    def test_longest_suffix_wins(self):
        # graph.facebook.com is Tracking even though facebook.com is Social
        self.assertEqual(_categorise("graph.facebook.com"), "Tracking")
        self.assertEqual(_categorise("www.facebook.com"), "Social")

    def test_unknown_returns_empty(self):
        self.assertEqual(_categorise("example.org"), "")

    def test_handles_trailing_dot_and_case(self):
        self.assertEqual(_categorise("NETFLIX.COM."), "Streaming")


class DnsSnifferLogTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.sniffer = DNSSniffer(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_record_and_get_log(self):
        self.sniffer._record("192.168.1.10", "www.netflix.com")
        self.sniffer._record("192.168.1.11", "example.org")
        log = self.sniffer.get_log()
        self.assertEqual(len(log), 2)
        # Newest first
        self.assertEqual(log[0]["domain"], "example.org")

    def test_get_log_filters_by_ip(self):
        self.sniffer._record("192.168.1.10", "a.netflix.com")
        self.sniffer._record("192.168.1.11", "b.example.org")
        log = self.sniffer.get_log(ip="192.168.1.10")
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["ip"], "192.168.1.10")

    def test_stats_counts_categories(self):
        self.sniffer._record("192.168.1.10", "www.netflix.com")
        self.sniffer._record("192.168.1.10", "www.youtube.com")
        self.sniffer._record("192.168.1.10", "unknown.example")
        stats = self.sniffer.get_stats()
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["by_category"]["Streaming"], 2)
        self.assertEqual(stats["by_category"]["Other"], 1)

    def test_clear_single_ip(self):
        self.sniffer._record("192.168.1.10", "a.netflix.com")
        self.sniffer._record("192.168.1.11", "b.example.org")
        self.sniffer.clear(ip="192.168.1.10")
        self.assertEqual(self.sniffer.get_log(ip="192.168.1.10"), [])
        self.assertEqual(len(self.sniffer.get_log()), 1)

    def test_persistence_roundtrip(self):
        self.sniffer._record("192.168.1.10", "www.netflix.com")
        self.sniffer._flush()
        restored = DNSSniffer(self._tmp.name)
        log = restored.get_log()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["domain"], "www.netflix.com")

    def test_corrupt_log_file_is_ignored(self):
        path = os.path.join(self._tmp.name, "dns_log.json")
        with open(path, "w") as f:
            f.write("{not valid json")
        restored = DNSSniffer(self._tmp.name)
        self.assertEqual(restored.get_log(), [])


if __name__ == "__main__":
    unittest.main()
