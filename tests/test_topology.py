import struct
import unittest

import topology as topo


class ValidIpTests(unittest.TestCase):
    def test_accepts_private_unicast(self):
        for ip in ("192.168.1.1", "10.0.0.5", "172.16.0.1"):
            self.assertTrue(topo._valid_ip(ip), ip)

    def test_rejects_malformed(self):
        for ip in ("", "abc", "1.2.3", "999.1.1.1", "1.2.3.4.5", "1.2.3.4 "):
            self.assertFalse(topo._valid_ip(ip), repr(ip))

    def test_rejects_multicast(self):
        self.assertFalse(topo._valid_ip("224.0.0.1"))


class SafeSubnetTests(unittest.TestCase):
    def test_accepts_three_octets(self):
        self.assertTrue(topo._safe_subnet("192.168.1"))

    def test_rejects_bad_formats(self):
        for s in ("192.168", "192.168.1.0", "a.b.c", "192.168.999", ""):
            self.assertFalse(topo._safe_subnet(s), repr(s))


class LldpParserTests(unittest.TestCase):
    @staticmethod
    def _tlv(tlv_type, value):
        header = (tlv_type << 9) | len(value)
        return struct.pack("!H", header) + value

    def _frame(self, *tlvs):
        eth = b"\x01\x80\xc2\x00\x00\x0e" + b"\xaa" * 6 + struct.pack("!H", 0x88CC)
        return eth + b"".join(tlvs) + self._tlv(0, b"")

    def test_parses_sysname_and_mgmt_ip(self):
        frame = self._frame(
            self._tlv(1, b"\x04" + bytes.fromhex("001122334455")),  # chassis: MAC
            self._tlv(5, b"core-switch"),
            self._tlv(8, b"\x05\x01" + bytes([192, 168, 1, 2]) + b"\x00"),
        )
        parsed = topo._parse_lldp_frame(frame)
        self.assertEqual(parsed["chassis_id"], "00:11:22:33:44:55")
        self.assertEqual(parsed["sys_name"], "core-switch")
        self.assertEqual(parsed["mgmt_ip"], "192.168.1.2")

    def test_ignores_non_lldp_ethertype(self):
        frame = b"\x00" * 12 + struct.pack("!H", 0x0800) + b"payload"
        self.assertEqual(topo._parse_lldp_frame(frame), {})

    def test_handles_truncated_frame(self):
        self.assertEqual(topo._parse_lldp_frame(b"\x01\x02"), {})


class InferDeviceTypeTests(unittest.TestCase):
    def test_router_by_vendor_keyword(self):
        self.assertEqual(
            topo.infer_device_type({"ip": "192.168.1.50", "vendor": "TP-Link"}),
            "router")

    def test_gateway_ip_heuristic(self):
        self.assertEqual(
            topo.infer_device_type({"ip": "192.168.1.1", "vendor": ""}),
            "router")

    def test_camera_by_rtsp_port(self):
        dev = {"ip": "192.168.1.30", "open_ports": [554]}
        self.assertEqual(topo.infer_device_type(dev), "camera")

    def test_printer_by_jetdirect_port(self):
        dev = {"ip": "192.168.1.31", "open_ports": [9100]}
        self.assertEqual(topo.infer_device_type(dev), "printer")

    def test_phone_by_dhcp_fingerprint(self):
        dev = {"ip": "192.168.1.32", "opt55_os": "Android"}
        self.assertEqual(topo.infer_device_type(dev), "phone")

    def test_unknown_defaults_to_other(self):
        self.assertEqual(topo.infer_device_type({"ip": "192.168.1.99"}), "other")


class FindGatewayTests(unittest.TestCase):
    def test_prefers_dot_one(self):
        node_map = {"192.168.1.50": {}, "192.168.1.1": {}, "192.168.1.254": {}}
        self.assertEqual(topo._find_gateway(node_map), "192.168.1.1")

    def test_falls_back_to_dot_254(self):
        node_map = {"192.168.1.50": {}, "192.168.1.254": {}}
        self.assertEqual(topo._find_gateway(node_map), "192.168.1.254")

    def test_falls_back_to_router_type(self):
        node_map = {"192.168.1.50": {}, "192.168.1.77": {"type": "router"}}
        self.assertEqual(topo._find_gateway(node_map), "192.168.1.77")

    def test_empty_map_returns_none(self):
        self.assertIsNone(topo._find_gateway({}))


class BuildTopologyGraphTests(unittest.TestCase):
    DEVICES = [
        {"ip": "192.168.1.1",  "mac": "AA:00:00:00:00:01", "vendor": "RouterCo", "hostname": "gw"},
        {"ip": "192.168.1.10", "mac": "AA:00:00:00:00:02", "vendor": "", "hostname": "pc-1"},
    ]

    def test_star_fallback_when_no_edges(self):
        graph = topo.build_topology_graph([dict(d) for d in self.DEVICES])
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(len(graph["edges"]), 1)
        edge = graph["edges"][0]
        self.assertEqual(edge["type"], "inferred_star")
        self.assertEqual(edge["src"], "192.168.1.1")

    def test_traceroute_edges_used_when_present(self):
        tr = {"edges": [{"src": "192.168.1.1", "dst": "192.168.1.10", "hop_index": 0}]}
        graph = topo.build_topology_graph(
            [dict(d) for d in self.DEVICES], traceroute_data=tr)
        types = {e["type"] for e in graph["edges"]}
        self.assertIn("l3_hop", types)
        self.assertNotIn("inferred_star", types)

    def test_dhcp_enrichment_matches_by_mac(self):
        dhcp = {"AA:00:00:00:00:02": {"hostname": "dhcp-name", "opt55_os": "Windows 10/11"}}
        graph = topo.build_topology_graph(
            [dict(d) for d in self.DEVICES], dhcp_data=dhcp)
        pc = next(n for n in graph["nodes"] if n["ip"] == "192.168.1.10")
        self.assertEqual(pc["opt55_os"], "Windows 10/11")

    def test_internal_fields_stripped_from_nodes(self):
        fp = {"192.168.1.10": {"open_ports": [80], "banners": {80: "secret-banner"}}}
        graph = topo.build_topology_graph(
            [dict(d) for d in self.DEVICES], fingerprint_data=fp)
        pc = next(n for n in graph["nodes"] if n["ip"] == "192.168.1.10")
        self.assertNotIn("banners", pc)
        self.assertEqual(pc["open_ports"], [80])

    def test_snmp_arp_adds_new_nodes(self):
        snmp = {"192.168.1.1": {
            "sysinfo": {"sysName": "gw"},
            "arp_table": {"192.168.1.200": "AA:00:00:00:00:99"},
            "lldp": [],
        }}
        graph = topo.build_topology_graph(
            [dict(d) for d in self.DEVICES], snmp_results=snmp)
        ips = {n["ip"] for n in graph["nodes"]}
        self.assertIn("192.168.1.200", ips)


if __name__ == "__main__":
    unittest.main()
