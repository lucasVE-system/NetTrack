import unittest
from unittest.mock import patch

import app as nettrack_app


class NetTrackApiTests(unittest.TestCase):
    def setUp(self):
        nettrack_app.app.config["TESTING"] = True
        self.client = nettrack_app.app.test_client()

    def test_scan_multi_rejects_bad_payload_type(self):
        resp = self.client.post("/scan-multi", json={"subnets": "192.168.1"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("subnets", resp.get_json()["error"])

    def test_scan_multi_handles_mixed_valid_invalid_subnets(self):
        with patch("app.scan_subnet_devices", return_value=[]):
            resp = self.client.post(
                "/scan-multi",
                json={"subnets": ["bad-subnet", "10.0.0", "10.0.0"]},
            )
        data = resp.get_json()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(data["subnets_requested"], ["bad-subnet", "10.0.0"])
        self.assertEqual(len(data["subnet_results"]), 2)
        self.assertTrue(data["subnet_results"][0]["errors"])

    def test_scan_multi_dedupes_by_mac_then_ip(self):
        def _scan(subnet, local_ip=""):
            if subnet == "10.0.0":
                return [
                    {"ip": "10.0.0.2", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "V1", "hostname": ""},
                    {"ip": "10.0.0.3", "mac": "", "vendor": "V2", "hostname": "host-a"},
                ]
            return [
                {"ip": "10.1.0.9", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "", "hostname": "core"},
                {"ip": "10.0.0.3", "mac": "", "vendor": "V2", "hostname": ""},
            ]

        with patch("app.scan_subnet_devices", side_effect=_scan):
            resp = self.client.post("/scan-multi", json={"subnets": ["10.0.0", "10.1.0"]})

        data = resp.get_json()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(data["count"], 2)
        by_mac = [d for d in data["devices"] if d.get("mac") == "AA:BB:CC:DD:EE:FF"]
        self.assertEqual(len(by_mac), 1)
        self.assertEqual(by_mac[0]["hostname"], "core")

    def test_save_all_rejects_invalid_ip(self):
        resp = self.client.post("/save-all", json=[{"ip": "999.1.1.1"}])
        self.assertEqual(resp.status_code, 400)

    def test_delete_device_requires_identifier(self):
        resp = self.client.post("/delete-device", json={})
        self.assertEqual(resp.status_code, 400)

    def test_snmp_config_rejects_non_numeric_port(self):
        resp = self.client.post(
            "/snmp-config", json={"ip": "10.0.0.2", "community": "public", "port": "x"}
        )
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
