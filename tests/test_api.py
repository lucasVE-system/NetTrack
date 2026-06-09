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


class SnmpV3ConfigTests(unittest.TestCase):
    def setUp(self):
        nettrack_app.app.config["TESTING"] = True
        self.client = nettrack_app.app.test_client()

    def _post(self, payload):
        with patch("app.save_snmp_config"):
            return self.client.post("/snmp-config", json=payload)

    def test_v3_requires_user(self):
        resp = self._post({"ip": "10.0.0.2", "version": "v3"})
        self.assertEqual(resp.status_code, 400)

    def test_v3_accepts_user_with_auth(self):
        resp = self._post({
            "ip": "10.0.0.2", "version": "v3", "user": "admin",
            "auth_key": "secret123", "auth_proto": "sha",
        })
        self.assertEqual(resp.status_code, 200)

    def test_v3_rejects_unknown_auth_proto(self):
        resp = self._post({
            "ip": "10.0.0.2", "version": "v3", "user": "admin",
            "auth_key": "secret123", "auth_proto": "rot13",
        })
        self.assertEqual(resp.status_code, 400)

    def test_rejects_unknown_version(self):
        resp = self._post({"ip": "10.0.0.2", "version": "v1", "community": "public"})
        self.assertEqual(resp.status_code, 400)

    def test_get_never_returns_credentials(self):
        self._post({"ip": "10.0.0.9", "version": "v3", "user": "admin",
                    "auth_key": "supersecret"})
        resp = self.client.get("/snmp-config")
        body = resp.get_data(as_text=True)
        self.assertNotIn("supersecret", body)
        self.assertNotIn("admin", body)


class SnmpConfigSchemaTests(unittest.TestCase):
    def test_valid_v2c_entry(self):
        self.assertTrue(nettrack_app._valid_snmp_entry(
            "10.0.0.1", {"version": "v2c", "community": "public", "port": 161}))

    def test_legacy_entry_without_version(self):
        self.assertTrue(nettrack_app._valid_snmp_entry(
            "10.0.0.1", {"community": "public", "port": 161}))

    def test_wildcard_ip_allowed(self):
        self.assertTrue(nettrack_app._valid_snmp_entry(
            "*", {"community": "public"}))

    def test_rejects_bad_ip(self):
        self.assertFalse(nettrack_app._valid_snmp_entry(
            "999.0.0.1", {"community": "public"}))

    def test_rejects_bad_port(self):
        self.assertFalse(nettrack_app._valid_snmp_entry(
            "10.0.0.1", {"community": "public", "port": 99999}))

    def test_rejects_v3_without_user(self):
        self.assertFalse(nettrack_app._valid_snmp_entry(
            "10.0.0.1", {"version": "v3"}))

    def test_rejects_non_dict(self):
        self.assertFalse(nettrack_app._valid_snmp_entry("10.0.0.1", "public"))


class VersionParsingTests(unittest.TestCase):
    def test_parses_plain_and_v_prefixed(self):
        self.assertEqual(nettrack_app.parse_version("1.2.0"), (1, 2, 0))
        self.assertEqual(nettrack_app.parse_version("v1.10.3"), (1, 10, 3))

    def test_invalid_returns_zero_tuple(self):
        self.assertEqual(nettrack_app.parse_version("garbage"), (0, 0, 0))

    def test_ordering(self):
        self.assertGreater(
            nettrack_app.parse_version("v1.10.0"),
            nettrack_app.parse_version("v1.9.9"))


class UpdateUrlAllowlistTests(unittest.TestCase):
    def test_allows_official_release_url(self):
        url = (f"https://github.com/{nettrack_app.GITHUB_REPO}"
               "/releases/download/v9.9.9/NetTrack.exe")
        self.assertTrue(nettrack_app.is_allowed_update_url(url))

    def test_blocks_http(self):
        url = (f"http://github.com/{nettrack_app.GITHUB_REPO}"
               "/releases/download/v9.9.9/NetTrack.exe")
        self.assertFalse(nettrack_app.is_allowed_update_url(url))

    def test_blocks_other_hosts(self):
        self.assertFalse(nettrack_app.is_allowed_update_url(
            "https://evil.example.com/NetTrack.exe"))

    def test_blocks_other_repos_on_github(self):
        self.assertFalse(nettrack_app.is_allowed_update_url(
            "https://github.com/attacker/repo/releases/download/v1/x.exe"))


if __name__ == "__main__":
    unittest.main()
