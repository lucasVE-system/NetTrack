import unittest
from unittest.mock import MagicMock, patch

import scanner


class GetSubnetTests(unittest.TestCase):
    def test_extracts_slash24_prefix(self):
        self.assertEqual(scanner.get_subnet("192.168.1.100"), "192.168.1")

    def test_handles_short_input(self):
        self.assertEqual(scanner.get_subnet("10.0"), "10.0")


class GetArpTableTests(unittest.TestCase):
    def _run_with_output(self, stdout):
        fake = MagicMock(stdout=stdout)
        with patch("scanner.subprocess.run", return_value=fake):
            return scanner.get_arp_table()

    def test_parses_windows_style_entries(self):
        out = (
            "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic\n"
            "  192.168.1.20         11-22-33-44-55-66     dynamic\n"
        )
        result = self._run_with_output(out)
        self.assertEqual(result["192.168.1.1"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(result["192.168.1.20"], "11:22:33:44:55:66")

    def test_filters_broadcast_and_multicast(self):
        out = (
            "  192.168.1.255        ff-ff-ff-ff-ff-ff     static\n"
            "  224.0.0.22           01-00-5e-00-00-16     static\n"
            "  239.255.255.250      01-00-5e-7f-ff-fa     static\n"
        )
        self.assertEqual(self._run_with_output(out), {})

    def test_returns_empty_on_subprocess_error(self):
        with patch("scanner.subprocess.run", side_effect=OSError("boom")):
            self.assertEqual(scanner.get_arp_table(), {})


class PingSweepTests(unittest.TestCase):
    def test_rejects_invalid_subnet(self):
        # No pings should ever run for a malformed subnet
        with patch("scanner.ping_host") as mock_ping:
            self.assertEqual(scanner.ping_sweep("not-a-subnet"), [])
            mock_ping.assert_not_called()

    def test_returns_only_alive_ips(self):
        alive = {"10.0.0.5", "10.0.0.9"}
        with patch("scanner.ping_host", side_effect=lambda ip: ip in alive):
            result = scanner.ping_sweep("10.0.0")
        self.assertEqual(sorted(result), ["10.0.0.5", "10.0.0.9"])


class ScanSubnetDevicesTests(unittest.TestCase):
    def test_merges_arp_and_ping_results(self):
        arp = {"192.168.1.10": "AA:BB:CC:DD:EE:01"}
        with patch("scanner.get_arp_table", return_value=arp), \
             patch("scanner.ping_sweep", return_value=["192.168.1.20"]), \
             patch("scanner.lookup_vendor", return_value="TestVendor"), \
             patch("scanner.get_hostname", return_value="host"):
            devices = scanner.scan_subnet_devices("192.168.1")

        ips = [d["ip"] for d in devices]
        self.assertEqual(ips, ["192.168.1.10", "192.168.1.20"])
        self.assertEqual(devices[0]["mac"], "AA:BB:CC:DD:EE:01")
        self.assertEqual(devices[0]["vendor"], "TestVendor")
        self.assertEqual(devices[1]["mac"], "")  # ping-only device has no MAC

    def test_excludes_local_ip_and_foreign_subnets(self):
        arp = {
            "192.168.1.10": "AA:BB:CC:DD:EE:01",
            "10.0.0.5":     "AA:BB:CC:DD:EE:02",  # outside requested subnet
        }
        with patch("scanner.get_arp_table", return_value=arp), \
             patch("scanner.ping_sweep", return_value=["192.168.1.50"]), \
             patch("scanner.lookup_vendor", return_value=""), \
             patch("scanner.get_hostname", return_value=""):
            devices = scanner.scan_subnet_devices("192.168.1", local_ip="192.168.1.50")

        self.assertEqual([d["ip"] for d in devices], ["192.168.1.10"])


if __name__ == "__main__":
    unittest.main()
