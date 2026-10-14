import unittest

from ghostlink.config import Target
from ghostlink.report import generate_findings, render_markdown


def _target() -> Target:
    return Target(
        iface="wlan0",
        address="10.0.0.5",
        prefix=24,
        gateway="10.0.0.1",
        resolvers=["10.0.0.1"],
        network="10.0.0.0/24",
        wireless=True,
        mac="aa:bb:cc:dd:ee:ff",
    )


def _base_results(portal_url: str | None = None) -> dict:
    return {
        "recon": {"target": {"iface": "wlan0"}, "portal": {"portal": portal_url is not None, "portal_url": portal_url, "probes": []}},
        "egress": {"tcp": {}, "dns_leak": {"upstream": [], "gateway": None}},
        "walled": {"reachable": {}},
        "extras": {"ipv6_addresses": [], "path": {}, "dhcp": {}},
    }


class TestFindings(unittest.TestCase):
    def test_open_network_is_informational(self):
        results = _base_results()
        results["egress"]["dns_leak"]["upstream"] = [{"server": "1.1.1.1", "reply": True}]
        findings = generate_findings(results)
        self.assertTrue(all(f["severity"] == "info" for f in findings))

    def test_portal_escalates_dns_leak(self):
        results = _base_results(portal_url="http://portal.local/login")
        results["egress"]["dns_leak"]["upstream"] = [{"server": "1.1.1.1", "reply": True}]
        findings = generate_findings(results)
        titles = [f["title"] for f in findings]
        self.assertTrue(any("UDP/53" in t for t in titles))
        dns = next(f for f in findings if "UDP/53" in f["title"])
        self.assertEqual(dns["severity"], "high")

    def test_ipv6_egress_high(self):
        results = _base_results()
        results["extras"]["ipv6_addresses"] = [{"iface": "wlan0", "address": "2001:db8::1", "prefixlen": 64}]
        results["extras"]["ipv6_egress"] = "open"
        findings = generate_findings(results)
        self.assertTrue(any(f["severity"] == "high" and "IPv6" in f["title"] for f in findings))

    def test_path_divergence_medium(self):
        results = _base_results()
        results["extras"]["path"] = {"expected_gateway": "10.0.0.1", "first_hop": "10.0.0.9", "matches_gateway": False}
        findings = generate_findings(results)
        self.assertTrue(any(f["severity"] == "medium" for f in findings))


class TestRender(unittest.TestCase):
    def test_markdown_sections(self):
        results = _base_results(portal_url="http://portal.local/login")
        md = render_markdown(_target(), results)
        self.assertIn("# GhostLink report", md)
        self.assertIn("## Portal", md)
        self.assertIn("## Pre-auth egress", md)
        self.assertIn("## Findings", md)
        self.assertIn("http://portal.local/login", md)
        self.assertIn("10.0.0.5", md)


if __name__ == "__main__":
    unittest.main()
