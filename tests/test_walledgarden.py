import unittest

from ghostlink.walledgarden import extract_candidate_hosts, probe_candidates


PORTAL_HTML = """
<html><head>
<script src="https://js.stripe.com/v3/"></script>
<script src="//cdn.portalvendor.net/assets/app.js"></script>
<link rel="stylesheet" href="/local/style.css">
</head><body>
<img src="http://connectivitycheck.gstatic.com/generate_204">
<a href="https://portal.venue.local/login?ip=10.0.0.5">Pay</a>
<a href="ftp://files.example.com/x">ftp</a>
<script>fetch('https://api.portalvendor.net/session')</script>
</body></html>
"""


class TestExtractCandidateHosts(unittest.TestCase):
    def test_finds_external_hosts(self):
        hosts = extract_candidate_hosts(PORTAL_HTML, portal_host="portal.venue.local")
        self.assertIn("js.stripe.com", hosts)
        self.assertIn("cdn.portalvendor.net", hosts)
        self.assertIn("api.portalvendor.net", hosts)

    def test_excludes_portal_itself(self):
        hosts = extract_candidate_hosts(PORTAL_HTML, portal_host="portal.venue.local")
        self.assertNotIn("portal.venue.local", hosts)

    def test_dedupes_and_sorts(self):
        html = "https://a.com/x https://x.com/y <script>a.com/z</script>"
        hosts = extract_candidate_hosts(html, portal_host=None)
        self.assertEqual(hosts, ["a.com", "x.com"])

    def test_protocol_relative_urls(self):
        html = '<script src="//cdn.example.net/a.js"></script>'
        self.assertEqual(extract_candidate_hosts(html, None), ["cdn.example.net"])

    def test_respects_limit(self):
        html = " ".join(f"https://h{i}.example.com/x" for i in range(100))
        self.assertEqual(len(extract_candidate_hosts(html, limit=10)), 10)

    def test_empty_html(self):
        self.assertEqual(extract_candidate_hosts("", None), [])


class TestProbeCandidates(unittest.TestCase):
    def test_only_reachable_returned(self):
        # unroutable TEST-NET range: connects hang then fail, so nothing is returned
        result = probe_candidates(["192.0.2.1"], timeout=0.5)
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
