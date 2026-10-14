import unittest

from ghostlink.mac import (
    MacError,
    is_locally_administered,
    normalize_mac,
    random_mac,
)


class TestNormalize(unittest.TestCase):
    def test_colon_form(self):
        self.assertEqual(normalize_mac("62:0E:4B:81:A9:E8"), "62:0e:4b:81:a9:e8")

    def test_dash_form(self):
        self.assertEqual(normalize_mac("62-0E-4B-81-A9-E8"), "62:0e:4b:81:a9:e8")

    def test_rejects_garbage(self):
        for bad in ["", "nope", "62:0e:4b:81:a9", "zz:0e:4b:81:a9:e8", "62:0e:4b:81:a9:e8:ff"]:
            with self.assertRaises(MacError):
                normalize_mac(bad)


class TestLocalBit(unittest.TestCase):
    def test_detected(self):
        self.assertTrue(is_locally_administered("02:00:00:00:00:00"))
        self.assertTrue(is_locally_administered("06:00:00:00:00:00"))
        self.assertFalse(is_locally_administered("04:00:00:00:00:00"))  # multicast only
        self.assertFalse(is_locally_administered("f0:18:98:00:00:00"))  # vendor OUI verbatim


class TestRandomMac(unittest.TestCase):
    def test_local_bit_set(self):
        for _ in range(50):
            self.assertTrue(is_locally_administered(random_mac(local=True)))

    def test_not_multicast(self):
        for _ in range(50):
            first = int(normalize_mac(random_mac()).split(":")[0], 16)
            self.assertEqual(first & 0b1, 0)

    def test_vendor_prefix_preserved_verbatim(self):
        # regression: mangling the U/L bit broke the OUI (a4 -> a6)
        for _ in range(50):
            mac = random_mac(vendor="apple")
            self.assertTrue(mac.startswith(("f0:18:98", "dc:a6:32", "a4:83:e7")), mac)

    def test_unknown_vendor(self):
        with self.assertRaises(MacError):
            random_mac(vendor="nokia-3310")

    def test_unique(self):
        self.assertEqual(len({random_mac() for _ in range(100)}), 100)


if __name__ == "__main__":
    unittest.main()
