import struct
import unittest

from ghostlink import ids


class TestMacUtils(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(ids.normalize_mac("F0-18-98-2A-07-06"), "f0:18:98:2a:07:06")
        self.assertEqual(ids.normalize_mac("f0:18:98:2a:07:06"), "f0:18:98:2a:07:06")

    def test_normalize_rejects(self):
        for bad in ["", "zz:18:98:2a:07:06", "f0:18:98:2a:07", "nope"]:
            with self.assertRaises(ids.IdentityError):
                ids.normalize_mac(bad)

    def test_is_randomized(self):
        self.assertTrue(ids.is_randomized("02:11:22:33:44:55"))
        self.assertTrue(ids.is_randomized("06:11:22:33:44:55"))
        self.assertFalse(ids.is_randomized("04:11:22:33:44:55"))  # multicast only
        self.assertFalse(ids.is_randomized("f0:18:98:2a:07:06"))  # vendor OUI


class TestVendorLookup(unittest.TestCase):
    def test_known(self):
        self.assertEqual(ids.lookup_vendor("f0:18:98:2a:07:06"), "Apple")
        self.assertEqual(ids.lookup_vendor("34:23:87:ab:cd:ef"), "Samsung")

    def test_unknown_is_empty(self):
        self.assertEqual(ids.lookup_vendor("aa:bb:cc:dd:ee:ff"), "")
        self.assertEqual(ids.lookup_vendor("garbage"), "")


class TestIfaceType(unittest.TestCase):
    def test_types(self):
        self.assertEqual(ids.friendly_iface_type("lo"), "loopback")
        self.assertEqual(ids.friendly_iface_type("wlp0s20f3"), "wifi")
        self.assertEqual(ids.friendly_iface_type("enp0s31f6"), "ethernet")
        self.assertEqual(ids.friendly_iface_type("docker0"), "bridge")
        self.assertEqual(ids.friendly_iface_type("br-1234"), "bridge")
        self.assertEqual(ids.friendly_iface_type("veth0"), "virtual")
        self.assertEqual(ids.friendly_iface_type("tun0"), "virtual")
        self.assertEqual(ids.friendly_iface_type("weird0"), "other")

    def test_wireless_overrides(self):
        self.assertEqual(ids.friendly_iface_type("enx1234", wireless=True), "wifi")


class TestNbname(unittest.TestCase):
    def test_encoding(self):
        encoded = ids._encode_nbname("*")
        self.assertEqual(len(encoded), 33)
        self.assertEqual(encoded[0], 32)
        self.assertEqual(encoded[1:3], b"CK")  # '*' = 0x2A -> 'C' + 'K'


class TestParseNbstat(unittest.TestCase):
    def _response(self):
        header = struct.pack(">HHHHHH", 0x1337, 0x8400, 0, 1, 0, 0)
        answer_ptr = struct.pack(">H", 0xC00C)
        name = b"WORKSTATION1".ljust(15) + bytes([0x03]) + struct.pack(">H", 0x4000)
        rdata = bytes([1]) + name
        rdata = rdata[:1] + name  # count byte + one name entry
        answer = answer_ptr + struct.pack(">HHIH", 0x21, 1, 0, len(rdata)) + rdata
        return header + answer

    def test_parses_names(self):
        names = ids.parse_nbstat_response(self._response())
        self.assertEqual(names, ["WORKSTATION1 (nb:0x03)"])

    def test_rejects_short(self):
        self.assertEqual(ids.parse_nbstat_response(b"\x00" * 4), [])


class TestDecodeName(unittest.TestCase):
    def test_plain_labels(self):
        data = b"\x03www\x07example\x03com\x00rest"
        self.assertEqual(ids.decode_name(data, 0), ("www.example.com", 17))

    def test_compression_pointer(self):
        data = b"\x03abc\x00" + struct.pack(">H", 0xC000)
        self.assertEqual(ids.decode_name(data, 5), ("abc", 7))


class TestExtractPtr(unittest.TestCase):
    def _response(self):
        header = struct.pack(">HHHHHH", 0x6D64, 0x8400, 1, 1, 0, 0)
        question = b"\x0210\x07in-addr\x04arpa\x00" + struct.pack(">HH", 12, 1)
        rdata = b"\x03mac\x04mini\x04home\x00"
        answer = struct.pack(">H", 0xC00C) + struct.pack(">HHIH", 12, 1, 0, len(rdata)) + rdata
        return header + question + answer

    def test_extracts_ptr_name(self):
        self.assertEqual(ids.extract_ptr_from_mdns(self._response()), "mac.mini.home")

    def test_no_answers(self):
        header = struct.pack(">HHHHHH", 0x6D64, 0x8400, 0, 0, 0, 0)
        self.assertIsNone(ids.extract_ptr_from_mdns(header))

    def test_rejects_short(self):
        self.assertIsNone(ids.extract_ptr_from_mdns(b"\x00" * 6))


if __name__ == "__main__":
    unittest.main()
