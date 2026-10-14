import struct
import unittest

from ghostlink import dnswire


class TestBuildQuery(unittest.TestCase):
    def test_header_fields(self):
        query = dnswire.build_query("example.com", qid=0xABCD, rd=True)
        qid, flags, qd = struct.unpack(">HHH", query[:6])
        self.assertEqual(qid, 0xABCD)
        self.assertEqual(flags, 0x0100)  # recursion desired
        self.assertEqual(qd, 1)

    def test_question_encoding(self):
        query = dnswire.build_query("a.b", qid=1)
        question = query[12:]
        self.assertEqual(question[0], 1)
        self.assertEqual(question[1], ord("a"))
        self.assertEqual(question[2], 1)
        self.assertEqual(question[3], ord("b"))
        self.assertEqual(question[4], 0)
        qtype, qclass = struct.unpack(">HH", question[5:9])
        self.assertEqual((qtype, qclass), (dnswire.QTYPE_A, dnswire.QCLASS_IN))

    def test_rd_disabled(self):
        query = dnswire.build_query("example.com", rd=False)
        self.assertEqual(struct.unpack(">H", query[2:4])[0], 0x0000)


class TestParseHeader(unittest.TestCase):
    def test_roundtrip(self):
        parsed = dnswire.parse_header(dnswire.build_query("example.org", qid=0x1234))
        self.assertEqual(parsed["id"], 0x1234)
        self.assertTrue(parsed["rd"])
        self.assertEqual(parsed["qdcount"], 1)
        self.assertEqual(parsed["ancount"], 0)
        self.assertEqual(parsed["rcode"], 0)

    def test_flags_decoding(self):
        header = struct.pack(">HHHHHH", 7, 0x8180, 1, 2, 0, 0)
        parsed = dnswire.parse_header(header)
        self.assertEqual(parsed["id"], 7)
        self.assertTrue(parsed["ra"])
        self.assertEqual(parsed["rcode"], 0)
        self.assertEqual(parsed["ancount"], 2)

    def test_rejects_short(self):
        with self.assertRaises(ValueError):
            dnswire.parse_header(b"\x00")


if __name__ == "__main__":
    unittest.main()
