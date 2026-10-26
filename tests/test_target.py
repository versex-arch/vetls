import unittest

from vetls.target import normalize_hostname, parse_target


class ParseTargetTests(unittest.TestCase):
    def test_valid_targets(self):
        cases = {
            "example.com": ("example.com", 443, "example.com"),
            "example.com:8443": ("example.com", 8443, "example.com"),
            "  Example.COM.  ": ("example.com", 443, "example.com"),
            "https://example.com": ("example.com", 443, "example.com"),
            "https://example.com:9443/a/b?q=1#frag": ("example.com", 9443, "example.com"),
            "example.com/some/path": ("example.com", 443, "example.com"),
            "example.com:8443/some/path?x=1": ("example.com", 8443, "example.com"),
            "10.0.0.1": ("10.0.0.1", 443, None),
            "10.0.0.1:8443": ("10.0.0.1", 8443, None),
            "[2001:db8::1]:8443": ("2001:db8::1", 8443, None),
            "[2001:db8::1]": ("2001:db8::1", 443, None),
            "2001:db8::1": ("2001:db8::1", 443, None),
            "https://[::1]:8443/x": ("::1", 8443, None),
            "bücher.example": ("xn--bcher-kva.example", 443, "xn--bcher-kva.example"),
            "BÜCHER.example": ("xn--bcher-kva.example", 443, "xn--bcher-kva.example"),
            "faß.de": ("xn--fa-hia.de", 443, "xn--fa-hia.de"),  # IDNA 2008, not "fass.de"
            "https://пример.рф:8443/": ("xn--e1afmkfd.xn--p1ai", 8443, "xn--e1afmkfd.xn--p1ai"),
            "tls://example.com:993": ("example.com", 993, "example.com"),
        }
        for raw, (host, port, sni) in cases.items():
            with self.subTest(raw=raw):
                parsed = parse_target(raw)
                self.assertEqual((parsed.host, parsed.port, parsed.sni), (host, port, sni))
                self.assertIsInstance(parsed.port, int)

    def test_ip_has_no_sni(self):
        self.assertTrue(parse_target("127.0.0.1").is_ip)
        self.assertFalse(parse_target("localhost").is_ip)

    def test_default_port_argument(self):
        self.assertEqual(parse_target("example.com", default_port=22).port, 22)

    def test_invalid_targets(self):
        for raw in [
            "",
            "   ",
            "example.com:99999",
            "example.com:0",
            "example.com:abc",
            "example.com:-1",
            "http://example.com",
            "ftp://example.com",
            "user:pw@example.com",
            "https://user@example.com",
            "exa mple.com",
            "-bad.example",
            "a..b",
            "[2001:db8::1",
            "https://",
            "a" * 64 + ".example",
        ]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_target(raw)

    def test_normalize_hostname(self):
        self.assertEqual(normalize_hostname(" Example.COM. "), "example.com")
        for bad in ("", "a..b", "xn--a.example\u200d", "-x.example"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                normalize_hostname(bad)

    def test_non_string(self):
        with self.assertRaises(ValueError):
            parse_target(None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
