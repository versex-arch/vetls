import asyncio
import unittest

from helpers import RawServer, free_port
from vetls.ssh_scanner import SSHScanner, parse_banner, scan_ssh


class ParseBannerTests(unittest.TestCase):
    def test_standard(self):
        r = parse_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
        self.assertTrue(r["is_ssh"])
        self.assertEqual(r["protocol_version"], "2.0")
        self.assertEqual(r["software_version"], "OpenSSH_9.6p1")
        self.assertEqual(r["comments"], "Ubuntu-3ubuntu13")

    def test_not_ssh(self):
        self.assertFalse(parse_banner("HTTP/1.1 200 OK\r\n")["is_ssh"])
        self.assertFalse(parse_banner("")["is_ssh"])
        self.assertFalse(parse_banner("SSH-2.0")["is_ssh"])
        self.assertFalse(parse_banner("SSH--x")["is_ssh"])


class ScanSshTests(unittest.TestCase):
    def test_reads_banner(self):
        with RawServer(b"SSH-2.0-TestSSH_1.0\r\n") as srv:
            r = SSHScanner("127.0.0.1", port=srv.port, timeout=2).scan_sync()
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["banner"], "SSH-2.0-TestSSH_1.0")
        self.assertEqual(r["protocol_version"], "2.0")
        self.assertEqual(r["software_version"], "TestSSH_1.0")
        self.assertEqual(r["pre_banner_lines"], [])

    def test_pre_banner_lines_are_kept(self):
        with RawServer(b"Welcome\r\nAuthorized use only\r\nSSH-2.0-Srv\r\n") as srv:
            r = SSHScanner("127.0.0.1", port=srv.port, timeout=2).scan_sync()
        self.assertEqual(r["pre_banner_lines"], ["Welcome", "Authorized use only"])
        self.assertEqual(r["banner"], "SSH-2.0-Srv")

    def test_too_many_pre_banner_lines(self):
        with RawServer(b"x\r\n" * 50) as srv:
            r = SSHScanner("127.0.0.1", port=srv.port, timeout=2).scan_sync()
        self.assertEqual(r["status"], "ok")
        self.assertIsNone(r["banner"])
        self.assertEqual(len(r["pre_banner_lines"]), 9)

    def test_non_ssh_service(self):
        with RawServer(b"220 mail.example ESMTP\r\n") as srv:
            r = SSHScanner("127.0.0.1", port=srv.port, timeout=2).scan_sync()
        self.assertEqual(r["status"], "ok")
        self.assertFalse(r["banner"] and r["banner"].startswith("SSH-"))
        self.assertIn("may not speak SSH", r["note"] or "")

    def test_silent_server_times_out_cleanly(self):
        with RawServer(None, hold=1.5) as srv:
            r = SSHScanner("127.0.0.1", port=srv.port, timeout=0.3).scan_sync()
        self.assertEqual(r["status"], "ok")
        self.assertIsNone(r["banner"])
        self.assertIn("timed out", r["note"])

    def test_connection_refused(self):
        r = SSHScanner("127.0.0.1", port=free_port(), timeout=2).scan_sync()
        self.assertEqual(r["status"], "error")
        self.assertIn("connection failed", r["error"])

    def test_error_result_keeps_full_schema(self):
        ok = asyncio.run(scan_ssh("127.0.0.1", free_port(), 1))
        with RawServer(b"SSH-2.0-x\r\n") as srv:
            good = SSHScanner("127.0.0.1", port=srv.port).scan_sync()
        self.assertEqual(set(ok), set(good))

    def test_no_vulnerability_claims(self):
        with RawServer(b"SSH-2.0-OpenSSH_4.3\r\n") as srv:
            r = SSHScanner("127.0.0.1", port=srv.port, timeout=2).scan_sync()
        self.assertTrue(r["vulnerability_assessment"].startswith("not performed"))

    def test_target_handling(self):
        s = SSHScanner("[::1]:2222")
        self.assertEqual((s.host, s.port), ("::1", 2222))
        self.assertEqual(SSHScanner("example.com").port, 22)
        self.assertEqual(SSHScanner("example.com:2222", port=22022).port, 22022)
        with self.assertRaises(ValueError):
            SSHScanner("bad host")
        with self.assertRaises(ValueError):
            SSHScanner("example.com", port=70000)
        with self.assertRaises(ValueError):
            SSHScanner("example.com", timeout=0)

    def test_scan_sync_inside_running_loop_raises(self):
        async def inner():
            with self.assertRaises(RuntimeError):
                SSHScanner("127.0.0.1").scan_sync()

        asyncio.run(inner())


if __name__ == "__main__":
    unittest.main()
