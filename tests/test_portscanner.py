# tests/test_portscanner.py
from __future__ import annotations
import asyncio
import tempfile
import os
import unittest

from tools.portscanner.utils import parse_ports, expand_cidrs, write_csv
from tools.portscanner.scanner import scan_ips, ScanResult


class TestUtils(unittest.TestCase):
    def test_parse_ports_simple(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_parse_ports_ranges_and_dups(self):
        self.assertEqual(
            parse_ports("1-3,2,3,5,10-12"),
            [1, 2, 3, 5, 10, 11, 12],
        )

    def test_parse_ports_invalid_ignored(self):
        # Values out of range are filtered out
        self.assertEqual(parse_ports("0,1,65535,65536"), [1, 65535])

    def test_expand_cidrs_small(self):
        # /30 has 2 hosts (excluding network/broadcast)
        ips = expand_cidrs(["192.168.1.0/30"])
        self.assertEqual(ips, ["192.168.1.1", "192.168.1.2"])

    def test_write_csv(self):
        results = [
            ScanResult(ip="10.0.0.1", open_ports=[22, 80]),
            ScanResult(ip="10.0.0.2", open_ports=[443]),
        ]
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "out.csv")
            write_csv(results, out)
            with open(out, "r") as f:
                content = f.read().strip().splitlines()
        # Header + 3 rows
        self.assertEqual(content[0], "ip,port")
        self.assertIn("10.0.0.1,22", content)
        self.assertIn("10.0.0.1,80", content)
        self.assertIn("10.0.0.2,443", content)


class TestScanner(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Start a temporary TCP server locally to get an open port
        self.server = await asyncio.start_server(self._handle, host="127.0.0.1", port=0)
        # The actual assigned port
        self.open_port = self.server.sockets[0].getsockname()[1]
        self.closed_port = self.open_port + 1  # This port is likely to be closed

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # Simply accept the connection and close
        try:
            await asyncio.sleep(0.05)
        finally:
            writer.close()
            if hasattr(writer, "wait_closed"):
                await writer.wait_closed()

    async def test_scan_ips_detects_open_port(self):
        results = await scan_ips(
            ips=["127.0.0.1"],
            ports=[self.open_port, self.closed_port],
            timeout=0.3,
            host_concurrency=10,
            port_concurrency=10,
            progress=False,
        )
        # There should be only one result, and it should include open_port
        self.assertTrue(any(r.ip == "127.0.0.1" for r in results))
        r = [r for r in results if r.ip == "127.0.0.1"][0]
        self.assertIn(self.open_port, r.open_ports)
        self.assertNotIn(self.closed_port, r.open_ports)


if __name__ == "__main__":
    unittest.main()
