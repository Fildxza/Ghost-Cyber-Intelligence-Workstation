import socket
import unittest
from unittest import mock

import httpx

from ghost import netguard
from ghost.errors import GhostError
from ghost.netguard import BlockedTarget
from base import GhostTestCase


class AddressPolicy(GhostTestCase):
    def test_non_public_addresses_are_rejected(self):
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.9", "169.254.169.254", "::1", "fe80::1", "::ffff:127.0.0.1", "0.0.0.0", "100.64.0.1"]:
            with self.subTest(ip=ip):
                self.assertFalse(netguard.is_public_ip(ip))

    def test_public_addresses_accepted(self):
        for ip in ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"]:
            with self.subTest(ip=ip):
                self.assertTrue(netguard.is_public_ip(ip))

    def test_resolve_public_blocks_literals(self):
        for host in ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"]:
            with self.subTest(host=host), self.assertRaises(BlockedTarget):
                netguard.resolve_public(host)

    def test_hostname_resolving_to_private_is_blocked(self):
        with mock.patch.object(socket, "getaddrinfo", lambda h, p, **k: [(2, 1, 6, "", ("10.0.0.7", p))]):
            with self.assertRaisesRegex(BlockedTarget, "non-public"):
                netguard.resolve_public("rebind.example")

    def test_mixed_public_and_private_answers_are_blocked(self):
        answers = [(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("127.0.0.1", 443))]
        with mock.patch.object(socket, "getaddrinfo", lambda h, p, **k: answers):
            with self.assertRaises(BlockedTarget):
                netguard.resolve_public("mixed.example")


class UrlAndDomainValidation(GhostTestCase):
    def test_validate_url_rejects_unsafe(self):
        for url in ["file:///etc/passwd", "gopher://x/", "ftp://example.com/", "http://user:pw@example.com/", "http://example.com:22/", "javascript:alert(1)"]:
            with self.subTest(url=url), self.assertRaises(BlockedTarget):
                netguard.validate_url(url)

    def test_validate_url_accepts_plain_https(self):
        self.assertEqual(netguard.validate_url("https://Example.com/a?b=1"), ("https", "example.com", 443, "/a?b=1"))

    def test_normalise_domain_rejects(self):
        for bad in ["", "http://example.com", "example.com/path", "user@example.com", "exa mple.com", "localhost", "-bad.com", "a" * 70 + ".com", "example.com:443"]:
            with self.subTest(bad=bad), self.assertRaises(GhostError):
                netguard.normalise_domain(bad)

    def test_normalise_domain_idna_and_case(self):
        self.assertEqual(netguard.normalise_domain("  Example.COM. "), "example.com")
        self.assertEqual(netguard.normalise_domain("bücher.example"), "xn--bcher-kva.example")


class SafeFetch(GhostTestCase):
    def world(self, dns, handler):
        real = httpx.Client
        stack = [
            mock.patch.object(socket, "getaddrinfo", lambda h, p, **k: [(2, 1, 6, "", (dns[h], p))]),
            mock.patch.object(netguard.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **{k: v for k, v in kw.items() if k != "verify"})),
        ]
        for m in stack:
            m.start()
            self.addCleanup(m.stop)

    def test_pins_ip_and_keeps_host_header(self):
        seen = {}

        def handler(req):
            seen["url"], seen["host"] = str(req.url), req.headers["host"]
            return httpx.Response(200, text="ok")

        self.world({"good.example": "93.184.216.34"}, handler)
        resp = netguard.safe_fetch("https://good.example/x")
        self.assertEqual((resp.status, resp.peer_ip), (200, "93.184.216.34"))
        self.assertTrue(seen["url"].startswith("https://93.184.216.34/"))
        self.assertEqual(seen["host"], "good.example")

    def test_redirect_to_private_host_is_blocked_at_the_boundary(self):
        self.world({"good.example": "93.184.216.34", "internal.example": "10.0.0.5"},
                   lambda req: httpx.Response(302, headers={"location": "http://internal.example/admin"}))
        with self.assertRaisesRegex(BlockedTarget, "non-public"):
            netguard.safe_fetch("https://good.example/")

    def test_redirect_to_metadata_literal_is_blocked(self):
        self.world({"good.example": "93.184.216.34"}, lambda req: httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"}))
        with self.assertRaises(BlockedTarget):
            netguard.safe_fetch("https://good.example/")

    def test_redirect_loop_is_bounded(self):
        self.world({"loop.example": "93.184.216.34"}, lambda req: httpx.Response(302, headers={"location": "https://loop.example/"}))
        with self.assertRaisesRegex(GhostError, "Too many redirects"):
            netguard.safe_fetch("https://loop.example/")

    def test_response_body_is_capped(self):
        self.world({"big.example": "93.184.216.34"}, lambda req: httpx.Response(200, content=b"A" * 1_000_000))
        resp = netguard.safe_fetch("https://big.example/")
        self.assertTrue(resp.truncated)
        self.assertEqual(len(resp.body), 262144)


if __name__ == "__main__":
    unittest.main()
