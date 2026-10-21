import hashlib
import io
import json
import unittest
import zipfile
from pathlib import Path

from ghost import config
from ghost.db import db
from ghost.errors import GhostError, Unavailable
from ghost.services import cases, evidence, findings, operations, pcap, reports, system
from base import GhostTestCase
from helpers import classic_pcap, pcapng


class PcapTests(GhostTestCase):
    def run_cap(self, data, case_id=None, engine="builtin", name="cap.pcap"):
        up = pcap.store_upload(io.BytesIO(data), name)
        return operations.wait_for(pcap.start_analysis(up, case_id, engine)["id"], 30), up

    def test_builtin_analysis_extracts_real_facts(self):
        for name, builder in (("pcap", classic_pcap), ("pcapng", pcapng)):
            with self.subTest(fmt=name):
                data = builder()
                done, up = self.run_cap(data)
                self.assertEqual(done["status"], "completed", done["error"])
                r, a = done["result"], done["result"]["analysis"]
                self.assertEqual(r["file"]["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(a["packets"], 5)
                self.assertTrue(a["start"].startswith("2023-11-14T22:13:20"))
                self.assertTrue({"DNS", "TLS/HTTPS", "ARP"} <= {p["name"] for p in a["protocols"]})
                self.assertEqual(a["dns_queries"][0]["name"], "evil.example.org")
                self.assertIn("A 93.184.216.34", a["dns_queries"][0]["answers"])
                self.assertEqual(a["indicators"]["domains"], ["evil.example.org"])
                self.assertIn("93.184.216.34", a["indicators"]["public_ips"])
                self.assertEqual(next(e for e in a["tcp_endpoints"] if e["port"] == 443)["syn_in"], 1)

    def test_non_pcap_upload_rejected_by_magic_bytes_and_not_kept(self):
        with self.assertRaises(GhostError) as e:
            pcap.store_upload(io.BytesIO(b"MZ\x90\x00 this is an executable, not a capture"), "evil.pcap")
        self.assertEqual(e.exception.status, 415)
        self.assertEqual(list(config.get_settings().upload_dir.glob("*")), [])

    def test_upload_size_limit(self):
        self.reset(max_upload_mb=0)
        with self.assertRaises(GhostError) as e:
            pcap.store_upload(io.BytesIO(classic_pcap()), "a.pcap")
        self.assertEqual(e.exception.status, 413)

    def test_empty_capture_fails_honestly(self):
        done, _ = self.run_cap(classic_pcap([]))
        self.assertEqual(done["status"], "failed")
        self.assertIn("no packets", done["error"])

    def test_truncated_capture_does_not_crash(self):
        done, _ = self.run_cap(classic_pcap()[:-10])
        self.assertEqual((done["status"], done["result"]["analysis"]["packets"]), ("completed", 4))

    def test_tshark_requested_but_missing_is_unavailable(self):
        if system.find_tool("tshark", None):
            self.skipTest("tshark is installed on this machine")
        with self.assertRaises(Unavailable) as e:
            pcap.start_analysis(pcap.store_upload(io.BytesIO(classic_pcap()), "a.pcap"), None, "tshark")
        self.assertEqual(e.exception.code, "tool_missing")
        self.assertIn("install", e.exception.message.lower())

    def test_tshark_output_parsing_does_not_double_count_dns(self):
        """A DNS response echoes the question; only the query may be counted, and the answers must be kept."""
        import subprocess
        from unittest import mock as m
        rows = [
            ["1700000000.0", "70", "192.168.1.10", "", "192.168.1.1", "", "DNS", "", "", "53000", "53", "", "evil.example.org", "1", "", "", "False", "", ""],
            ["1700000000.2", "86", "192.168.1.1", "", "192.168.1.10", "", "DNS", "", "", "53", "53000", "", "evil.example.org", "1", "", "", "True", "93.184.216.34,93.184.216.35", ""],
            ["1700000001.0", "74", "192.168.1.10", "", "93.184.216.34", "", "TCP", "40000", "443", "", "", "0x00000002", "", "", "6", "", "", "", ""],
        ]
        text = "\n".join("\t".join(r) for r in rows)
        out = subprocess.CompletedProcess([], 0, stdout=text, stderr="")
        with m.patch("subprocess.run", return_value=out):
            a = pcap.analyse_tshark(Path("x.pcap"), "/usr/bin/tshark", [])
        self.assertEqual(a["packets"], 3)
        self.assertEqual(a["dns_query_count"], 1)
        self.assertEqual(a["dns_queries"][0]["answers"], ["A 93.184.216.34", "A 93.184.216.35"])
        self.assertEqual(a["tcp_endpoints"][0]["syn_in"], 1)
        self.assertEqual(a["indicators"]["domains"], ["evil.example.org"])

    def test_hash_tamper_between_upload_and_analysis_is_refused(self):
        up = pcap.store_upload(io.BytesIO(classic_pcap()), "a.pcap")
        Path(up["path"]).write_bytes(classic_pcap() + b"\x00")
        done = operations.wait_for(pcap.start_analysis(up)["id"], 20)
        self.assertEqual(done["status"], "failed")
        self.assertIn("hash changed", done["error"])

    def test_analysis_links_into_case_graph(self):
        c = cases.create_case("Net case")
        self.run_cap(classic_pcap(), c["id"])
        rels = {e["rel_type"] for e in findings.graph(case_id=c["id"])["edges"]}
        self.assertTrue({"contains_capture", "queried_in_capture", "contacted_in_capture"} <= rels)


class EvidenceTests(GhostTestCase):
    def test_register_verify_and_tamper_detection(self):
        c = cases.create_case("Evid case")
        e = evidence.register(io.BytesIO(b"secret contents"), "../../etc/passwd.txt", case_id=c["id"], source="usb")
        self.assertEqual(e["name"], "passwd.txt", "path components must be stripped")
        self.assertEqual(e["sha256"], hashlib.sha256(b"secret contents").hexdigest())
        self.assertFalse(e["encrypted"])
        self.assertTrue(evidence.verify(e["id"])["intact"])
        next(config.get_settings().vault_dir.glob("*.bin")).write_bytes(b"tampered")
        v = evidence.verify(e["id"])
        self.assertEqual((v["intact"], v["result"]), (False, "MISMATCH"))
        self.assertNotEqual(v["recomputed_sha256"], v["recorded_sha256"])
        self.assertEqual([x["action"] for x in evidence.get(e["id"])["custody_log"]], ["evidence.register", "evidence.verify", "evidence.verify"])

    def test_verify_recomputes_rather_than_trusting_stored_state(self):
        e = evidence.register(io.BytesIO(b"abc"), "a.txt")
        next(config.get_settings().vault_dir.glob("*.bin")).write_bytes(b"xyz")
        with db() as c:
            c.execute("UPDATE evidence SET last_verify_result='match' WHERE id=?", (e["id"],))
        self.assertFalse(evidence.verify(e["id"])["intact"])

    def test_missing_vault_file_is_unverifiable_not_ok(self):
        e = evidence.register(io.BytesIO(b"abc"), "a.txt")
        next(config.get_settings().vault_dir.glob("*.bin")).unlink()
        v = evidence.verify(e["id"])
        self.assertFalse(v["intact"])
        self.assertTrue(v["result"].startswith("unverifiable"))

    def test_encryption_at_rest_roundtrip_and_wrong_passphrase(self):
        self.reset(vault_passphrase="correct horse")
        e = evidence.register(io.BytesIO(b"top secret bytes"), "s.bin")
        self.assertTrue(e["encrypted"])
        raw = next(config.get_settings().vault_dir.glob("*.bin")).read_bytes()
        self.assertNotIn(b"top secret bytes", raw)
        self.assertTrue(raw.startswith(b"GHOSTENC1"))
        self.assertTrue(evidence.verify(e["id"])["intact"])
        self.assertEqual(evidence.read_bytes(e["id"])[0], b"top secret bytes")
        self.reset(vault_passphrase="wrong")
        v = evidence.verify(e["id"])
        self.assertFalse(v["intact"])
        self.assertIn("unverifiable", v["result"])
        self.reset(vault_passphrase=None)
        with self.assertRaises(Unavailable):
            evidence.read_bytes(e["id"])

    def test_delete_removes_file_and_leaves_audit_record(self):
        e = evidence.register(io.BytesIO(b"abc"), "a.txt")
        evidence.delete(e["id"])
        self.assertEqual(list(config.get_settings().vault_dir.glob("*.bin")), [])
        with db() as c:
            row = c.execute("SELECT detail FROM audit WHERE action='evidence.delete'").fetchone()
        self.assertIn(e["sha256"], row["detail"])

    def test_backup_contains_db_vault_and_manifest(self):
        evidence.register(io.BytesIO(b"abc"), "a.txt")
        path = evidence.create_backup(Path(self.tmp) / "b")
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            manifest = json.loads(z.read("manifest.json"))
            self.assertIn("ghost.db", names)
            self.assertTrue(any(n.startswith("vault/") for n in names))
            self.assertEqual(hashlib.sha256(z.read("ghost.db")).hexdigest(), manifest["files"]["ghost.db"])


class ReportTests(GhostTestCase):
    def test_sections_and_html_escaping(self):
        c = cases.create_case("<script>alert(1)</script> case", "obj <b>", "scope.example", True)
        cases.add_note(c["id"], "note with <img src=x onerror=alert(1)>")
        evidence.register(io.BytesIO(b"abc"), "e.txt", case_id=c["id"])
        with db() as conn:
            findings.add_finding(conn, kind="http", title="HTTP", source="Direct HTTPS request", case_id=c["id"],
                                 data={"missing_security_headers": ["content-security-policy"], "final_url": "https://scope.example/"})
        r = reports.generate(c["id"])
        html = (config.get_settings().report_dir / r["filename"]).read_text(encoding="utf-8")
        for section in ("Scope &amp; Authorisation", "Methodology", "Findings", "Indicators", "Evidence", "Limitations", "Recommendations"):
            self.assertIn(section, html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("content-security-policy", html)
        self.assertIn("UNREVIEWED", html)
        self.assertIn("are not digital signatures", html)
        self.assertEqual(hashlib.sha256(html.encode()).hexdigest(), r["sha256"])


if __name__ == "__main__":
    unittest.main()
