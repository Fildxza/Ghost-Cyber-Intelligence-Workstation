import unittest
from unittest import mock

from ghost import config
from ghost.db import db, migrate
from ghost.errors import GhostError, NotFound, Unavailable
from ghost.services import cases, findings, operations, osint, system
from base import GhostTestCase


class CaseTests(GhostTestCase):
    def test_lifecycle_and_persistence_across_restart(self):
        c = cases.create_case("Phishing review", "find infra", "example.com", True, "high", ["Phish", "phish", " brand "])
        self.assertTrue(c["ref"].startswith("GHO-CASE-") and c["ref"].endswith("-0001"))
        self.assertEqual((c["tags"], c["status"], c["authorisation_ack"]), (["phish", "brand"], "open", True))
        cases.add_note(c["id"], "first note")
        cases.update_case(c["id"], status="active", priority="critical")
        # "restart": drop settings and reopen the same data directory
        self.reset()
        migrate()
        again = cases.get_case(c["id"])
        self.assertEqual((again["status"], again["priority"], again["counts"]["notes"]), ("active", "critical", 1))
        self.assertEqual([x["ref"] for x in cases.list_cases(q="phish")], [c["ref"]])

    def test_refs_are_sequential_and_unique(self):
        refs = [cases.create_case(f"Case {i}")["ref"] for i in range(3)]
        self.assertEqual(refs, sorted(set(refs)))
        self.assertTrue(refs[-1].endswith("-0003"))

    def test_validation_and_archive(self):
        with self.assertRaises(GhostError):
            cases.create_case("x")
        with self.assertRaises(GhostError):
            cases.create_case("Valid name", priority="urgent")
        c = cases.create_case("To archive")
        cases.archive_case(c["id"])
        self.assertEqual(cases.list_cases(), [])
        self.assertEqual(len(cases.list_cases(include_archived=True)), 1)
        with self.assertRaisesRegex(GhostError, "archived"):
            operations.create("domain_investigation", "example.com", case_id=c["id"], run=False)

    def test_workspaces_scope_cases(self):
        other = cases.create_workspace("Alpha")
        cases.create_case("In default")
        cases.create_case("In alpha", workspace_id=other["id"])
        self.assertEqual([c["name"] for c in cases.list_cases(workspace_id=other["id"])], ["In alpha"])
        with self.assertRaises(GhostError):
            cases.create_workspace("Alpha")

    def test_timeline_records_actions(self):
        c = cases.create_case("Timeline case")
        cases.add_note(c["id"], "n")
        self.assertEqual([e["action"] for e in cases.case_timeline(c["id"])], ["case.note", "case.create"])


class AuthorisationTests(GhostTestCase):
    def test_active_checks_require_declared_scope_and_authorisation(self):
        with self.assertRaises(GhostError) as e:
            osint.start_domain_investigation("example.com", None, active=True, authorisation_note="x")
        self.assertEqual(e.exception.code, "authorisation_required")
        c = cases.create_case("No auth")
        with self.assertRaises(GhostError) as e:
            osint.start_domain_investigation("example.com", c["id"], active=True, authorisation_note="x")
        self.assertEqual(e.exception.status, 403)
        ok = cases.create_case("With auth", scope="example.com", authorisation_ack=True)
        with self.assertRaisesRegex(GhostError, "authorisation statement"):
            osint.start_domain_investigation("example.com", ok["id"], active=True, authorisation_note="  ")

    def test_invalid_domain_rejected_before_any_operation_exists(self):
        with self.assertRaises(GhostError):
            osint.start_domain_investigation("http://evil.com/x")
        self.assertEqual(operations.list_operations(), [])

    def test_field_mode_blocks_outbound_operations(self):
        system.set_field_mode(True)
        with self.assertRaises(Unavailable) as e:
            osint.start_domain_investigation("example.com")
        self.assertEqual(e.exception.code, "field_mode")


def boom(msg, status, code):
    def _raise(*a, **k):
        raise GhostError(msg, status, code)
    return _raise


class OperationTests(GhostTestCase):
    def test_failure_is_reported_honestly_with_no_invented_findings(self):
        with mock.patch.object(osint, "_dns_step", lambda d: ({}, ["A: timed out"])), \
             mock.patch.object(osint, "_rdap_step", boom("RDAP: rate limited", 429, "rate_limited")), \
             mock.patch.object(osint, "_ct_step", boom("crt.sh timed out", 504, "timeout")):
            op = osint.start_domain_investigation("example.com")
            done = operations.wait_for(op["id"], 20)
        self.assertEqual(done["status"], "failed")
        self.assertIn("rate limited", done["error"])
        self.assertIn("timed out", done["error"])
        self.assertEqual(findings.list_findings(operation_id=op["id"]), [])

    def test_success_builds_findings_with_provenance_and_graph(self):
        c = cases.create_case("Graph case", scope="example.com", authorisation_ack=True)
        rdap = {"registrar": "Reg Inc", "registered": "1995-08-14", "expires": "2030-01-01", "nameservers": ["a.iana-servers.net"],
                "status": [], "last_changed": None, "ldh_name": "example.com", "resolved_via": "x"}
        with mock.patch.object(osint, "_dns_step", lambda d: ({"A": ["93.184.216.34"], "NS": ["a.iana-servers.net."]}, [])), \
             mock.patch.object(osint, "_rdap_step", lambda d: rdap), \
             mock.patch.object(osint, "_ct_step", lambda d: {"certificates_logged": 3, "distinct_names": ["www.example.com"], "issuers": {}, "query_url": "u"}):
            done = operations.wait_for(osint.start_domain_investigation("Example.com", c["id"])["id"], 20)
        self.assertEqual((done["status"], done["target"]), ("completed", "example.com"))
        fnds = findings.list_findings(case_id=c["id"])
        self.assertEqual({f["kind"] for f in fnds}, {"dns", "rdap", "certificate_transparency"})
        self.assertTrue(all(f["retrieved_at"] and f["source"] and f["review_status"] == "pending" for f in fnds))
        steps = {s["step"]: s["status"] for s in done["result"]["steps"]}
        self.assertEqual((steps["tls"], steps["http"]), ("skipped", "skipped"))
        g = findings.graph(case_id=c["id"])
        self.assertTrue({"investigates", "resolves_to", "uses_nameserver", "ct_logged_name"} <= {e["rel_type"] for e in g["edges"]})
        self.assertTrue(all(e["source"] for e in g["edges"]), "every edge must carry its source")

    def test_cancel_draft(self):
        op = operations.create("domain_investigation", "example.com", run=False)
        self.assertEqual(op["status"], "draft")
        self.assertEqual(operations.cancel(op["id"])["status"], "cancelled")
        with self.assertRaises(GhostError):
            operations.run_operation(op["id"])

    def test_interrupted_operations_recovered_as_failed(self):
        op = operations.create("domain_investigation", "example.com", run=False)
        with db() as c:
            c.execute("UPDATE operations SET status='running' WHERE id=?", (op["id"],))
        self.assertEqual(operations.recover_interrupted(), 1)
        got = operations.get(op["id"])
        self.assertEqual(got["status"], "failed")
        self.assertIn("Interrupted", got["error"])


class CertificateTransparencyFallbackTests(GhostTestCase):
    def test_falls_back_to_certspotter_when_crtsh_is_down(self):
        with mock.patch.object(osint, "_ct_crtsh", boom("crt.sh responded with HTTP 502", 502, "provider_error")), \
             mock.patch.object(osint, "_ct_certspotter", lambda d: {"provider": "certspotter", "certificates_logged": 2, "distinct_names": ["a.example.com"], "issuers": {}, "query_url": "u"}), \
             mock.patch("time.sleep", lambda s: None):
            data = osint._ct_step("example.com")
        self.assertEqual(data["provider"], "certspotter")
        self.assertIn("502", data["fallback_reason"])

    def test_reports_both_failures_when_everything_is_down(self):
        with mock.patch.object(osint, "_ct_crtsh", boom("crt.sh down", 502, "provider_error")), \
             mock.patch.object(osint, "_ct_certspotter", boom("certspotter down", 502, "provider_error")), mock.patch("time.sleep", lambda s: None):
            with self.assertRaises(GhostError) as e:
                osint._ct_step("example.com")
        self.assertIn("crt.sh down", e.exception.message)
        self.assertIn("certspotter down", e.exception.message)


class GeolocateAndSampleTests(GhostTestCase):
    def test_investigation_geolocates_resolved_ips_when_asked(self):
        from ghost.services import intel
        c = cases.create_case("Geo investigation")
        seen = {}

        def fake_geo(ips, case_id, op_id, check_cancel=lambda: None):
            seen["ips"] = ips
            return [{"ip": ip, "status": "ok", "label": "Somewhere"} for ip in ips]
        with mock.patch.object(osint, "_dns_step", lambda d: ({"A": ["93.184.216.34"], "AAAA": ["2606:2800::1"]}, [])), \
             mock.patch.object(osint, "_rdap_step", boom("x", 404, "not_found")), mock.patch.object(osint, "_ct_step", boom("x", 502, "provider_error")), \
             mock.patch.object(intel, "geolocate_ips", fake_geo):
            done = operations.wait_for(osint.start_domain_investigation("example.com", c["id"], geolocate=True)["id"], 20)
        self.assertEqual(done["status"], "completed")
        self.assertEqual(seen["ips"], ["93.184.216.34", "2606:2800::1"])
        self.assertEqual({s["step"]: s["status"] for s in done["result"]["steps"]}["geolocation"], "ok")

    def test_sample_loads_once_and_is_tagged(self):
        from ghost.services import sample
        started = {}
        with mock.patch.object(osint, "start_domain_investigation", lambda *a, **k: started.setdefault("op", {"ref": "OP"})), \
             mock.patch("ghost.services.intel.start_enrichment", lambda *a, **k: {"ref": "OP2"}):
            r = sample.load_sample()
            self.assertEqual(r["case"]["tags"], ["sample"])
            self.assertFalse(r["case"]["authorisation_ack"], "must not attest authorisation on the user's behalf")
            with self.assertRaises(GhostError) as e:
                sample.load_sample()
        self.assertEqual(e.exception.code, "already_loaded")


class FindingTests(GhostTestCase):
    def test_review_workflow(self):
        c = cases.create_case("Review case")
        with db() as conn:
            f = findings.add_finding(conn, kind="dns", title="t", source="s", case_id=c["id"])
        self.assertEqual(findings.set_review(f["id"], "confirmed")["review_status"], "confirmed")
        with self.assertRaises(GhostError):
            findings.set_review(f["id"], "maybe")
        with self.assertRaises(NotFound):
            findings.set_review(9999, "confirmed")

    def test_stale_findings_are_labelled(self):
        with db() as conn:
            findings.add_finding(conn, kind="dns", title="old", source="s", retrieved_at="2020-01-01T00:00:00.000000Z")
        self.assertEqual(findings.list_findings()[0]["freshness"], "stale")


class DnsWireTests(GhostTestCase):
    def test_rejects_malicious_compression_loop_and_truncation(self):
        from ghost import dnswire
        loop = b"\x00" * 12 + b"\xc0\x0c"
        with self.assertRaises(ValueError):
            dnswire.read_name(loop, 12)
        with self.assertRaises(ValueError):
            dnswire.read_name(b"\x05abc", 0)

    def test_roundtrip_of_a_synthetic_response(self):
        from ghost import dnswire
        from helpers import dns_response
        msg = dnswire.parse_response(dns_response("example.com", "93.184.216.34"))
        self.assertEqual((msg["response"], msg["rcode"]), (True, 0))
        self.assertEqual(msg["answers"][0]["data"], "93.184.216.34")

    def test_client_validates_txid_and_nxdomain(self):
        from ghost import dnsclient
        import os
        os.environ["GHOST_DNS_SERVER"] = "192.0.2.53"
        with mock.patch.object(dnsclient, "_exchange", side_effect=lambda s, p, t, to: __import__("struct").pack(">HHHHHH", t, 0x8183, 1, 0, 0, 0) + p[12:]):
            with self.assertRaises(dnsclient.NXDomain):
                dnsclient.resolve("nope.example", "A")
        with mock.patch.object(dnsclient, "_exchange", side_effect=lambda s, p, t, to: __import__("struct").pack(">HHHHHH", (t + 1) & 0xFFFF, 0x8180, 1, 0, 0, 0) + p[12:]):
            with self.assertRaises(GhostError):
                dnsclient.resolve("spoof.example", "A")


if __name__ == "__main__":
    unittest.main()
