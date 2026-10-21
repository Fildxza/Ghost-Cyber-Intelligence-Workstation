import unittest
from unittest import mock

from ghost.errors import GhostError, Unavailable
from ghost.services import cases, findings, intel, operations
from base import GhostTestCase


class NormalisationTests(GhostTestCase):
    def test_normalisation(self):
        cases_ = [
            ("hxxps://Evil[.]Example[.]com/Path?q=1#frag", ("url", "https://evil.example.com/Path?q=1")),
            ("Evil[.]EXAMPLE.com", ("domain", "evil.example.com")),
            ("203.0.113.9", ("ip", "203.0.113.9")),
            ("2001:DB8::1", ("ip", "2001:db8::1")),
            ("D41D8CD98F00B204E9800998ECF8427E", ("hash", "d41d8cd98f00b204e9800998ecf8427e")),
            ("a" * 64, ("hash", "a" * 64)),
        ]
        for raw, expected in cases_:
            with self.subTest(raw=raw):
                self.assertEqual(intel.normalise(raw), expected)

    def test_invalid_indicators_rejected(self):
        for raw, typ in [("999.1.1.1", "ip"), ("zzzz", "hash"), ("abc123", "hash"), ("javascript:alert(1)", "url"),
                         ("http://u:p@x.com/", "url"), ("", None), ("not a domain", "domain")]:
            with self.subTest(raw=raw), self.assertRaises(GhostError):
                intel.normalise(raw, typ)

    def test_duplicate_detection_and_case_linking(self):
        c1, c2 = cases.create_case("One"), cases.create_case("Two")
        a = intel.add_indicator("Evil[.]com", case_id=c1["id"])
        b = intel.add_indicator("evil.com", case_id=c2["id"])
        self.assertEqual((a["duplicate"], b["duplicate"], a["id"] == b["id"]), (False, True, True))
        self.assertEqual(sorted(x["ref"] for x in intel.get_indicator(a["id"])["cases"]), sorted([c1["ref"], c2["ref"]]))
        self.assertEqual(len(intel.list_indicators()), 1)

    def test_export(self):
        intel.add_indicator("1.2.3.4")
        text, media, name = intel.export_indicators("csv")
        self.assertEqual(media, "text/csv")
        self.assertIn("1.2.3.4", text)
        self.assertTrue(name.endswith(".csv"))
        self.assertIn('"count": 1', intel.export_indicators("json")[0])
        with self.assertRaises(GhostError):
            intel.export_indicators("xml")


class ScoringTests(GhostTestCase):
    def test_score_is_explainable_and_never_says_safe(self):
        sev, conf, why = intel.score([{"provider": "virustotal", "status": "ok", "data": {"stats": {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 10}}}])
        self.assertEqual((sev, conf), ("informational", "low"))
        self.assertTrue(any("does not prove" in w for w in why))
        sev, conf, why = intel.score([{"provider": "virustotal", "status": "ok", "data": {"stats": {"malicious": 14, "harmless": 50}}},
                                      {"provider": "abuseipdb", "status": "ok", "data": {"abuseConfidenceScore": 92, "totalReports": 40}}])
        self.assertEqual((sev, conf), ("high", "high"))
        self.assertGreaterEqual(len(why), 3)
        self.assertEqual(intel.score([{"provider": "virustotal", "status": "rate_limited"}])[:2], ("unknown", "none"))


class EnrichmentTests(GhostTestCase):
    def enable(self):
        self.setenv(VIRUSTOTAL_API_KEY="test-key-not-real", ABUSEIPDB_API_KEY="test-key-not-real", IPINFO_TOKEN="test-token-not-real")

    def test_without_provider_is_honestly_unavailable(self):
        ind = intel.add_indicator("evil.com")
        with self.assertRaises(Unavailable) as e:
            intel.start_enrichment(ind["id"])
        self.assertEqual(e.exception.code, "no_provider")
        self.assertIn("VIRUSTOTAL_API_KEY", e.exception.message)
        self.assertEqual(operations.list_operations(), [])

    def test_end_to_end_with_mocked_providers(self):
        self.enable()
        c = cases.create_case("Enrich case")

        def fake_call(url, headers):
            if "virustotal" in url:
                return 200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 0, "harmless": 60}, "reputation": -4, "tags": []}}}, None
            if "abuseipdb" in url:
                return 200, {"data": {"abuseConfidenceScore": 80, "totalReports": 12, "countryCode": "XX"}}, None
            return 200, {"loc": "3.1390,101.6869", "city": "Kuala Lumpur", "country": "MY"}, None

        with mock.patch.object(intel, "_call", fake_call):
            ind = intel.add_indicator("93.184.216.34", case_id=c["id"])
            done = operations.wait_for(intel.start_enrichment(ind["id"])["id"], 20)
        self.assertEqual(done["status"], "completed", done["error"])
        got = intel.get_indicator(ind["id"])
        # VirusTotal lands in the "medium" band, AbuseIPDB in "high": sources disagree on band -> medium confidence
        self.assertEqual((got["severity"], got["confidence"]), ("high", "medium"))
        self.assertEqual(got["geo_label"], "Kuala Lumpur, MY")
        self.assertAlmostEqual(got["geo_lat"], 3.139, places=5)
        self.assertEqual({e["provider"] for e in got["enrichments"]}, {"virustotal", "abuseipdb", "ipinfo"})
        self.assertTrue(all("token" not in (e["source_url"] or "") for e in got["enrichments"]), "token must not be persisted")
        fnds = findings.list_findings(case_id=c["id"])
        self.assertEqual(len(fnds), 3)
        self.assertTrue(all(f["source_url"] for f in fnds))

    def test_private_ip_never_sent_to_third_parties(self):
        self.enable()
        with mock.patch.object(intel, "_call", side_effect=AssertionError("private IP must not be sent")):
            ind = intel.add_indicator("10.0.0.5")
            done = operations.wait_for(intel.start_enrichment(ind["id"])["id"], 20)
        self.assertEqual(done["status"], "failed")
        self.assertIn("skipped", done["error"])

    def test_provider_errors_are_surfaced(self):
        self.enable()
        with mock.patch.object(intel, "_call", lambda url, headers: (429, None, None)):
            ind = intel.add_indicator("evil.com")
            done = operations.wait_for(intel.start_enrichment(ind["id"])["id"], 20)
        self.assertEqual(done["status"], "failed")
        self.assertIn("rate_limited", done["error"])
        self.assertEqual(intel.get_indicator(ind["id"])["severity"], "unknown")


if __name__ == "__main__":
    unittest.main()
