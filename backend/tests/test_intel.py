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
        ind = intel.add_indicator("http://evil.example/x")  # URLs have no key-less provider
        with self.assertRaises(Unavailable) as e:
            intel.start_enrichment(ind["id"])
        self.assertEqual(e.exception.code, "no_provider")
        self.assertIn("VIRUSTOTAL_API_KEY", e.exception.message)
        self.assertEqual(operations.list_operations(), [])

    def test_end_to_end_with_mocked_providers(self):
        self.enable()
        c = cases.create_case("Enrich case")

        def fake_call(url, headers):
            if "ipwho.is" in url:
                return 200, {"success": True, "city": "Kuala Lumpur", "country": "Malaysia", "country_code": "MY", "latitude": 3.139, "longitude": 101.6869,
                             "connection": {"asn": 64500, "org": "Example Net"}, "timezone": {"id": "Asia/Kuala_Lumpur"}}, None
            if "internetdb" in url:
                return 200, {"ports": [80, 443], "hostnames": [], "cpes": [], "vulns": [], "tags": []}, None
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
        self.assertEqual({e["provider"] for e in got["enrichments"]}, {"virustotal", "abuseipdb", "ipinfo", "ipwho", "internetdb"})
        self.assertTrue(all("token" not in (e["source_url"] or "") for e in got["enrichments"]), "token must not be persisted")
        fnds = findings.list_findings(case_id=c["id"])
        self.assertEqual(len(fnds), 5)
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
            ind = intel.add_indicator("http://evil.example/x")
            done = operations.wait_for(intel.start_enrichment(ind["id"])["id"], 20)
        self.assertEqual(done["status"], "failed")
        self.assertIn("rate_limited", done["error"])
        self.assertEqual(intel.get_indicator(ind["id"])["severity"], "unknown")


class KeylessProviderTests(GhostTestCase):
    def test_providers_are_ready_without_any_key_and_say_where_data_goes(self):
        from ghost.services import system
        info = {p["id"]: p for p in system.providers()}
        for pid in ("ipwho", "internetdb", "circl-hashlookup", "dns-posture"):
            self.assertTrue(info[pid]["configured"] and not info[pid]["needs_key"] and not info[pid]["reputation"], pid)
        for pid in ("virustotal", "abuseipdb", "ipinfo"):
            self.assertFalse(info[pid]["configured"], pid)
        self.assertTrue(all(p["sends_to"] for p in info.values()))

    def test_context_only_sources_never_move_severity_and_say_so(self):
        res = [{"provider": "ipwho", "status": "ok", "data": {"city": "Kuala Lumpur", "country": "Malaysia", "org": "Example Net", "asn": 64500}},
               {"provider": "internetdb", "status": "ok", "data": {"ports": [22, 80], "vulns": ["CVE-2020-0001"], "tags": ["self-signed"]}}]
        sev, conf, why = intel.score(res)
        self.assertEqual((sev, conf), ("unknown", "none"))
        self.assertTrue(any("not “safe”" in w for w in why))
        self.assertTrue(any("Kuala Lumpur" in w and "context only" in w for w in why))
        self.assertTrue(any("1 CVE" in w for w in why))

    def test_geo_extraction_validates_coordinates(self):
        ok = {"provider": "ipwho", "data": {"latitude": 3.1, "longitude": 101.6, "city": "KL", "country": "MY"}}
        self.assertEqual(intel.extract_geo(ok), (3.1, 101.6, "KL, MY"))
        self.assertIsNone(intel.extract_geo({"provider": "ipwho", "data": {"latitude": 95, "longitude": 10}}))
        self.assertIsNone(intel.extract_geo({"provider": "ipwho", "data": {"latitude": "x", "longitude": 1}}))
        self.assertEqual(intel.extract_geo({"provider": "ipinfo", "data": {"loc": "1.5,2.5", "city": "A"}})[:2], (1.5, 2.5))

    def test_hash_and_ip_and_domain_enrichment_without_any_key(self):
        def fake_call(url, headers):
            if "hashlookup" in url:
                return 200, {"FileName": "eicar.com", "source": "NSRL", "hashlookup:trust": 100}, None
            if "ipwho.is" in url:
                return 200, {"success": True, "city": "San Jose", "country": "United States", "latitude": 37.3, "longitude": -121.9, "connection": {"org": "Google LLC", "asn": 15169}}, None
            return 404, None, None  # internetdb: nothing known
        posture = lambda t, v: intel.ProviderResult(provider="dns-posture", status="ok", source_url="dns://x", data={"notes": ["SPF present", "No DMARC record"]})
        with mock.patch.object(intel, "_call", fake_call), mock.patch.dict(intel.PROVIDERS, {"dns-posture": (lambda s: True, ("domain",), posture)}):
            for value, expect in (("44d88612fea8a8f36de82e1278abb02f", "Known file 'eicar.com'"), ("8.8.8.8", "San Jose"), ("example.org", "No DMARC record")):
                ind = intel.add_indicator(value)
                done = operations.wait_for(intel.start_enrichment(ind["id"])["id"], 20)
                self.assertEqual(done["status"], "completed", (value, done["error"]))
                self.assertTrue(any(expect in line for line in done["result"]["reasoning"]), (value, done["result"]["reasoning"]))
        ip = intel.get_indicator(intel.list_indicators(type_="ip")[0]["id"])
        self.assertEqual(ip["geo_label"], "San Jose, United States")

    def test_geolocate_ips_creates_pins_and_skips_private(self):
        c = cases.create_case("Geo case")

        def fake(type_, value):
            return intel.ProviderResult(provider="ipwho", status="ok", source_url="https://ipwho.is/" + value,
                                        data={"city": "Singapore", "country": "Singapore", "latitude": 1.35, "longitude": 103.8, "org": "X", "asn": 1})
        with mock.patch.object(intel, "query_ipwho", fake):
            out = intel.geolocate_ips(["8.8.4.4", "10.0.0.1"], c["id"], None)
        self.assertEqual([o["status"] for o in out], ["ok", "skipped"])
        from ghost.services import command
        pins = command.overview()["geo"]
        self.assertEqual([(p["value"], p["label"]) for p in pins], [("8.8.4.4", "Singapore, Singapore")])
        self.assertEqual(findings.list_findings(case_id=c["id"])[0]["kind"], "geolocation")


if __name__ == "__main__":
    unittest.main()
