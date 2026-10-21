import json
import time
import unittest
from unittest import mock

import httpx
from click.testing import CliRunner

from ghost import config
from ghost.api.main import app as flask_app, startup
from ghost.cli import app as cli
from ghost.db import db
from ghost.services import findings
from base import GhostTestCase
from helpers import classic_pcap


class ApiTests(GhostTestCase):
    def setUp(self):
        super().setUp()
        startup()
        self.c = flask_app.test_client()

    def wait(self, op_id, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            op = self.c.get(f"/api/operations/{op_id}").get_json()
            if op["status"] in ("completed", "failed", "cancelled"):
                return op
            time.sleep(0.1)
        self.fail("operation did not finish")

    def test_status_reflects_reality(self):
        s = self.c.get("/api/status").get_json()
        self.assertTrue(s["database"]["ok"])
        self.assertGreaterEqual(s["database"]["schema_version"], 1)
        tshark = next(t for t in s["tools"] if t["id"] == "tshark")
        self.assertTrue((not tshark["installed"]) or tshark["path"])
        self.assertTrue(all(not p["configured"] for p in s["providers"]))
        self.assertFalse(s["ai"]["configured"])
        self.assertEqual(s["vault"]["encryption"], "disabled")

    def test_map_is_bundled_by_default_and_referrer_is_sent_cross_origin(self):
        cfg = self.c.get("/api/config").get_json()
        self.assertEqual(cfg["map"]["tile_url"], "", "default basemap must be bundled vector (no third-party tiles)")
        self.assertEqual(self.c.get("/api/health").headers["Referrer-Policy"], "strict-origin-when-cross-origin")
        self.setenv(GHOST_MAP_TILE_URL="https://tiles.example/{z}/{x}/{y}.png")
        self.assertEqual(self.c.get("/api/config").get_json()["map"]["tile_url"], "https://tiles.example/{z}/{x}/{y}.png")

    def test_graph_limit_parameter(self):
        for i in range(5):
            self.c.post("/api/cases", json={"name": f"Graph limit {i}"})
        from ghost.db import db
        from ghost.services import findings
        with db() as conn:
            for i in range(8):
                findings.upsert_entity(conn, "domain", f"d{i}.example")
        self.assertEqual(len(self.c.get("/api/graph?limit=3").get_json()["nodes"]), 3)
        self.assertEqual(len(self.c.get("/api/graph").get_json()["nodes"]), 8)

    def test_secrets_never_serialised(self):
        self.setenv(VIRUSTOTAL_API_KEY="SUPERSECRETKEY123")
        for path in ("/api/status", "/api/config", "/api/intel/providers"):
            self.assertNotIn("SUPERSECRETKEY123", self.c.get(path).get_data(as_text=True))

    def test_case_crud(self):
        r = self.c.post("/api/cases", json={"name": "HTTP case", "scope": "a.example", "authorisation_ack": True, "tags": ["x"]})
        self.assertEqual(r.status_code, 201)
        cid = r.get_json()["id"]
        self.assertEqual(self.c.patch(f"/api/cases/{cid}", json={"status": "active"}).get_json()["status"], "active")
        self.assertEqual(self.c.post(f"/api/cases/{cid}/notes", json={"body": "hello"}).status_code, 201)
        self.assertEqual(self.c.get("/api/cases?q=HTTP").get_json()[0]["id"], cid)
        self.assertEqual(self.c.post("/api/cases", json={"name": "x"}).status_code, 422)
        self.assertEqual(self.c.post("/api/cases", json={"name": "Valid", "tags": "nope"}).status_code, 422)
        self.assertEqual(self.c.get("/api/cases/9999").get_json()["error"]["code"], "not_found")

    def test_overview_comes_from_stored_records(self):
        empty = self.c.get("/api/command/overview").get_json()
        self.assertEqual(empty["metrics"], {"open_cases": 0, "findings_pending_review": 0, "high_priority_indicators": 0, "recent_completed_analyses": 0})
        self.assertEqual((empty["events"], empty["geo"]), ([], []))
        self.assertEqual(sum(sum(v for k, v in d.items() if k != "date") for d in empty["timeline"]), 0)
        self.c.post("/api/cases", json={"name": "Counted case"})
        after = self.c.get("/api/command/overview").get_json()
        self.assertEqual(after["metrics"]["open_cases"], 1)
        self.assertEqual(after["recent_cases"][0]["name"], "Counted case")
        self.assertEqual(after["events"][0]["action"], "case.create")

    def test_pcap_upload_flow(self):
        import io
        r = self.c.post("/api/network/analyze", data={"file": (io.BytesIO(classic_pcap()), "t.pcap"), "engine": "builtin"}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 202, r.get_data(as_text=True))
        op = self.wait(r.get_json()["id"])
        self.assertEqual((op["status"], op["result"]["analysis"]["packets"]), ("completed", 5))
        dl = self.c.get(f"/api/operations/{op['id']}/download")
        self.assertTrue(dl.headers["Content-Disposition"].startswith("attachment"))
        self.assertEqual(json.loads(dl.get_data(as_text=True))["result"]["engine"], "builtin")
        bad = self.c.post("/api/network/analyze", data={"file": (io.BytesIO(b"MZ not a capture"), "x.pcap")}, content_type="multipart/form-data")
        self.assertEqual((bad.status_code, bad.get_json()["error"]["code"]), (415, "unsupported_type"))
        self.assertEqual(self.c.post("/api/network/analyze", data={}, content_type="multipart/form-data").status_code, 422)

    def test_evidence_download_is_never_served_as_html(self):
        import io
        r = self.c.post("/api/evidence", data={"file": (io.BytesIO(b"<script>alert(1)</script>"), "a.html")}, content_type="multipart/form-data")
        eid = r.get_json()["id"]
        self.assertTrue(self.c.post(f"/api/evidence/{eid}/verify").get_json()["intact"])
        d = self.c.get(f"/api/evidence/{eid}/download")
        self.assertEqual(d.headers["Content-Type"], "application/octet-stream")
        self.assertEqual(d.headers["X-Content-Type-Options"], "nosniff")

    def test_report_view_has_restrictive_csp(self):
        cid = self.c.post("/api/cases", json={"name": "Report case"}).get_json()["id"]
        rep = self.c.post(f"/api/cases/{cid}/report").get_json()
        v = self.c.get(f"/api/reports/{rep['id']}/view")
        self.assertIn("default-src 'none'", v.headers["Content-Security-Policy"])
        self.assertIn("Recommendations", v.get_data(as_text=True))

    def test_cross_origin_state_change_rejected(self):
        r = self.c.post("/api/cases", json={"name": "CSRF attempt"}, headers={"Origin": "https://evil.example"})
        self.assertEqual((r.status_code, r.get_json()["error"]["code"]), (403, "forbidden_origin"))
        ok = self.c.post("/api/cases", json={"name": "Legit local"}, headers={"Origin": "http://localhost:5173"})
        self.assertEqual(ok.status_code, 201)
        self.assertEqual(ok.headers["Access-Control-Allow-Origin"], "http://localhost:5173")

    def test_unexpected_host_header_rejected(self):
        r = self.c.get("/api/health", headers={"Host": "attacker.example"})
        self.assertEqual(r.status_code, 400)

    def test_ai_unconfigured_is_a_proper_unavailable_state(self):
        cid = self.c.post("/api/cases", json={"name": "AI case"}).get_json()["id"]
        r = self.c.post("/api/ai/analyse", json={"case_id": cid, "task": "summarise"})
        self.assertEqual(r.status_code, 503)
        self.assertIn("GHOST_AI_BASE_URL", r.get_json()["error"]["message"])

    def test_ai_output_is_labelled_and_grounded(self):
        self.setenv(GHOST_AI_BASE_URL="http://localhost:11434/v1", GHOST_AI_MODEL="test-model")
        cid = self.c.post("/api/cases", json={"name": "AI case"}).get_json()["id"]
        with db() as c:
            findings.add_finding(c, kind="dns", title="DNS", source="s", case_id=cid)
        seen = {}

        def fake_post(url, headers=None, json=None, timeout=None):
            seen["body"] = json
            return httpx.Response(200, json={"choices": [{"message": {"content": "HYPOTHESIS: something"}}]})

        with mock.patch("ghost.services.ai.httpx.post", fake_post):
            out = self.c.post("/api/ai/analyse", json={"case_id": cid, "task": "gaps"}).get_json()
        self.assertTrue(out["label"].startswith("MODEL-GENERATED"))
        self.assertIn("FND", out["grounding_refs"][0])
        self.assertIn("Never invent", seen["body"]["messages"][0]["content"])


class CliTests(GhostTestCase):
    def setUp(self):
        super().setUp()
        self.r = CliRunner()

    def invoke(self, *args):
        return self.r.invoke(cli, list(args))

    def test_status_json(self):
        res = self.invoke("status", "--json")
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertTrue(json.loads(res.output)["database"]["ok"])

    def test_case_create_list_persistence(self):
        res = self.invoke("case", "create", "CLI case", "--scope", "x.example", "--authorised", "--tag", "t1", "--json")
        self.assertEqual(res.exit_code, 0, res.output)
        ref = json.loads(res.output)["ref"]
        self.assertEqual([c["ref"] for c in json.loads(self.invoke("case", "list", "--json").output)], [ref])
        self.assertEqual(self.invoke("case", "create", "No scope", "--authorised").exit_code, 1)

    def test_error_exit_codes(self):
        self.assertEqual(self.invoke("case", "show", "999").exit_code, 1)
        res = self.invoke("intel", "enrich", "evil.com")
        self.assertEqual(res.exit_code, 3)
        self.assertIn("No enrichment provider", res.output)
        self.assertEqual(self.invoke("osint", "domain", "http://bad").exit_code, 1)
        self.assertEqual(self.invoke("network", "analyze", "nope.pcap").exit_code, 1)
        self.assertEqual(self.invoke("no-such-command").exit_code, 2)

    def test_network_analyze_runs_real_analysis(self):
        from pathlib import Path
        p, out = Path(self.tmp) / "c.pcap", Path(self.tmp) / "out.json"
        p.write_bytes(classic_pcap())
        res = self.invoke("network", "analyze", str(p), "--engine", "builtin", "--output", str(out))
        self.assertEqual(res.exit_code, 0, res.output)
        saved = json.loads(out.read_text())
        self.assertEqual(saved["analysis"]["packets"], 5)
        self.assertTrue(saved["file"]["sha256"])

    def test_evidence_and_report_roundtrip(self):
        from pathlib import Path
        case = json.loads(self.invoke("case", "create", "Roundtrip", "--json").output)
        f = Path(self.tmp) / "e.bin"
        f.write_bytes(b"evidence")
        ev = json.loads(self.invoke("evidence", "add", str(f), "--case", str(case["id"]), "--json").output)
        self.assertEqual(self.invoke("evidence", "verify", str(ev["id"])).exit_code, 0)
        next(config.get_settings().vault_dir.glob("*.bin")).write_bytes(b"changed")
        self.assertEqual(self.invoke("evidence", "verify", str(ev["id"])).exit_code, 4)
        out = Path(self.tmp) / "r.html"
        self.assertEqual(self.invoke("report", "generate", str(case["id"]), "--output", str(out)).exit_code, 0)
        self.assertIn("Recommendations", out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
