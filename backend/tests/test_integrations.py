import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from ghost import config
from ghost.api.main import app as flask_app, startup
from ghost.db import db
from ghost.errors import GhostError, Unavailable
from ghost.services import ai, cases, findings, integrations, intel, system
from base import GhostTestCase

KEY = "vt_ABCDEFGH1234567890"


class IntegrationBase(GhostTestCase):
    def setUp(self):
        super().setUp()
        self.env = Path(self.tmp) / ".env"
        config.reset_settings(data_dir=self.data_dir, env_file=self.env)


class SaveTests(IntegrationBase):
    def test_saves_without_echoing_secret_and_applies_live(self):
        self.env.write_text("# my notes\nGHOST_PORT=9000\n", encoding="utf-8")
        st = integrations.save({"VIRUSTOTAL_API_KEY": KEY})
        row = next(r for r in st if r["env"] == "VIRUSTOTAL_API_KEY")
        self.assertTrue(row["configured"])
        self.assertEqual(row["hint"], "••••7890")
        self.assertNotIn(KEY, json.dumps(st))
        text = self.env.read_text(encoding="utf-8")
        self.assertIn("# my notes", text)
        self.assertIn("GHOST_PORT=9000", text)
        self.assertIn(f"VIRUSTOTAL_API_KEY={KEY}", text)
        self.assertTrue(next(p for p in system.providers() if p["id"] == "virustotal")["configured"], "must take effect without restart")
        self.assertIn("virustotal", intel.available_providers("url"))

    def test_replacing_updates_in_place_and_null_removes(self):
        self.env.write_text(f"VIRUSTOTAL_API_KEY=oldoldoldold\nOTHER=1\n", encoding="utf-8")
        integrations.save({"VIRUSTOTAL_API_KEY": KEY})
        self.assertEqual(self.env.read_text().count("VIRUSTOTAL_API_KEY"), 1)
        self.assertIn(KEY, self.env.read_text())
        integrations.save({"VIRUSTOTAL_API_KEY": None})
        self.assertNotIn("VIRUSTOTAL_API_KEY", self.env.read_text())
        self.assertIn("OTHER=1", self.env.read_text())
        self.assertFalse(next(p for p in system.providers() if p["id"] == "virustotal")["configured"])

    def test_validation_blocks_injection_and_writes_nothing(self):
        self.env.write_text("KEEP=me\n", encoding="utf-8")
        before = self.env.read_text()
        bad = [("VIRUSTOTAL_API_KEY", "abc\nEVIL=1"), ("VIRUSTOTAL_API_KEY", "short"), ("VIRUSTOTAL_API_KEY", "has space inside 12345"),
               ("GHOST_AI_BASE_URL", "file:///etc/passwd"), ("GHOST_AI_BASE_URL", "http://u:p@host/v1"), ("GHOST_AI_BASE_URL", "javascript:alert(1)"),
               ("GHOST_AI_MODEL", "bad;rm -rf"), ("GHOST_TSHARK_PATH", "/definitely/not/here/tshark"), ("GHOST_PORT", "1234"), ("VIRUSTOTAL_API_KEY", 12345678)]
        for k, v in bad:
            with self.subTest(k=k, v=v), self.assertRaises(GhostError):
                integrations.save({k: v})
        # one bad value must reject the whole batch (atomic), including a valid sibling
        with self.assertRaises(GhostError):
            integrations.save({"ABUSEIPDB_API_KEY": "validvalidvalid1", "GHOST_AI_BASE_URL": "ftp://x"})
        self.assertEqual(self.env.read_text(), before)
        self.assertNotIn("ABUSEIPDB_API_KEY", os.environ)

    def test_model_name_with_spaces_is_quoted_and_loadable(self):
        integrations.save({"GHOST_AI_MODEL": "my model 1", "GHOST_AI_BASE_URL": "http://localhost:11434/v1"})
        self.assertIn('GHOST_AI_MODEL="my model 1"', self.env.read_text())
        self.assertTrue(system.ai_status()["configured"])

    def test_no_temp_files_left_behind(self):
        integrations.save({"IPINFO_TOKEN": "tokentokentoken1"})
        self.assertEqual([p.name for p in Path(self.tmp).iterdir() if p.name.startswith(".env.") and p.name.endswith(".tmp")], [])

    def test_audit_records_key_names_never_values(self):
        integrations.save({"VIRUSTOTAL_API_KEY": KEY})
        with db() as c:
            row = c.execute("SELECT detail FROM audit WHERE action='settings.integrations'").fetchone()
        self.assertIn("VIRUSTOTAL_API_KEY", row["detail"])
        self.assertNotIn(KEY, row["detail"])


class ApiTests(IntegrationBase):
    def setUp(self):
        super().setUp()
        startup()
        self.c = flask_app.test_client()

    def test_api_never_returns_secrets_and_guards_origin(self):
        r = self.c.put("/api/settings/integrations", json={"values": {"VIRUSTOTAL_API_KEY": KEY}})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(KEY, r.get_data(as_text=True))
        self.assertNotIn(KEY, self.c.get("/api/settings/integrations").get_data(as_text=True))
        self.assertNotIn(KEY, self.c.get("/api/status").get_data(as_text=True))
        evil = self.c.put("/api/settings/integrations", json={"values": {"VIRUSTOTAL_API_KEY": "attackerattackerkey"}}, headers={"Origin": "https://evil.example"})
        self.assertEqual(evil.status_code, 403)
        self.assertIn(KEY, self.env.read_text())
        self.assertEqual(self.c.put("/api/settings/integrations", json={"values": "nope"}).status_code, 422)
        self.assertEqual(self.c.put("/api/settings/integrations", json={"values": {"GHOST_PORT": "1"}}).status_code, 422)

    def test_test_endpoint_reports_honestly(self):
        self.assertEqual(self.c.post("/api/settings/integrations/test", json={"target": "virustotal"}).status_code, 503)
        integrations.save({"VIRUSTOTAL_API_KEY": KEY})
        for status, ok, word in (("ok", True, "accepted"), ("auth_error", False, "REJECTED"), ("rate_limited", True, "rate-limiting"), ("error", False, "boom")):
            res = intel.ProviderResult(provider="virustotal", status=status, http_status=401 if status == "auth_error" else 200, error="boom")
            with mock.patch.object(intel, "query_virustotal", lambda t, v, res=res: res):
                out = self.c.post("/api/settings/integrations/test", json={"target": "virustotal"}).get_json()
            self.assertEqual(out["ok"], ok, status)
            self.assertIn(word, out["message"])
        self.assertEqual(self.c.post("/api/settings/integrations/test", json={"target": "nope"}).status_code, 422)

    def test_test_endpoint_blocked_in_field_mode(self):
        integrations.save({"VIRUSTOTAL_API_KEY": KEY})
        system.set_field_mode(True)
        r = self.c.post("/api/settings/integrations/test", json={"target": "virustotal"})
        self.assertEqual((r.status_code, r.get_json()["error"]["code"]), (503, "field_mode"))


class _Handler(BaseHTTPRequestHandler):
    mode = "ok"
    seen: dict = {}

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        type(self).seen = {"path": self.path, "auth": self.headers.get("Authorization"), "body": body}
        code, payload = {
            "ok": (200, {"choices": [{"message": {"content": "OK. HYPOTHESIS: the case has one DNS finding [FND]."}}]}),
            "unauthorised": (401, {"error": "bad key"}),
            "missing": (404, {"error": "model not found"}),
            "weird": (200, {"unexpected": True}),
        }[type(self).mode]
        raw = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class AiAgainstRealServerTests(IntegrationBase):
    """The AI client talks to a genuine HTTP server (no patched httpx) so request shape and parsing are really exercised."""

    def setUp(self):
        super().setUp()
        self.srv = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)  # cleanups run LIFO: shutdown the loop first, then close the socket
        self.addCleanup(self.srv.shutdown)
        self.url = f"http://127.0.0.1:{self.srv.server_port}/v1"
        _Handler.mode = "ok"

    def test_ping_states(self):
        integrations.save({"GHOST_AI_BASE_URL": self.url, "GHOST_AI_MODEL": "tiny-model"})
        out = ai.ping()
        self.assertTrue(out["ok"])
        self.assertEqual(_Handler.seen["path"], "/v1/chat/completions")
        self.assertEqual(_Handler.seen["body"]["model"], "tiny-model")
        self.assertIsNone(_Handler.seen["auth"], "no key configured -> no Authorization header")
        for mode, status in (("unauthorised", "auth_error"), ("missing", "not_found"), ("weird", "bad_response")):
            _Handler.mode = mode
            self.assertEqual(ai.ping()["status"], status, mode)
        integrations.save({"GHOST_AI_BASE_URL": "http://127.0.0.1:9/v1"})
        self.assertEqual(ai.ping()["status"], "unreachable")

    def test_ping_without_config_is_unavailable(self):
        with self.assertRaises(Unavailable):
            ai.ping()

    def test_full_analysis_end_to_end_is_labelled_and_grounded(self):
        integrations.save({"GHOST_AI_BASE_URL": self.url, "GHOST_AI_MODEL": "tiny-model", "GHOST_AI_API_KEY": "localkeylocalkey1"})
        c = cases.create_case("AI e2e")
        with db() as conn:
            findings.add_finding(conn, kind="dns", title="DNS records", source="DNS", case_id=c["id"], summary="A x2")
        out = ai.run(c["id"], "gaps", "what is missing?")
        self.assertTrue(out["label"].startswith("MODEL-GENERATED"))
        self.assertIn("HYPOTHESIS", out["text"])
        self.assertTrue(out["grounding_refs"][0].startswith("GHO-FND"))
        self.assertEqual(_Handler.seen["auth"], "Bearer localkeylocalkey1")
        prompt = _Handler.seen["body"]["messages"][1]["content"]
        self.assertIn("what is missing?", prompt)
        self.assertIn("DNS records", prompt)
        self.assertNotIn("localkeylocalkey1", json.dumps(out))


if __name__ == "__main__":
    unittest.main()
