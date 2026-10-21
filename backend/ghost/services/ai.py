"""Optional AI analyst. Uses an OpenAI-compatible chat endpoint configured ONLY through the
environment (a local Ollama / llama.cpp server works). The endpoint is never taken from UI input.

Guard-rails: the model sees a bounded, serialised snapshot of the case and is instructed to cite
reference IDs and to say when evidence is missing. Output is always returned labelled as
model-generated and is never written back into findings or evidence.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from ..config import get_settings
from ..db import db, utcnow
from ..errors import GhostError, Unavailable
from . import audit, cases, evidence, findings, intel, system

TASKS = {
    "summarise": "Summarise what the case data shows. Group by theme. Cite finding/indicator/evidence reference IDs in square brackets.",
    "explain": "Explain the technical evidence in plain language for a non-specialist manager. Cite reference IDs.",
    "next_steps": "Suggest DEFENSIVE next investigative or remediation steps only. Each step must name the reference IDs that motivate it.",
    "draft_section": "Draft a 'Findings' report section from the confirmed findings. Mark anything unreviewed as unreviewed.",
    "gaps": "List uncertainty, missing evidence, unreviewed findings and checks that were NOT performed. Do not speculate beyond the data.",
}

SYSTEM_PROMPT = (
    "You are an analyst assistant inside a defensive OSINT / incident-response workstation. "
    "Use ONLY the case snapshot provided. If something is not in the snapshot, say it is not known. "
    "Never invent hosts, actors, attributions, CVEs, IP addresses or timestamps. "
    "Clearly separate (a) statements directly supported by cited records from (b) hypotheses, which you must prefix with 'HYPOTHESIS:'. "
    "Do not recommend offensive, intrusive or evasive actions. Be concise."
)


def status() -> dict[str, Any]:
    return system.ai_status()


def ping() -> dict[str, Any]:
    """One tiny completion to confirm the configured endpoint + model work (used by Settings → Test)."""
    s = get_settings()
    if not (s.ai_base_url and s.ai_model):
        raise Unavailable("Set the AI endpoint URL and model name first.", "ai_not_configured")
    headers = {"Content-Type": "application/json", **({"Authorization": f"Bearer {s.ai_api_key}"} if s.ai_api_key else {})}
    body = {"model": s.ai_model, "max_tokens": 8, "temperature": 0, "messages": [{"role": "user", "content": "Reply with the single word OK."}]}
    try:
        r = httpx.post(s.ai_base_url.rstrip("/") + "/chat/completions", headers=headers, json=body, timeout=60)
    except httpx.TimeoutException:
        return {"ok": False, "status": "timeout", "message": "The AI endpoint did not answer within 60 s (is the model still loading?)."}
    except httpx.HTTPError as exc:
        return {"ok": False, "status": "unreachable", "message": f"Could not reach {s.ai_base_url} ({type(exc).__name__}). Is the model server running?"}
    if r.status_code in (401, 403):
        return {"ok": False, "status": "auth_error", "message": "The endpoint rejected the API key.", "http_status": r.status_code}
    if r.status_code == 404:
        return {"ok": False, "status": "not_found", "message": "Endpoint or model not found. Check the URL ends with /v1 and the model name exists.", "http_status": 404}
    if r.status_code != 200:
        return {"ok": False, "status": "error", "message": f"Endpoint returned HTTP {r.status_code}.", "http_status": r.status_code}
    try:
        reply = r.json()["choices"][0]["message"]["content"].strip()[:80]
    except (KeyError, IndexError, ValueError):
        return {"ok": False, "status": "bad_response", "message": "The endpoint answered, but not in OpenAI chat format."}
    return {"ok": True, "status": "ok", "message": f"Model replied: \u201c{reply}\u201d", "http_status": 200}


def _snapshot(case_id: int) -> tuple[dict[str, Any], list[str]]:
    case = cases.get_case(case_id)
    fnds = findings.list_findings(case_id=case_id, limit=60)
    inds = intel.list_indicators(case_id=case_id, limit=60)
    evid = evidence.list_evidence(case_id=case_id, limit=40)
    snap = {
        "case": {k: case[k] for k in ("ref", "name", "objective", "scope", "status", "priority", "tags")},
        "findings": [{"ref": f["ref"], "kind": f["kind"], "title": f["title"], "summary": f["summary"], "source": f["source"],
                      "retrieved_at": f["retrieved_at"], "confidence": f["confidence"], "review": f["review_status"],
                      "freshness": f["freshness"], "data": json.dumps(f["data"], default=str)[:900]} for f in fnds if f["review_status"] != "dismissed"],
        "indicators": [{"ref": i["ref"], "type": i["type"], "value": i["value"], "severity": i["severity"], "confidence": i["confidence"], "reasoning": i["reasoning"]} for i in inds],
        "evidence": [{"ref": e["ref"], "name": e["name"], "sha256": e["sha256"], "verified": e["last_verify_result"]} for e in evid],
    }
    refs = [f["ref"] for f in snap["findings"]] + [i["ref"] for i in snap["indicators"]] + [e["ref"] for e in snap["evidence"]]
    return snap, refs


def run(case_id: int, task: str, question: str = "") -> dict[str, Any]:
    if task not in TASKS:
        raise GhostError(f"task must be one of {', '.join(TASKS)}", 422, "validation")
    s = get_settings()
    if not (s.ai_base_url and s.ai_model):
        raise Unavailable(status()["setup"], "ai_not_configured")
    snap, refs = _snapshot(case_id)
    if not snap["findings"] and not snap["indicators"] and not snap["evidence"]:
        raise GhostError("This case has no findings, indicators or evidence yet — nothing to analyse.", 422, "no_data")
    prompt = f"TASK: {TASKS[task]}\n" + (f"ANALYST QUESTION: {question[:500]}\n" if question.strip() else "") + "CASE SNAPSHOT (JSON):\n" + json.dumps(snap, default=str)
    headers = {"Content-Type": "application/json"}
    if s.ai_api_key:
        headers["Authorization"] = f"Bearer {s.ai_api_key}"
    body = {"model": s.ai_model, "temperature": 0.2,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]}
    url = s.ai_base_url.rstrip("/") + "/chat/completions"
    try:
        resp = httpx.post(url, headers=headers, json=body, timeout=180)
    except httpx.TimeoutException:
        raise GhostError("The AI provider timed out", 504, "timeout")
    except httpx.HTTPError as exc:
        raise Unavailable(f"Could not reach the AI provider at {s.ai_base_url}: {type(exc).__name__}", "ai_unreachable")
    if resp.status_code != 200:
        raise GhostError(f"AI provider returned HTTP {resp.status_code}", 502, "provider_error")
    try:
        text = resp.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError):
        raise GhostError("AI provider returned an unexpected response shape", 502, "provider_error")
    with db() as c:
        audit.record(c, "ai.generate", entity_type="case", entity_id=case_id, case_id=case_id,
                     detail={"task": task, "model": s.ai_model, "grounding_records": len(refs)})
    return {"label": "MODEL-GENERATED — NOT VERIFIED", "task": task, "model": s.ai_model, "text": text,
            "grounding_refs": refs, "generated_at": utcnow(),
            "notice": "Treat as hypotheses. Verify against the cited records before relying on or reporting any statement."}
