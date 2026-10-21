"""One-click sample investigation. Runs REAL operations (live DNS, RDAP, certificate transparency, geolocation,
DNS-posture enrichment) against example.com — a domain reserved by IANA for documentation. Nothing is fabricated;
the case is tagged `sample` so it is easy to find and archive. Passive only: no authorisation is declared on the user's behalf.
"""
from __future__ import annotations

from typing import Any

from ..db import db
from ..errors import GhostError
from . import cases, intel, osint

SAMPLE_DOMAIN = "example.com"


def load_sample() -> dict[str, Any]:
    with db() as c:
        existing = c.execute("SELECT id, ref FROM cases WHERE tags LIKE '%\"sample\"%' AND status != 'archived' LIMIT 1").fetchone()
    if existing:
        raise GhostError(f"A sample case already exists ({existing['ref']}). Archive it first to load another.", 409, "already_loaded")
    case = cases.create_case(
        f"Sample: {SAMPLE_DOMAIN} infrastructure review",
        objective="Demonstration case using real passive lookups against a domain reserved for documentation (example.com).",
        scope=SAMPLE_DOMAIN, authorisation_ack=False, priority="low", tags=["sample"])
    op = osint.start_domain_investigation(SAMPLE_DOMAIN, case["id"], active=False, geolocate=True)
    ind = intel.add_indicator(SAMPLE_DOMAIN, "domain", case["id"])
    enrich = intel.start_enrichment(ind["id"], case["id"])
    return {"case": case, "investigation": op, "enrichment": enrich}
