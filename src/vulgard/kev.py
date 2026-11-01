from __future__ import annotations

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev() -> frozenset[str]:
    resp = httpx.get(KEV_URL, timeout=30, follow_redirects=True)
    resp.raise_for_status()
    return frozenset(v["cveID"] for v in resp.json().get("vulnerabilities", []))
