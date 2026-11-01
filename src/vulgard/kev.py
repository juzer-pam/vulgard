from __future__ import annotations

import httpx


def fetch_kev(url: str) -> frozenset[str]:
    resp = httpx.get(url, timeout=30, follow_redirects=True)
    resp.raise_for_status()
    return frozenset(v["cveID"] for v in resp.json().get("vulnerabilities", []))
