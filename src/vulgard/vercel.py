"""Vercel REST client: the project scanner. httpx, token from deployments.vercel.token_env."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from .estate import Framework, ScanError, Sighting, VercelProject
from .policy import parse_time

API_URL = "https://api.vercel.com"
BUILDING = ("BUILDING", "INITIALIZING", "QUEUED")


class VercelError(RuntimeError):
    pass


def _when(value: int | str) -> datetime:
    """Vercel timestamps are epoch milliseconds; fixtures may use ISO strings."""
    if isinstance(value, str):
        return parse_time(value)
    return datetime.fromtimestamp(value / 1000, tz=UTC)


def sight_vercel_project(project: dict[str, Any], team_id: str) -> Sighting | None:
    """One /v9/projects entry -> Sighting of its production deployment, or None if it has never
    deployed to production. A custom production domain makes it protected."""
    prod = (project.get("targets") or {}).get("production")
    if not prod or not prod.get("createdAt"):
        return None
    link = project.get("link") or {}
    repo = f"{link['org']}/{link['repo']}" if link.get("org") and link.get("repo") else None
    domains = prod.get("alias") or []
    return Sighting(
        Framework.VERCEL,
        VercelProject(team_id, project["id"], project["name"]),
        project["name"],
        None,
        _when(prod["createdAt"]),
        repo_hint=repo,
        protected=any(not d.endswith(".vercel.app") for d in domains),
        in_progress=prod.get("readyState") in BUILDING,
    )


class Vercel:
    def __init__(self, token: str, team_id: str, base_url: str = API_URL):
        self._team_id = team_id
        self._http = httpx.Client(
            base_url=base_url, headers={"Authorization": f"Bearer {token}"}, timeout=30.0
        )

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        resp = self._http.get(path, params={"teamId": self._team_id, **params})
        if resp.status_code >= 400:
            raise VercelError(f"Vercel API {resp.status_code} on {path}: {resp.text[:200]}")
        return resp.json()

    def scan(self) -> list[Sighting]:
        try:
            return self._scan()
        except (VercelError, httpx.HTTPError) as e:
            raise ScanError(f"Vercel scan failed: {e}") from e

    def _scan(self) -> list[Sighting]:
        found: list[Sighting] = []
        params: dict[str, Any] = {"limit": 100}
        while True:
            data = self._get("/v9/projects", params)
            found += [
                s for p in data.get("projects", []) if (s := sight_vercel_project(p, self._team_id))
            ]
            nxt = (data.get("pagination") or {}).get("next")
            if not nxt:
                return found
            params = {"limit": 100, "until": nxt}

    def project(self, project_id: str) -> dict[str, Any] | None:
        resp = self._http.get(f"/v9/projects/{project_id}", params={"teamId": self._team_id})
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise VercelError(f"Vercel API {resp.status_code}: {resp.text[:200]}")
        return resp.json()

    def project_url(self, project: dict[str, Any]) -> str:
        return f"https://vercel.com/{self._team_id}/{project['name']}"

    def find_redeploy(self, project_id: str, request_id: str) -> str | None:
        data = self._get("/v6/deployments", {"projectId": project_id, "limit": 20})
        for d in data.get("deployments", []):
            if (d.get("meta") or {}).get("vulgardRequest") == request_id:
                return f"https://{d['url']}"
        return None

    def redeploy(self, project_id: str, request_id: str) -> str:
        """Rebuild the current production deployment, tagged with the request id."""
        project = self.project(project_id)
        if project is None:
            raise VercelError(f"Vercel project {project_id} no longer exists")
        prod = (project.get("targets") or {}).get("production") or {}
        if not prod.get("id"):
            raise VercelError(f"Vercel project {project['name']} has no production deployment")
        resp = self._http.post(
            "/v13/deployments",
            params={"teamId": self._team_id},
            json={
                "name": project["name"],
                "deploymentId": prod["id"],
                "target": "production",
                "meta": {"vulgardRequest": request_id},
            },
        )
        if resp.status_code >= 400:
            raise VercelError(f"Vercel redeploy {resp.status_code}: {resp.text[:200]}")
        return f"https://{resp.json()['url']}"

    def delete(self, project_id: str) -> str:
        project = self.project(project_id)
        if project is None:
            return f"https://vercel.com/{self._team_id}"
        resp = self._http.delete(f"/v9/projects/{project_id}", params={"teamId": self._team_id})
        if resp.status_code >= 400:
            raise VercelError(f"Vercel delete {resp.status_code}: {resp.text[:200]}")
        return self.project_url(project)
