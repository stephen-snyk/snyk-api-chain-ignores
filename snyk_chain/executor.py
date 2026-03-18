"""
Execute Snyk API calls with pagination, rate limiting, and session reuse.
"""

from __future__ import annotations

import time
from typing import Any

import requests


class SnykExecutor:
    def __init__(
        self,
        base_url: str = "https://api.snyk.io",
        api_token: str = "",
        api_version: str = "2024-10-15",
    ):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.api_version = api_version
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {api_token}",
            "Content-Type": "application/vnd.api+json",
        })

    def _full_url(self, path: str, api: str = "rest") -> str:
        """Build full URL. REST paths are relative to /rest, V1 paths include /v1."""
        if path.startswith("http"):
            return path
        if path.startswith("/v1"):
            return f"{self.base_url}{path}"
        if api == "rest" and not path.startswith("/rest"):
            return f"{self.base_url}/rest{path}"
        return f"{self.base_url}{path}"

    def _is_rest_path(self, path: str) -> bool:
        """Whether this path uses REST versioning."""
        return "/rest" in path or path.startswith("/orgs") or path.startswith("/groups") or path.startswith("/tenants") or path.startswith("/custom")

    def _add_version_param(self, params: dict, path: str) -> dict:
        """Add version param for REST endpoints. Skip if path already has query params (e.g. pagination next link)."""
        if "?" in path:
            return params or {}
        if self._is_rest_path(path):
            p = dict(params or {})
            if "version" not in p:
                p["version"] = self.api_version
            return p
        return params or {}

    def request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        json: dict | None = None,
        api: str = "rest",
        max_retries: int = 3,
    ) -> requests.Response:
        """Make request with 429 backoff."""
        url = self._full_url(path, api=api)
        params = self._add_version_param(params or {}, path)

        for attempt in range(max_retries):
            resp = self.session.request(method, url, params=params, json=json, timeout=60)
            if resp.status_code != 429:
                return resp
            # Rate limited
            time.sleep(2 ** attempt)
        return resp

    def get_paginated(
        self,
        path: str,
        params: dict | None = None,
        api: str = "rest",
        data_key: str = "data",
    ) -> list[Any]:
        """
        Fetch all pages and return merged data list.
        Assumes JSON:API style: {data: [...], links: {next: "/path?..."}}.
        """
        all_data: list[Any] = []
        current_path = path
        current_params = self._add_version_param(params or {}, path)

        while current_path:
            url = self._full_url(current_path, api=api)
            resp = self.request("GET", current_path, params=current_params, api=api)
            resp.raise_for_status()
            body = resp.json()

            data = body.get(data_key, [])
            all_data.extend(data if isinstance(data, list) else [data])

            links = body.get("links", {})
            next_path = links.get("next") if isinstance(links, dict) else None
            if next_path:
                current_path = next_path
                current_params = None
            else:
                current_path = None

        return all_data

    def get_single_page(self, path: str, params: dict | None = None, api: str = "rest") -> dict:
        """Fetch single page, return full JSON."""
        resp = self.request("GET", path, params=params, api=api)
        resp.raise_for_status()
        return resp.json()
