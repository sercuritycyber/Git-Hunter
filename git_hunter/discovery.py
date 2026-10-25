from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .storage import Store


LOGGER = logging.getLogger(__name__)
SEARCH_INTERVAL_SECONDS = 6.5


class GitHubClient:
    def __init__(self, token: str | None = None, max_retries: int = 3) -> None:
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.max_retries = max_retries
        self._last_search_at = 0.0

    def _request(self, url: str) -> Any:
        request = urllib.request.Request(url)
        request.add_header("Accept", "application/vnd.github+json")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)

    @staticmethod
    def _retry_delay(error: urllib.error.HTTPError) -> float:
        retry_after = error.headers.get("retry-after")
        if retry_after:
            try:
                return max(float(retry_after), 0.0)
            except ValueError:
                pass
        reset = int(error.headers.get("x-ratelimit-reset", time.time() + 60))
        return max(reset - time.time(), 0.0) + 2.0

    def get(self, path: str, attempt: int = 0) -> Any:
        try:
            return self._request(f"https://api.github.com/{path}")
        except urllib.error.HTTPError as error:
            if error.code not in {403, 429} or attempt >= self.max_retries:
                LOGGER.error("[-] GitHub request failed with HTTP %s: %s", error.code, path)
                raise
            delay = self._retry_delay(error)
            LOGGER.warning("[*] GitHub rate limit hit; retrying in %.1fs", delay)
            time.sleep(delay)
            return self.get(path, attempt + 1)

    def raw(self, url: str) -> str:
        request = urllib.request.Request(url)
        request.add_header("Accept", "text/plain")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read().decode("utf-8")

    def search(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        elapsed = time.monotonic() - self._last_search_at
        if elapsed < SEARCH_INTERVAL_SECONDS:
            time.sleep(SEARCH_INTERVAL_SECONDS - elapsed)
        self._last_search_at = time.monotonic()
        params = urllib.parse.urlencode({"q": query, "per_page": min(limit, 100), "sort": "updated"})
        LOGGER.info("[*] Searching GitHub for %s", query)
        return self.get(f"search/repositories?{params}").get("items", [])

    def related(self, repo: dict[str, Any]) -> list[dict[str, Any]]:
        owner = repo["owner"]["login"]
        related = self.get(f"users/{owner}/repos?per_page=100&sort=updated")
        if repo.get("forks_count", 0):
            related += self.get(f"repos/{repo['full_name']}/forks?per_page=100&sort=newest")
        return related

    def python_sources(self, full_name: str) -> dict[str, str]:
        tree = self.get(f"repos/{full_name}/git/trees/HEAD?recursive=1")
        sources: dict[str, str] = {}
        for item in tree.get("tree", []):
            path = item.get("path", "")
            if item.get("type") == "blob" and path.endswith(".py"):
                raw_path = urllib.parse.quote(path, safe="/")
                sources[path] = self.raw(f"https://raw.githubusercontent.com/{full_name}/HEAD/{raw_path}")
        return sources


def _priority(size: int) -> int:
    return max(1, 100_000 - min(size, 100_000))


def discover(store: Store, query: str, limit: int = 10, client: GitHubClient | None = None) -> int:
    client = client or GitHubClient()
    added = 0
    for seed in client.search(query, limit):
        candidates = [seed]
        candidates.extend(client.related(seed))
        for candidate in candidates:
            if candidate.get("archived") or candidate.get("size", 0) > 100_000:
                continue
            full_name = candidate.get("full_name")
            html_url = candidate.get("html_url")
            if not full_name or not html_url:
                continue
            if store.enqueue(html_url, full_name, _priority(candidate.get("size", 0))):
                added += 1
                LOGGER.info("[+] Queued %s", full_name)
    return added
