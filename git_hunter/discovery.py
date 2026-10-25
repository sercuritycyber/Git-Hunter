from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.error
import urllib.request
from typing import Any

from .storage import Store


class GitHubClient:
    def __init__(self, token: str | None = None, max_retries: int = 3) -> None:
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.max_retries = max_retries

    def _request(self, url: str) -> Any:
        request = urllib.request.Request(url)
        request.add_header("Accept", "application/vnd.github+json")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)

    def get(self, path: str, attempt: int = 0) -> Any:
        request = urllib.request.Request("https://api.github.com/" + path)
        request.add_header("Accept", "application/vnd.github+json")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code not in {403, 429} or attempt >= self.max_retries:
                raise
            retry_after = error.headers.get("Retry-After")
            if retry_after is not None:
                try:
                    delay = max(float(retry_after), 0)
                except ValueError:
                    delay = 60
            else:
                reset = int(error.headers.get("x-ratelimit-reset", time.time() + 60))
                delay = max(reset - time.time(), 0) + 2
            print(f"[!] GitHub rate limit hit. Retrying in {delay:.0f}s...")
            time.sleep(delay)
            return self.get(path, attempt + 1)

    def raw(self, url: str) -> str:
        request = urllib.request.Request(url)
        request.add_header("Accept", "text/plain")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read().decode("utf-8")

    def python_sources(self, full_name: str) -> dict[str, str]:
        tree = self.get(f"repos/{full_name}/git/trees/HEAD?recursive=1")
        sources = {}
        for item in tree.get("tree", []):
            path = item.get("path", "")
            if item.get("type") == "blob" and path.endswith(".py"):
                sources[path] = self.raw(f"https://raw.githubusercontent.com/{full_name}/HEAD/{urllib.parse.quote(path)}")
        return sources

    def search(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        params = urllib.parse.urlencode({"q": query, "per_page": min(limit, 100), "sort": "updated"})
        return self.get(f"search/repositories?{params}").get("items", [])

    def related(self, repo: dict[str, Any]) -> list[dict[str, Any]]:
        owner = repo["owner"]["login"]
        related = self.get(f"users/{owner}/repos?per_page=30&sort=updated")
        if repo.get("forks_count", 0):
            related += self.get(f"repos/{repo['full_name']}/forks?per_page=30&sort=newest")
        return related


def discover(store: Store, query: str, limit: int = 10, client: GitHubClient | None = None) -> int:
    client = client or GitHubClient()
    added = 0
    for repo in client.search(query, limit):
        candidates = [repo] + client.related(repo)
        for candidate in candidates:
            if candidate.get("archived") or candidate.get("size", 0) > 100_000:
                continue
            if store.enqueue(candidate["html_url"], candidate.get("full_name"), max(0, 100 - candidate.get("size", 0) / 1000)):
                added += 1
    return added