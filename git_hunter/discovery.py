from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

from .storage import Store


class GitHubClient:
    def __init__(self, token: str | None = None) -> None:
        self.token = token or os.getenv("GITHUB_TOKEN")

    def get(self, path: str) -> Any:
        request = urllib.request.Request("https://api.github.com/" + path)
        request.add_header("Accept", "application/vnd.github+json")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)

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