import io

from git_hunter.discovery import GitHubClient, wander_once
from git_hunter.storage import Store


class FakeClient:
    def __init__(self):
        self.queries = []

    def search(self, query, limit):
        self.queries.append(query)
        return [{"owner": {"login": "alice"}}]

    def user_repositories(self, username):
        return [
            {
                "full_name": f"{username}/one",
                "html_url": f"https://github.com/{username}/one",
                "size": 1,
            },
            {
                "full_name": f"{username}/two",
                "html_url": f"https://github.com/{username}/two",
                "size": 1,
            },
        ]

    def user_relationships(self, username):
        return []


def test_random_seed_mode_generates_supported_search_query(tmp_path):
    store = Store(tmp_path / "discovery.db")
    client = FakeClient()

    assert wander_once(store, client, set(), seed_query="random") == 2
    assert any(query.startswith(("CVE pushed:", "PoC pushed:", "language:python pushed:")) for query in client.queries)


class _Response(io.BytesIO):
    headers = {}


def test_github_requests_send_the_configured_bearer_token(monkeypatch):
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        return _Response(b'{"items": []}')

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    GitHubClient("sentinel-token").search("language:python", 1)

    assert requests[0].get_header("Authorization") == "Bearer sentinel-token"
