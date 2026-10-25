from git_hunter.discovery import wander_once
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
