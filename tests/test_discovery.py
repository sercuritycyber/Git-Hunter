import io
import threading
import zipfile

from git_hunter.discovery import GitHubClient, run_wanderer, wander_once
from git_hunter.storage import Store


class FakeClient:
    def __init__(self):
        self.queries = []

    def search(self, query, limit):
        self.queries.append(query)
        return [{"owner": {"login": "alice"}}]

    def user_repositories(self, username):
        return [
            {"full_name": f"{username}/one", "html_url": f"https://github.com/{username}/one", "size": 1},
            {"full_name": f"{username}/two", "html_url": f"https://github.com/{username}/two", "size": 1},
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


def test_repository_sources_fetches_one_in_memory_zipball(monkeypatch):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as compressed:
        compressed.writestr("owner-repo-main/scan.py", "print('ok')")
        compressed.writestr("owner-repo-main/README.md", "not scanned")

    requests = []

    class Response(io.BytesIO):
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    def fake_urlopen(request, timeout):
        requests.append(request)
        return Response(archive.getvalue())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    sources = GitHubClient("sentinel-token").repository_sources("owner/repo", (".py",))

    assert len(requests) == 1
    assert requests[0].full_url.endswith("/repos/owner/repo/zipball/HEAD")
    assert requests[0].get_header("Authorization") == "Bearer sentinel-token"
    assert sources == {"scan.py": "print('ok')"}


class _BackpressureStore:
    def pending_count(self):
        return 10


class _FailingClient:
    def search(self, query, limit):
        raise AssertionError("GitHub API must not be called under backpressure")


def test_wanderer_skips_github_when_pending_queue_is_at_capacity():
    run_event = threading.Event()
    run_event.set()
    shutdown_event = threading.Event()
    messages = []

    def stop_after_status(message):
        messages.append(message)
        shutdown_event.set()

    run_wanderer(
        _BackpressureStore(),
        run_event,
        interval_seconds=0,
        client=_FailingClient(),
        limit=lambda: 10,
        status=stop_after_status,
        shutdown_event=shutdown_event,
    )

    assert messages == ["Backpressure active: 10 pending (limit 10)"]


def test_wanderer_caps_a_cycle_to_the_configured_batch_size(tmp_path):
    class ManyRepositories(FakeClient):
        def user_repositories(self, username):
            return [
                {
                    "full_name": f"{username}/{index}",
                    "html_url": f"https://github.com/{username}/{index}",
                    "size": 1,
                }
                for index in range(20)
            ]

    store = Store(tmp_path / "capped.db")
    assert wander_once(store, ManyRepositories(), set(), limit=3) == 3
    assert store.pending_count() == 3


def test_wanderer_uses_only_remaining_queue_capacity(tmp_path):
    class ManyRepositories(FakeClient):
        def user_repositories(self, username):
            return [
                {
                    "full_name": f"{username}/{index}",
                    "html_url": f"https://github.com/{username}/{index}",
                    "size": 1,
                }
                for index in range(20)
            ]

    store = Store(tmp_path / "capacity.db")
    for index in range(2):
        store.enqueue(
            f"https://github.com/existing/{index}",
            f"existing/{index}",
            1,
        )

    run_event = threading.Event()
    run_event.set()
    shutdown_event = threading.Event()
    messages = []

    def stop_after_status(message):
        messages.append(message)
        shutdown_event.set()

    run_wanderer(
        store,
        run_event,
        interval_seconds=0,
        client=ManyRepositories(),
        limit=lambda: 10,
        status=stop_after_status,
        shutdown_event=shutdown_event,
    )

    assert store.pending_count() == 10
    assert messages == ["Wanderer cycle queued 8 repositories"]
