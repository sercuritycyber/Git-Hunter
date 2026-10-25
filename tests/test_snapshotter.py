import io

from git_hunter.snapshotter import snapshot_repository


def test_snapshot_uses_dashboard_token(monkeypatch, tmp_path):
    requests = []

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    def fake_urlopen(request, timeout):
        requests.append(request)
        return Response(b"zip content")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    snapshot_repository("owner/repo", cold_storage=tmp_path, token="dashboard-token")

    assert requests[0].get_header("Authorization") == "Bearer dashboard-token"
