from git_hunter.storage import Store


def test_queue_lifecycle(tmp_path):
    store = Store(tmp_path / "test.db")
    assert store.enqueue("https://github.com/a/b", "a/b", 5)
    assert not store.enqueue("https://github.com/a/b", "a/b", 5)
    row = store.claim_next()
    assert row["status"] == "pending"
    store.save_result(row["id"], {"anomaly_score": 10, "findings": []}, "# report", None)
    assert store.reports()[0]["status"] == "complete"