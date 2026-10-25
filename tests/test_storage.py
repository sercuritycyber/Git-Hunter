from git_hunter.storage import Store


def test_queue_lifecycle(tmp_path):
    store = Store(tmp_path / "test.db")
    assert store.enqueue("https://github.com/a/b", "a/b", 5)
    assert not store.enqueue("https://github.com/a/b", "a/b", 5)
    row = store.claim_next()
    assert row["status"] == "scanning"
    store.save_result(row["id"], {"anomaly_score": 75, "findings": []}, "# report")
    assert store.reports()[0]["status"] == "completed"


def test_safe_review_is_hidden(tmp_path):
    store = Store(tmp_path / "review.db")
    store.enqueue("https://github.com/a/b", "a/b", 5)
    row = store.claim_next()
    store.save_result(row["id"], {"anomaly_score": 75, "findings": []}, "# report")
    store.review(row["id"], "safe")
    assert store.reports() == []