from git_hunter.storage import Store


def test_queue_lifecycle(tmp_path):
    store = Store(tmp_path / "test.db")
    assert store.enqueue("a/b", "https://github.com/a/b", 5, "search_seed")
    assert not store.enqueue("a/b", "https://github.com/a/b", 5, "search_seed")
    row = store.claim_next()
    assert row["status"] == "analyzing"
    store.save_result(row["full_name"], {"anomaly_score": 75, "findings": []}, "# report", None)
    assert store.reports()[0]["status"] == "completed"
    assert store.reports()[0]["review_status"] == "awaiting_review"


def test_safe_review_is_hidden(tmp_path):
    store = Store(tmp_path / "review.db")
    store.enqueue("a/b", "https://github.com/a/b", 5, "search_seed")
    row = store.claim_next()
    store.save_result(row["full_name"], {"anomaly_score": 75, "findings": []}, "# report", None)
    store.review("a/b", "marked_safe")
    assert store.reports() == []