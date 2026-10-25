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


def test_local_database_creates_missing_parent_directory(tmp_path):
    database_path = tmp_path / "nested" / "data" / "git_hunter.db"
    store = Store(database_path)

    assert database_path.exists()
    assert store.client.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='queue'"
    ).rows


def test_claim_next_selects_from_pending_queue_randomly(tmp_path):
    store = Store(tmp_path / "random.db")
    store.enqueue("https://github.com/a/one", "a/one", 100)
    store.enqueue("https://github.com/a/two", "a/two", 1)

    queries = []
    original_execute = store.client.execute

    def record_execute(statement, args=None):
        queries.append(statement)
        return original_execute(statement, args)

    store.client.execute = record_execute
    row = store.claim_next()

    assert row is not None
    assert any("ORDER BY RANDOM()" in query for query in queries)


def test_pending_count_only_counts_pending_items(tmp_path):
    store = Store(tmp_path / "pending.db")
    store.enqueue("https://github.com/a/pending", "a/pending", 1)
    store.enqueue("https://github.com/a/other", "a/other", 1)
    row = store.claim_next()

    assert row is not None
    assert store.pending_count() == 1
