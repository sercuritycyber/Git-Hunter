import threading

from git_hunter.storage import Store


def test_queue_lifecycle(tmp_path):
    store = Store(tmp_path / "test.db")
    assert store.enqueue("https://github.com/a/b", "a/b", 5)
    assert not store.enqueue("https://github.com/a/b", "a/b", 5)
    row = store.claim_next()
    assert row["status"] == "scanning"
    store.save_result(row["id"], {"anomaly_score": 75, "findings": []}, "# report")
    assert store.report(row["id"])["status"] == "completed"
    assert store.reports() == []


def test_safe_review_is_hidden(tmp_path):
    store = Store(tmp_path / "review.db")
    store.enqueue("https://github.com/a/b", "a/b", 5)
    row = store.claim_next()
    store.save_result(row["id"], {"anomaly_score": 75, "findings": []}, "# report")
    store.review(row["id"], "safe")
    assert store.reports() == []


def test_queue_stats_reports_alert_and_finding_counts(tmp_path):
    store = Store(tmp_path / "counts.db")
    store.enqueue("https://github.com/a/b", "a/b", 5)
    row = store.claim_next()
    assert row is not None
    store.save_result(
        row["id"],
        {
            "anomaly_score": 75,
            "findings": [
                {"file": "scan.py", "line": 4, "kind": "execution_or_network"},
                {"file": "scan.py", "line": 8, "kind": "static_signature_match"},
            ],
        },
        "# report",
    )

    stats = store.queue_stats()

    assert stats["alerts"] == 1
    assert stats["findings"] == 2


def test_reports_include_findings_below_previous_score_threshold(tmp_path):
    store = Store(tmp_path / "low-score.db")
    store.enqueue("https://github.com/a/b", "a/b", 5)
    row = store.claim_next()
    assert row is not None
    store.save_result(
        row["id"],
        {"anomaly_score": 15, "findings": [{"file": "scan.py", "line": 2, "kind": "execution_or_network"}]},
        "# report",
    )

    reports = store.reports()

    assert len(reports) == 1
    assert reports[0]["finding_count"] == 1


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

    row = store.claim_next()

    assert row is not None
    assert row["status"] == "scanning"


def test_pending_count_only_counts_pending_items(tmp_path):
    store = Store(tmp_path / "pending.db")
    store.enqueue("https://github.com/a/pending", "a/pending", 1)
    store.enqueue("https://github.com/a/other", "a/other", 1)
    row = store.claim_next()

    assert row is not None
    assert store.pending_count() == 1


def test_query_status_filters_and_bounds_queue_records(tmp_path):
    store = Store(tmp_path / "inspect.db")
    store.enqueue("https://github.com/a/one", "a/one", 1)
    store.enqueue("https://github.com/a/two", "a/two", 2)
    claimed = store.claim_next()
    assert claimed is not None
    store.fail(claimed["id"])

    failed = store.query_status("failed")
    assert len(failed) == 1
    assert failed[0]["full_name"] in {"a/one", "a/two"}
    assert len(store.query_status("pending", limit=0)) == 1


def test_query_status_rejects_arbitrary_status(tmp_path):
    store = Store(tmp_path / "inspect-invalid.db")

    try:
        store.query_status("drop table queue")
    except ValueError as error:
        assert str(error) == "unsupported queue status"
    else:
        raise AssertionError("unsupported status should be rejected")


def test_concurrent_claims_do_not_claim_the_same_item(tmp_path):
    store = Store(tmp_path / "concurrent.db")
    store.enqueue("https://github.com/a/only", "a/only", 1)
    claimed = []

    def claim():
        row = store.claim_next()
        if row:
            claimed.append(row["id"])

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert claimed == [1]
