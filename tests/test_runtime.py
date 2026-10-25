import threading
import time

import git_hunter.discovery as discovery
import git_hunter.worker as worker


def _run_until(predicate, timeout=1.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_worker_waits_for_start_and_stops_cleanly(monkeypatch):
    calls = []
    run_event = threading.Event()
    shutdown_event = threading.Event()

    def fake_process_next(*args, **kwargs):
        calls.append(True)
        run_event.clear()
        return True

    monkeypatch.setattr(worker, "process_next", fake_process_next)
    thread = threading.Thread(
        target=worker.run_worker,
        args=(object(),),
        kwargs={
            "run_event": run_event,
            "shutdown_event": shutdown_event,
            "interval_seconds": 0,
        },
    )
    thread.start()
    assert not _run_until(lambda: calls)

    run_event.set()
    assert _run_until(lambda: calls)
    shutdown_event.set()
    run_event.set()
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_wanderer_waits_for_start_and_stops_cleanly(monkeypatch):
    calls = []
    run_event = threading.Event()
    shutdown_event = threading.Event()

    def fake_wander_once(*args, **kwargs):
        calls.append(True)
        run_event.clear()
        return 0

    class Store:
        def pending_count(self):
            return 0

    monkeypatch.setattr(discovery, "wander_once", fake_wander_once)
    thread = threading.Thread(
        target=discovery.run_wanderer,
        args=(Store(), run_event),
        kwargs={
            "interval_seconds": 0,
            "shutdown_event": shutdown_event,
        },
    )
    thread.start()
    assert not _run_until(lambda: calls)

    run_event.set()
    assert _run_until(lambda: calls)
    shutdown_event.set()
    run_event.set()
    thread.join(timeout=1)
    assert not thread.is_alive()
