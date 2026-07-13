"""
Tests for storage/scan_store.py — the persistent scan store (queue + history).

Fully offline: run_scan is monkeypatched at the storage.scan_store boundary with
a fast fake returning a canned record (no crawl/sandbox/LLM/network). Each test
uses its own tmp SQLite DB and shuts its worker pool down.

Run: PYTHONPATH=. python -m pytest tests/test_scan_store.py -v
"""
import json
import threading
import time
from pathlib import Path

import pytest

import storage.scan_store as store_mod
from storage.scan_store import ScanStore
from engine.scope import ScopeConfig, ScopeError


IN_SCOPE = "http://localhost:8080/"
OUT_SCOPE = "http://evil.com/"


def _scope(authorized=True, hosts=("localhost",)):
    return ScopeConfig(target_url=IN_SCOPE, allowed_hosts=list(hosts), authorized=authorized)


@pytest.fixture
def store(tmp_path):
    s = ScanStore(db_path=str(tmp_path / "redsee.db"), concurrency=1)
    try:
        yield s
    finally:
        s.shutdown()


def _fast_fake(tmp_path, *, summary=None):
    """A run_scan double that writes a real scan_<id>.json and returns the record."""
    summary = summary or {
        "findings_total": 1, "findings_by_severity": {"Critical": 1, "High": 0,
        "Medium": 0, "Low": 0}, "recon_observations": 2,
        "tools_ok": 7, "tools_error": 0, "tools_skipped": 0, "tools_total": 7,
    }

    def fake(target, *, scan_id, scope_config=None, **kwargs):
        path = tmp_path / f"scan_{scan_id}.json"
        record = {
            "scan_id": scan_id, "target": target,
            "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:01Z",
            "tools_run": [], "findings": [], "recon": {"nuclei": [], "observations": []},
            "summary": summary, "outputs": {"scan": str(path)},
        }
        path.write_text(json.dumps(record), encoding="utf-8")
        return record

    return fake


def _wait_status(store, scan_id, statuses, timeout=5.0):
    deadline = time.time() + timeout
    row = None
    while time.time() < deadline:
        row = store.get_scan(scan_id)
        if row and row["status"] in statuses:
            return row
        time.sleep(0.02)
    return row


# ── enqueue + gating ─────────────────────────────────────────────────────────

def test_enqueue_creates_queued_row_and_returns_id(store, monkeypatch, tmp_path):
    # Occupy the single worker with a blocking scan so the SECOND enqueue is
    # observably still "queued".
    release = threading.Event()
    started = threading.Event()

    def blocking(target, *, scan_id, scope_config=None, **kwargs):
        started.set()
        release.wait(3)
        return {"scan_id": scan_id, "target": target, "summary": {}, "outputs": {"scan": None}}

    monkeypatch.setattr(store_mod, "run_scan", blocking)

    first = store.enqueue_scan(IN_SCOPE, scope_config=_scope())
    assert started.wait(3), "worker never picked up the first scan"

    second = store.enqueue_scan(IN_SCOPE, scope_config=_scope())
    row = store.get_scan(second)
    assert row is not None
    assert row["scan_id"] == second
    assert row["status"] == "queued"
    assert row["target"] == IN_SCOPE
    assert row["started_at"] is None and row["finished_at"] is None

    release.set()  # let the worker drain so shutdown is clean


def test_unauthorized_target_refused_no_row(store, monkeypatch):
    def must_not_run(*a, **k):
        raise AssertionError("run_scan must not be called for a refused enqueue")
    monkeypatch.setattr(store_mod, "run_scan", must_not_run)

    with pytest.raises(ScopeError):
        store.enqueue_scan(IN_SCOPE, scope_config=_scope(authorized=False))
    assert store.list_scans(limit=10) == []


def test_out_of_scope_target_refused_no_row(store, monkeypatch):
    def must_not_run(*a, **k):
        raise AssertionError("run_scan must not be called for a refused enqueue")
    monkeypatch.setattr(store_mod, "run_scan", must_not_run)

    with pytest.raises(ScopeError):
        store.enqueue_scan(OUT_SCOPE, scope_config=_scope())   # authorized, but host not allowed
    assert store.list_scans(limit=10) == []


# ── worker lifecycle ─────────────────────────────────────────────────────────

def test_worker_runs_scan_queued_running_done_persists_summary(store, monkeypatch, tmp_path):
    monkeypatch.setattr(store_mod, "run_scan", _fast_fake(tmp_path))

    scan_id = store.enqueue_scan(IN_SCOPE, scope_config=_scope())
    row = _wait_status(store, scan_id, {"done", "error"})

    assert row["status"] == "done"
    assert row["scan_id"] == scan_id                        # SHARED scan_id
    assert row["started_at"] is not None
    assert row["finished_at"] is not None
    assert row["error"] is None
    # summary rollup persisted
    assert row["summary"]["findings_total"] == 1
    assert row["summary"]["findings_by_severity"]["Critical"] == 1
    # path to the on-disk JSON persisted (the DB does not blob the full record)
    assert row["scan_json_path"] == str(tmp_path / f"scan_{scan_id}.json")


def test_run_scan_raises_sets_error_not_left_running(store, monkeypatch):
    def boom(target, *, scan_id, scope_config=None, **kwargs):
        raise RuntimeError("sandbox exploded mid-scan")
    monkeypatch.setattr(store_mod, "run_scan", boom)

    scan_id = store.enqueue_scan(IN_SCOPE, scope_config=_scope())
    row = _wait_status(store, scan_id, {"done", "error"})

    assert row["status"] == "error"
    assert row["status"] != "running"
    assert "RuntimeError" in row["error"]
    assert "sandbox exploded" in row["error"]
    assert row["finished_at"] is not None
    assert row["summary"] is None                           # nothing fabricated


# ── list / get ───────────────────────────────────────────────────────────────

def test_list_scans_newest_first_with_status_filter_and_paging(store, monkeypatch, tmp_path):
    monkeypatch.setattr(store_mod, "run_scan", _fast_fake(tmp_path))

    ids = []
    for _ in range(3):
        ids.append(store.enqueue_scan(IN_SCOPE, scope_config=_scope()))
    for sid in ids:
        _wait_status(store, sid, {"done", "error"})

    newest_first = [r["scan_id"] for r in store.list_scans(limit=10)]
    assert newest_first == list(reversed(ids))              # last enqueued first

    done = store.list_scans(limit=10, status="done")
    assert {r["scan_id"] for r in done} == set(ids)
    assert all(r["status"] == "done" for r in done)
    assert store.list_scans(limit=10, status="error") == []

    # paging
    assert [r["scan_id"] for r in store.list_scans(limit=2)] == list(reversed(ids))[:2]
    assert [r["scan_id"] for r in store.list_scans(limit=2, offset=1)] == list(reversed(ids))[1:3]


def test_get_scan_loads_scan_json_when_file_exists(store, monkeypatch, tmp_path):
    monkeypatch.setattr(store_mod, "run_scan", _fast_fake(tmp_path))

    scan_id = store.enqueue_scan(IN_SCOPE, scope_config=_scope())
    _wait_status(store, scan_id, {"done", "error"})

    row = store.get_scan(scan_id)
    assert row["scan"] is not None                          # full record loaded from disk
    assert row["scan"]["scan_id"] == scan_id
    assert row["scan"]["target"] == IN_SCOPE

    # unknown id -> None
    assert store.get_scan("nope0000") is None

    # file removed -> row still returned, "scan" is None (not an error)
    Path(row["scan_json_path"]).unlink()
    row2 = store.get_scan(scan_id)
    assert row2 is not None and row2["scan"] is None


# ── persistence across restart ───────────────────────────────────────────────

def test_prior_scans_survive_a_new_store_instance(store, monkeypatch, tmp_path):
    monkeypatch.setattr(store_mod, "run_scan", _fast_fake(tmp_path))
    scan_id = store.enqueue_scan(IN_SCOPE, scope_config=_scope())
    _wait_status(store, scan_id, {"done"})
    store.shutdown()

    # Re-open a NEW store on the SAME db file (simulates a process restart).
    store2 = ScanStore(db_path=str(tmp_path / "redsee.db"), concurrency=1)
    try:
        rows = store2.list_scans(limit=10)
        assert [r["scan_id"] for r in rows] == [scan_id]
        assert rows[0]["status"] == "done"                  # last-known status preserved
        assert rows[0]["summary"]["findings_total"] == 1
    finally:
        store2.shutdown()


def test_orphaned_running_row_reconciled_to_error_on_init(tmp_path):
    db = str(tmp_path / "redsee.db")
    s1 = ScanStore(db_path=db, concurrency=1)
    # Simulate a scan that was mid-run when the process died: insert a row and
    # force it to "running" directly, then abandon the store WITHOUT finishing.
    with s1._db() as conn:
        conn.execute(
            "INSERT INTO scans (scan_id, target, status, created_at, started_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ("crash001", IN_SCOPE, "running", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        )
    s1.shutdown()

    # A fresh store over the same DB must reconcile the orphan to "error".
    s2 = ScanStore(db_path=db, concurrency=1)
    try:
        row = s2.get_scan("crash001")
        assert row["status"] == "error"
        assert "interrupted" in row["error"]
        assert row["finished_at"] is not None
    finally:
        s2.shutdown()


# ── concurrency bound ────────────────────────────────────────────────────────

def test_concurrency_bound_is_respected(tmp_path, monkeypatch):
    store = ScanStore(db_path=str(tmp_path / "redsee.db"), concurrency=1)
    release = threading.Event()
    state = {"current": 0, "max": 0}
    state_lock = threading.Lock()

    def blocking(target, *, scan_id, scope_config=None, **kwargs):
        with state_lock:
            state["current"] += 1
            state["max"] = max(state["max"], state["current"])
        try:
            release.wait(3)
            return {"scan_id": scan_id, "target": target, "summary": {},
                    "outputs": {"scan": None}}
        finally:
            with state_lock:
                state["current"] -= 1

    monkeypatch.setattr(store_mod, "run_scan", blocking)

    try:
        ids = [store.enqueue_scan(IN_SCOPE, scope_config=_scope()) for _ in range(3)]

        # Give the single worker a moment to pick up exactly ONE scan.
        deadline = time.time() + 3
        while time.time() < deadline and state["max"] < 1:
            time.sleep(0.02)

        statuses = [store.get_scan(i)["status"] for i in ids]
        assert statuses.count("running") == 1, statuses      # not all 3 running at once
        assert statuses.count("queued") == 2, statuses

        release.set()
        for i in ids:
            _wait_status(store, i, {"done", "error"})

        assert state["max"] == 1                             # bound never exceeded
        assert all(store.get_scan(i)["status"] == "done" for i in ids)
    finally:
        release.set()
        store.shutdown()


# ── standalone runner (repo convention) ──────────────────────────────────────

if __name__ == "__main__":
    class _MP:
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, value):
            if isinstance(obj, str):
                import importlib
                mod, _, attr = obj.rpartition(".")
                obj, name = importlib.import_module(mod), attr
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def undo(self):
            for obj, name, old in reversed(self._undo):
                setattr(obj, name, old)

    import inspect
    import tempfile

    def _run(fn):
        needs_mp = "monkeypatch" in inspect.signature(fn).parameters
        needs_store = "store" in inspect.signature(fn).parameters
        needs_tmp = "tmp_path" in inspect.signature(fn).parameters
        mp = _MP() if needs_mp else None
        try:
            with tempfile.TemporaryDirectory() as d:
                kwargs = {}
                if needs_tmp:
                    kwargs["tmp_path"] = Path(d)
                if needs_store:
                    kwargs["store"] = ScanStore(db_path=str(Path(d) / "redsee.db"), concurrency=1)
                if needs_mp:
                    kwargs["monkeypatch"] = mp
                try:
                    fn(**kwargs)
                finally:
                    if needs_store:
                        kwargs["store"].shutdown()
            print(f"  ok  {fn.__name__}")
        finally:
            if mp:
                mp.undo()

    _tests = [v for k, v in sorted(globals().items())
              if k.startswith("test_") and callable(v)]
    print(f"Running {len(_tests)} scan_store tests...")
    for _fn in _tests:
        _run(_fn)
    print("All scan_store tests passed!")
