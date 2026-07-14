# storage/scan_store.py
"""
Persistent scan store — queue + status lifecycle + history over the orchestrator.

Wraps `modules.scan.run_scan` (unchanged) with a SQLite-backed queue and history
so the dashboard/blue-team tabs can enqueue targets, poll a scan's lifecycle
(queued -> running -> done|error), and browse past scans AFTER a process restart.

Why storage/scan_store.py (a NEW top-level package), not engine/scan_store.py:
  This store imports `modules.scan.run_scan`, which itself imports `engine.*`
  (scope, report_io, nuclei_agent, recon_tools). The repo's dependency direction
  is storage -> modules -> engine. Placing the store in `engine/` would make an
  engine module import `modules.scan`, inverting that direction and risking an
  import cycle the moment anything in engine's import graph pulled it in (the task
  explicitly warns: "must NOT live somewhere modules.scan would need to import it
  back — avoid cycles"). A dedicated `storage/` layer strictly ABOVE modules/
  makes a cycle impossible — nothing in modules/ or engine/ imports storage/.
  Live entry is therefore `import storage.scan_store`.

Design (mirrors app.py's daemon-thread pattern + the run_scan status contract):
  * SQLite at outputs/redsee.db (gitignored: `outputs/*.db*`) — survives restart,
    queryable. stdlib sqlite3 only, NO new deps.
  * The DB stores a SUMMARY ROW per scan (status + the severity/tool rollup) plus
    a PATH to the on-disk scan_<id>.json — never the full record. The JSON file
    written by run_scan/report_io stays the single source of truth.
  * Gating is authoritative and UP FRONT: enqueue_scan reuses engine.scope's
    require_authorization + assert_in_scope and REFUSES (ScopeError) before a row
    is ever created; the worker then calls run_scan, which gates again. Scope is
    never bypassed.
  * A bounded worker pool (default 1, `REDSEE_SCAN_CONCURRENCY` or the ScanStore
    `concurrency=` arg) drains the queue so queued scans never spawn unbounded
    sandboxes. Every run is wrapped so an exception is recorded as status=error —
    a scan is NEVER left stuck in "running"; a store re-opened after a hard crash
    reconciles any orphaned "running" row to "error" on init.

schemas.py is untouched — the scan row is a persistence concern, not a schema type.
NOT wired into Flask routes here (that is the next task).
"""

import json
import os
import queue
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from modules.scan import run_scan, DEFAULT_MODE
from engine.scope import (
    ScopeError, assert_in_scope, load_scope_config, require_authorization,
)

_DEFAULT_DB_PATH = "outputs/redsee.db"
_DEFAULT_CONCURRENCY = 1
_STOP = object()                       # worker-shutdown sentinel

# status lifecycle: queued -> running -> done | error
_STATUS_QUEUED = "queued"
_STATUS_RUNNING = "running"
_STATUS_DONE = "done"
_STATUS_ERROR = "error"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _env_concurrency() -> int:
    try:
        return max(1, int(os.environ.get("REDSEE_SCAN_CONCURRENCY", _DEFAULT_CONCURRENCY)))
    except (ValueError, TypeError):
        return _DEFAULT_CONCURRENCY


class ScanStore:
    """A SQLite-backed scan queue + history with a bounded background worker pool.

    Construct one per process (the module-level enqueue_scan/list_scans/get_scan
    delegate to a lazily-created default instance on outputs/redsee.db). Tests
    construct their own on a tmp DB path and call shutdown() when done.
    """

    def __init__(self, db_path: str = _DEFAULT_DB_PATH, *, concurrency: int | None = None):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.concurrency = max(1, int(concurrency)) if concurrency is not None else _env_concurrency()

        self._lock = threading.RLock()          # serializes all DB access (single writer)
        self._queue: "queue.Queue" = queue.Queue()
        # In-memory only: scan_id -> ScopeConfig used to gate this run. NOT persisted
        # (a ScopeConfig isn't a durable artifact); a scan resumed in a *future*
        # process would re-derive scope from the environment inside run_scan.
        self._scope_by_id: dict = {}
        self._workers: list = []

        self._init_db()
        self._reconcile_orphans()
        self._start_workers()

    # ── DB plumbing ─────────────────────────────────────────────────────────

    @contextmanager
    def _db(self):
        """One short-lived connection per operation, serialized by self._lock so
        concurrent worker threads never hit 'database is locked'. Commits on
        success, rolls back on error, always closes."""
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def _init_db(self) -> None:
        with self._db() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id        TEXT PRIMARY KEY,
                    target         TEXT NOT NULL,
                    status         TEXT NOT NULL,
                    mode           TEXT,
                    created_at     TEXT NOT NULL,
                    started_at     TEXT,
                    finished_at    TEXT,
                    summary_json   TEXT,
                    error          TEXT,
                    scan_json_path TEXT
                )
                """
            )
            # Additive migration for a DB created before scan modes existed — the
            # column is harmless (NULL -> the run_scan default) on old rows.
            try:
                conn.execute("ALTER TABLE scans ADD COLUMN mode TEXT")
            except sqlite3.OperationalError:
                pass                                  # column already present

    def _reconcile_orphans(self) -> None:
        """Any row still 'running' when a store initializes belongs to a process
        that died mid-scan — its worker is gone and it can never progress, so
        mark it 'error' rather than leave it stuck in 'running' forever."""
        with self._db() as conn:
            conn.execute(
                "UPDATE scans SET status=?, error=?, finished_at=? WHERE status=?",
                (_STATUS_ERROR, "scan interrupted (process restart while running)",
                 _ts(), _STATUS_RUNNING),
            )

    def _update(self, scan_id: str, **cols) -> None:
        if not cols:
            return
        assignments = ", ".join(f"{k}=?" for k in cols)     # keys are internal, not user input
        values = list(cols.values()) + [scan_id]
        with self._db() as conn:
            conn.execute(f"UPDATE scans SET {assignments} WHERE scan_id=?", values)

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        raw = d.pop("summary_json", None)
        try:
            d["summary"] = json.loads(raw) if raw else None
        except (json.JSONDecodeError, TypeError):
            d["summary"] = None
        return d

    @staticmethod
    def _load_scan_json(path):
        if not path:
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    # ── Worker pool ─────────────────────────────────────────────────────────

    def _start_workers(self) -> None:
        for i in range(self.concurrency):
            t = threading.Thread(target=self._worker_loop,
                                 name=f"redsee-scan-worker-{i}", daemon=True)
            t.start()
            self._workers.append(t)

    def _worker_loop(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _STOP:
                    return
                self._process(item)
            finally:
                self._queue.task_done()

    def _process(self, scan_id: str) -> None:
        row = self.get_scan(scan_id)
        if row is None:                      # row deleted out from under us — nothing to do
            return
        target = row["target"]
        mode = row.get("mode") or DEFAULT_MODE
        scope_config = self._scope_by_id.pop(scan_id, None)

        self._update(scan_id, status=_STATUS_RUNNING, started_at=_ts())
        try:
            record = run_scan(target, scan_id=scan_id, scope_config=scope_config, mode=mode)
        except Exception as exc:             # noqa: BLE001 - record ANY failure, never stay running
            self._update(scan_id, status=_STATUS_ERROR,
                         error=f"{type(exc).__name__}: {exc}", finished_at=_ts())
            return

        summary = record.get("summary") if isinstance(record, dict) else None
        scan_path = None
        if isinstance(record, dict):
            scan_path = (record.get("outputs") or {}).get("scan")
        self._update(
            scan_id, status=_STATUS_DONE, finished_at=_ts(),
            summary_json=json.dumps(summary) if summary is not None else None,
            scan_json_path=scan_path,
        )

    def shutdown(self, wait: bool = True) -> None:
        """Stop the worker pool (used by tests / clean shutdown). Daemon threads
        would not block process exit regardless."""
        for _ in self._workers:
            self._queue.put(_STOP)
        if wait:
            for t in self._workers:
                t.join(timeout=5)

    # ── Public API ──────────────────────────────────────────────────────────

    def enqueue_scan(self, target_url: str, *, scope_config=None,
                     mode: str = DEFAULT_MODE) -> str:
        """Validate authorization + scope UP FRONT, persist a queued row, hand the
        scan to the worker pool, and return its scan_id. Does NOT run inline.

        `mode` (fast / standard / deep) is persisted with the row and passed to
        run_scan by the worker (an unknown mode degrades to the default there).

        Raises ScopeError (before any row is created) if unauthorized or the
        target is out of scope — enqueue never bypasses the scope gate.
        """
        if scope_config is None:
            scope_config = load_scope_config()
        require_authorization(scope_config)          # raises before persisting
        assert_in_scope(target_url, scope_config)    # raises before persisting

        mode = (mode or DEFAULT_MODE)
        scan_id = uuid.uuid4().hex[:8]
        with self._db() as conn:
            conn.execute(
                "INSERT INTO scans (scan_id, target, status, mode, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (scan_id, target_url, _STATUS_QUEUED, mode, _ts()),
            )
        self._scope_by_id[scan_id] = scope_config    # set BEFORE queueing so the worker sees it
        self._queue.put(scan_id)
        return scan_id

    def list_scans(self, *, limit: int = 50, offset: int = 0, status=None) -> list:
        """Summary rows, newest first (by insertion order). Optional status filter.
        Does NOT load the full scan JSON (cheap listing) — use get_scan for that."""
        q = "SELECT * FROM scans"
        params: list = []
        if status is not None:
            q += " WHERE status=?"
            params.append(status)
        q += " ORDER BY rowid DESC LIMIT ? OFFSET ?"
        params += [int(limit), int(offset)]
        with self._db() as conn:
            rows = conn.execute(q, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_scan(self, scan_id: str):
        """The summary row for one scan plus, under key "scan", the full parsed
        scan_<id>.json when that file exists on disk (else None). Returns None if
        there is no such scan."""
        with self._db() as conn:
            r = conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        if r is None:
            return None
        row = self._row_to_dict(r)
        row["scan"] = self._load_scan_json(row.get("scan_json_path"))
        return row


# ── Module-level default store + convenience functions ──────────────────────
# Lazily created (so importing this module starts no threads and creates no DB
# until first use). The live smoke uses these:
#   import storage.scan_store as s; id = s.enqueue_scan("http://host/")

_default_store = None
_default_lock = threading.Lock()


def _store() -> ScanStore:
    global _default_store
    if _default_store is None:
        with _default_lock:
            if _default_store is None:
                _default_store = ScanStore()
    return _default_store


def enqueue_scan(target_url: str, *, scope_config=None, mode: str = DEFAULT_MODE) -> str:
    return _store().enqueue_scan(target_url, scope_config=scope_config, mode=mode)


def list_scans(*, limit: int = 50, offset: int = 0, status=None) -> list:
    return _store().list_scans(limit=limit, offset=offset, status=status)


def get_scan(scan_id: str):
    return _store().get_scan(scan_id)
