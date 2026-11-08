"""Best-effort local audit ledger; unavailable storage never stops an agent turn."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Optional


def get_default_db_path() -> str:
    from hermes_constants import get_hermes_home

    return str(get_hermes_home() / "plugin-data" / "hermes-sentinel" / "sentinel_audit.db")


class AuditLedger:
    def __init__(self, db_path: Optional[str] = None):
        self._lock = threading.RLock()
        self._memory: Optional[sqlite3.Connection] = None
        self.storage = "disabled"
        self.db_path = ":memory:"
        try:
            self.db_path = str(db_path) if db_path is not None else get_default_db_path()
            if self.db_path == ":memory:":
                self._open_memory()
            else:
                Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
                self.storage = "persistent"
                self._init_db()
        except Exception:
            self.close()
            try:
                self._open_memory()
            except Exception:
                self.close()

    def _open_memory(self):
        self.db_path = ":memory:"
        # Hermes may dispatch hooks on worker threads. The lock serializes this
        # retained connection; reopening :memory: per operation would lose records.
        self._memory = sqlite3.connect(":memory:", check_same_thread=False)
        self.storage = "memory"
        self._init_db()

    @contextmanager
    def _connection(self):
        if self.storage == "disabled":
            raise sqlite3.OperationalError("Sentinel auditing is disabled")
        conn = self._memory if self._memory is not None else sqlite3.connect(self.db_path, timeout=2.0)
        try:
            yield conn
        finally:
            if conn is not self._memory:
                conn.close()

    def _init_db(self):
        with self._lock, self._connection() as conn, conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS execution_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    tool_name TEXT,
                    action TEXT NOT NULL,
                    reason TEXT,
                    details TEXT
                )
            """)
            conn.execute("CREATE TABLE IF NOT EXISTS sentinel_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute("INSERT OR IGNORE INTO sentinel_meta (key, value) VALUES ('reset_epoch', '0')")

    def _run(self, operation, default=None):
        try:
            with self._lock, self._connection() as conn, conn:
                return operation(conn)
        except Exception:
            # Includes connection acquisition, transactions and serialization:
            # audit failures must not disable the credential or loop guards.
            return default

    def close(self):
        with self._lock:
            if self._memory is not None:
                try:
                    self._memory.close()
                except sqlite3.Error:
                    pass
                self._memory = None
            self.storage = "disabled"

    def get_reset_epoch(self) -> int:
        def read(conn):
            row = conn.execute("SELECT value FROM sentinel_meta WHERE key = 'reset_epoch'").fetchone()
            return int(row[0]) if row else 0

        return self._run(read, 0)

    @staticmethod
    def _increment_epoch(conn) -> int:
        conn.execute("UPDATE sentinel_meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'reset_epoch'")
        return int(conn.execute("SELECT value FROM sentinel_meta WHERE key = 'reset_epoch'").fetchone()[0])

    def bump_reset_epoch(self) -> int:
        return self._run(self._increment_epoch, 0)

    def clear(self) -> bool:
        def clear_records(conn):
            conn.execute("DELETE FROM execution_events")
            conn.execute("DELETE FROM sentinel_meta WHERE key != 'reset_epoch'")
            # Do not unlink a live SQLite database or rewind the epoch: other
            # processes must observe this reset even after earlier resets.
            self._increment_epoch(conn)
            return True

        return self._run(clear_records, False)

    def record_event(
        self,
        session_id: str,
        event_type: str,
        action: str,
        tool_name: Optional[str] = None,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        def insert(conn):
            conn.execute(
                "INSERT INTO execution_events (timestamp, session_id, event_type, tool_name, action, reason, details) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), session_id or "default",
                 event_type, tool_name, action, reason, json.dumps(details or {}, ensure_ascii=False)),
            )

        self._run(insert)

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        def read(conn):
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM execution_events ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in rows]

        return self._run(read, [])

    def render_markdown_summary(self, limit: int = 20) -> str:
        if self.storage == "disabled":
            return "Sentinel auditing is disabled: storage is unavailable. Guards remain active."
        events = self.get_recent_events(limit)
        if not events:
            return "No Sentinel execution events available (empty ledger or storage read failed)."
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        lines = [
            "# Hermes Sentinel Execution Ledger",
            f"Last updated: {now}\n",
            "| ID | Timestamp | Event | Tool | Action | Reason |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for event in events:
            tool = event["tool_name"] or "-"
            reason = (event["reason"] or "-").replace("\n", " ")[:60]
            lines.append(f"| {event['id']} | {event['timestamp'][11:19]} | {event['event_type']} | "
                         f"`{tool}` | **{event['action']}** | {reason} |")
        return "\n".join(lines)
