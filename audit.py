"""
Local SQLite audit ledger for Hermes Sentinel.
Logs execution truth, tool results, and block actions without external telemetry.
"""
import sqlite3
import os
import json
import tempfile
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

def get_default_db_path() -> str:
    env_path = os.environ.get("HERMES_SENTINEL_DB")
    if env_path:
        return env_path

    # Check for active hermes profile or default home
    hermes_home = os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes"))
    home_path = os.path.join(hermes_home, "sentinel_audit.db")
    try:
        os.makedirs(os.path.dirname(os.path.abspath(home_path)), exist_ok=True)
        # Test actual SQLite file locking / journal writeability (not just open)
        test_conn = sqlite3.connect(home_path, timeout=5.0)
        try:
            with test_conn:
                test_conn.execute(
                    "CREATE TABLE IF NOT EXISTS _sentinel_probe (id INTEGER PRIMARY KEY)"
                )
        finally:
            test_conn.close()
        return home_path
    except Exception:
        return os.path.join(tempfile.gettempdir(), "hermes_sentinel_audit.db")

class AuditLedger:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or get_default_db_path()
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
            self._init_db()
        except Exception:
            self.db_path = os.path.join(tempfile.gettempdir(), "hermes_sentinel_audit.db")
            self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=10.0)

    def _init_db(self):
        conn = self._get_conn()
        try:
            with conn:
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
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS sentinel_meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                """)
                conn.execute(
                    "INSERT OR IGNORE INTO sentinel_meta (key, value) VALUES ('reset_epoch', '0')"
                )
        finally:
            conn.close()

    def get_reset_epoch(self) -> int:
        conn = self._get_conn()
        try:
            cursor = conn.execute("SELECT value FROM sentinel_meta WHERE key = 'reset_epoch'")
            row = cursor.fetchone()
            return int(row[0]) if row else 0
        except Exception:
            return 0
        finally:
            conn.close()

    def bump_reset_epoch(self) -> int:
        conn = self._get_conn()
        try:
            current = self.get_reset_epoch()
            new_epoch = current + 1
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO sentinel_meta (key, value) VALUES ('reset_epoch', ?)",
                    (str(new_epoch),),
                )
            return new_epoch
        except Exception:
            return 0
        finally:
            conn.close()

    def record_event(
        self,
        session_id: str,
        event_type: str,
        action: str,
        tool_name: Optional[str] = None,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        details_str = json.dumps(details or {}, ensure_ascii=False)
        conn = self._get_conn()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO execution_events (timestamp, session_id, event_type, tool_name, action, reason, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (now, session_id or "default", event_type, tool_name, action, reason, details_str),
                )
        except Exception:
            # Audit logger must never crash the host agent
            pass
        finally:
            conn.close()

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM execution_events ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception:
            return []
        finally:
            conn.close()

    def render_markdown_summary(self, limit: int = 20) -> str:
        events = self.get_recent_events(limit)
        if not events:
            return "No Sentinel execution events recorded yet."

        now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        lines = [
            "# Hermes Sentinel Execution Ledger",
            f"Last updated: {now_str}\n",
            "| ID | Timestamp | Event | Tool | Action | Reason |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for e in events:
            ts = e["timestamp"][11:19]
            tool = e["tool_name"] or "-"
            action = e["action"]
            reason = (e["reason"] or "-").replace("\n", " ")[:60]
            lines.append(f"| {e['id']} | {ts} | {e['event_type']} | `{tool}` | **{action}** | {reason} |")

        return "\n".join(lines)
