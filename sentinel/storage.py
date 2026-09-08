# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import sqlite3
from pathlib import Path
from datetime import datetime, timezone


SCHEMA = '''
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    severity TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
'''


class Storage:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def add_event(self, severity: str, event_type: str, message: str, metadata_json: str | None = None) -> None:
        created_at = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO events(created_at,severity,event_type,message,metadata_json) VALUES(?,?,?,?,?)",
            (created_at, severity, event_type, message, metadata_json),
        )
        self.conn.commit()

    def get_state(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_state(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO state(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    def count_events_since(self, since_iso: str, event_type: str | None = None, severity: str | None = None) -> int:
        clauses = ["created_at >= ?"]
        params = [since_iso]

        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)

        if severity:
            clauses.append("severity = ?")
            params.append(severity)

        row = self.conn.execute(
            f"SELECT COUNT(*) FROM events WHERE {' AND '.join(clauses)}",
            tuple(params),
        ).fetchone()

        return int(row[0] if row else 0)

    def recent_events(self, since_iso: str, event_type: str | None = None) -> list[tuple]:
        clauses = ["created_at >= ?"]
        params = [since_iso]

        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)

        return self.conn.execute(
            f"SELECT id, created_at, severity, event_type, message, metadata_json "
            f"FROM events WHERE {' AND '.join(clauses)} ORDER BY id DESC",
            tuple(params),
        ).fetchall()
