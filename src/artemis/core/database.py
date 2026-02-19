"""DuckDB database layer — time-series optimized storage for all Artemis data."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

import duckdb

logger = logging.getLogger("artemis.db")

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id              VARCHAR PRIMARY KEY,
    timestamp       TIMESTAMP NOT NULL DEFAULT now(),
    event_type      VARCHAR NOT NULL,
    source          VARCHAR NOT NULL,
    severity        INTEGER NOT NULL DEFAULT 0,
    data            JSON NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    ip              VARCHAR PRIMARY KEY,
    mac             VARCHAR,
    hostname        VARCHAR,
    os_guess        VARCHAR,
    first_seen      TIMESTAMP NOT NULL DEFAULT now(),
    last_seen       TIMESTAMP NOT NULL DEFAULT now(),
    open_ports      JSON DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS alerts (
    id              VARCHAR PRIMARY KEY,
    timestamp       TIMESTAMP NOT NULL DEFAULT now(),
    title           VARCHAR NOT NULL,
    description     VARCHAR,
    severity        INTEGER NOT NULL DEFAULT 0,
    event_ids       JSON DEFAULT '[]',
    status          VARCHAR NOT NULL DEFAULT 'open',
    mitre_tactics   JSON DEFAULT '[]',
    mitre_techniques JSON DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS file_baselines (
    path            VARCHAR PRIMARY KEY,
    hash_sha256     VARCHAR NOT NULL,
    size_bytes      BIGINT,
    last_checked    TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS schema_meta (
    key             VARCHAR PRIMARY KEY,
    value           VARCHAR
);
"""


class Database:
    """DuckDB wrapper for Artemis persistent storage."""

    def __init__(self, db_path: str | Path = "data/artemis.duckdb") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: duckdb.DuckDBPyConnection | None = None

    def connect(self) -> duckdb.DuckDBPyConnection:
        if self._conn is None:
            self._conn = duckdb.connect(str(self.db_path))
            self._init_schema()
            logger.info("Database connected: %s", self.db_path)
        return self._conn

    @property
    def conn(self) -> duckdb.DuckDBPyConnection:
        return self.connect()

    def _init_schema(self) -> None:
        assert self._conn is not None
        self._conn.execute(SCHEMA_SQL)
        self._conn.execute(
            "INSERT OR REPLACE INTO schema_meta VALUES ('version', ?)",
            [str(SCHEMA_VERSION)],
        )
        logger.info("Schema initialized (v%d)", SCHEMA_VERSION)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ── Events ────────────────────────────────────────────────────────

    def insert_event(self, event_id: str, event_type: str, source: str,
                     severity: int, data: str, timestamp: float) -> None:
        ts = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        self.conn.execute(
            "INSERT INTO events (id, timestamp, event_type, source, severity, data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [event_id, ts, event_type, source, severity, data],
        )

    def get_recent_events(self, limit: int = 100, event_type: str | None = None) -> list[tuple]:
        if event_type:
            return self.conn.execute(
                "SELECT * FROM events WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
                [event_type, limit],
            ).fetchall()
        return self.conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", [limit]
        ).fetchall()

    def count_events_since(self, hours: int = 24) -> int:
        result = self.conn.execute(
            f"SELECT COUNT(*) FROM events WHERE timestamp > now() - INTERVAL '{hours} hours'"
        ).fetchone()
        return result[0] if result else 0

    # ── Alerts ────────────────────────────────────────────────────────

    def get_open_alerts(self) -> list[tuple]:
        return self.conn.execute(
            "SELECT * FROM alerts WHERE status = 'open' ORDER BY severity DESC, timestamp DESC"
        ).fetchall()

    def count_open_alerts(self) -> int:
        result = self.conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'open'"
        ).fetchone()
        return result[0] if result else 0

    # ── Hosts ─────────────────────────────────────────────────────────

    def get_hosts(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT ip, mac, hostname, os_guess, first_seen, last_seen, open_ports "
            "FROM hosts ORDER BY last_seen DESC"
        ).fetchall()
        return [
            {
                "ip": r[0], "mac": r[1], "hostname": r[2], "os_guess": r[3],
                "first_seen": str(r[4]), "last_seen": str(r[5]), "open_ports": r[6],
            }
            for r in rows
        ]

    def count_hosts(self) -> int:
        result = self.conn.execute("SELECT COUNT(*) FROM hosts").fetchone()
        return result[0] if result else 0

    # ── Search / Hunt ─────────────────────────────────────────────────

    def search_events(self, query: str, limit: int = 100,
                      event_type: str | None = None,
                      min_severity: int = 0,
                      hours: int | None = None) -> list[tuple]:
        """Full-text search across event data, type, and source."""
        conditions = ["1=1"]
        params: list = []

        if query:
            conditions.append(
                "(event_type ILIKE ? OR source ILIKE ? OR CAST(data AS VARCHAR) ILIKE ?)"
            )
            like = f"%{query}%"
            params.extend([like, like, like])

        if event_type:
            conditions.append("event_type ILIKE ?")
            params.append(f"{event_type}%")

        if min_severity > 0:
            conditions.append("severity >= ?")
            params.append(min_severity)

        if hours:
            conditions.append(f"timestamp > now() - INTERVAL '{hours} hours'")

        where = " AND ".join(conditions)
        params.append(limit)

        return self.conn.execute(
            f"SELECT * FROM events WHERE {where} ORDER BY timestamp DESC LIMIT ?",
            params,
        ).fetchall()

    def get_event_timeline(self, hours: int = 24, bucket_minutes: int = 15) -> list[dict]:
        """Event counts bucketed by time for timeline charts."""
        rows = self.conn.execute(
            f"""SELECT
                time_bucket(INTERVAL '{bucket_minutes} minutes', timestamp) AS bucket,
                COUNT(*) AS count,
                MAX(severity) AS max_severity
            FROM events
            WHERE timestamp > now() - INTERVAL '{hours} hours'
            GROUP BY bucket
            ORDER BY bucket"""
        ).fetchall()
        return [{"time": str(r[0]), "count": r[1], "max_severity": r[2]} for r in rows]

    def get_process_tree(self, pid: int | None = None) -> list[dict]:
        """Get process events, optionally filtered by PID."""
        if pid:
            rows = self.conn.execute(
                """SELECT * FROM events
                WHERE event_type LIKE 'edr.process.%'
                AND (CAST(data->'$.pid' AS INTEGER) = ? OR CAST(data->'$.ppid' AS INTEGER) = ?)
                ORDER BY timestamp DESC LIMIT 50""",
                [pid, pid],
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM events WHERE event_type LIKE 'edr.process.%' ORDER BY timestamp DESC LIMIT 100"
            ).fetchall()
        return rows
