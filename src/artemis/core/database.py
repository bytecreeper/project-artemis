"""DuckDB database layer — time-series optimized storage for all Artemis data."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

import duckdb

logger = logging.getLogger("artemis.db")

SCHEMA_VERSION = 2

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

CREATE TABLE IF NOT EXISTS findings (
    id              VARCHAR PRIMARY KEY,
    timestamp       DOUBLE NOT NULL,
    category        VARCHAR NOT NULL,
    severity        VARCHAR NOT NULL,
    title           VARCHAR NOT NULL,
    description     VARCHAR NOT NULL,
    evidence        JSON NOT NULL DEFAULT '{}',
    confidence      DOUBLE NOT NULL DEFAULT 0.0,
    mitre_id        VARCHAR DEFAULT '',
    mitre_tactic    VARCHAR DEFAULT '',
    remediation_id  VARCHAR DEFAULT '',
    event_ids       JSON DEFAULT '[]',
    dismissed       BOOLEAN DEFAULT FALSE,
    resolved        BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS investigations (
    id              VARCHAR PRIMARY KEY,
    trigger         VARCHAR NOT NULL,
    trigger_type    VARCHAR NOT NULL,
    timestamp       DOUBLE NOT NULL,
    severity_assessment VARCHAR DEFAULT '',
    kill_chain_phase VARCHAR DEFAULT '',
    mitre_techniques JSON DEFAULT '[]',
    narrative       VARCHAR DEFAULT '',
    recommendations JSON DEFAULT '[]',
    confidence      DOUBLE DEFAULT 0.0,
    status          VARCHAR DEFAULT 'complete',
    duration_seconds DOUBLE DEFAULT 0.0,
    related_events_count INTEGER DEFAULT 0,
    related_hosts_count INTEGER DEFAULT 0,
    related_processes_count INTEGER DEFAULT 0,
    timeline_count  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_results (
    id              VARCHAR PRIMARY KEY,
    timestamp       DOUBLE NOT NULL,
    target          VARCHAR NOT NULL,
    scanner         VARCHAR NOT NULL,
    severity        VARCHAR NOT NULL,
    category        VARCHAR NOT NULL,
    title           VARCHAR NOT NULL,
    description     VARCHAR DEFAULT '',
    technical_detail VARCHAR DEFAULT '',
    evidence        JSON DEFAULT '{}',
    remediation     VARCHAR DEFAULT '',
    cve             VARCHAR DEFAULT '',
    mitre_id        VARCHAR DEFAULT '',
    confidence      DOUBLE DEFAULT 1.0
);

CREATE TABLE IF NOT EXISTS plain_alerts (
    id              VARCHAR PRIMARY KEY,
    timestamp       DOUBLE NOT NULL,
    event_type      VARCHAR NOT NULL,
    severity        INTEGER NOT NULL DEFAULT 0,
    headline        VARCHAR NOT NULL,
    plain           VARCHAR NOT NULL,
    action          VARCHAR DEFAULT '',
    technical       VARCHAR DEFAULT '',
    dismissed       BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS score_history (
    id              INTEGER PRIMARY KEY,
    timestamp       TIMESTAMP NOT NULL DEFAULT now(),
    score           INTEGER NOT NULL,
    label           VARCHAR NOT NULL,
    finding_count   INTEGER NOT NULL DEFAULT 0,
    events_24h      INTEGER NOT NULL DEFAULT 0
);

CREATE SEQUENCE IF NOT EXISTS score_history_seq START 1;

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

    # ── Findings ──────────────────────────────────────────────────────

    def upsert_finding(self, finding: dict) -> None:
        """Insert or update a finding."""
        import json
        self.conn.execute(
            """INSERT OR REPLACE INTO findings
            (id, timestamp, category, severity, title, description, evidence,
             confidence, mitre_id, mitre_tactic, remediation_id, event_ids, dismissed, resolved)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                finding["id"], finding["timestamp"], finding["category"], finding["severity"],
                finding["title"], finding["description"], json.dumps(finding.get("evidence", {})),
                finding.get("confidence", 0.0), finding.get("mitre_id", ""),
                finding.get("mitre_tactic", ""), finding.get("remediation_id", ""),
                json.dumps(finding.get("event_ids", [])),
                finding.get("dismissed", False), finding.get("resolved", False),
            ],
        )

    def get_findings(self, active_only: bool = True) -> list[dict]:
        """Load findings from DB."""
        import json
        where = "WHERE dismissed = FALSE AND resolved = FALSE" if active_only else ""
        rows = self.conn.execute(
            f"SELECT * FROM findings {where} ORDER BY timestamp DESC"
        ).fetchall()
        cols = ["id", "timestamp", "category", "severity", "title", "description",
                "evidence", "confidence", "mitre_id", "mitre_tactic",
                "remediation_id", "event_ids", "dismissed", "resolved"]
        results = []
        for r in rows:
            d = dict(zip(cols, r))
            if isinstance(d["evidence"], str):
                try: d["evidence"] = json.loads(d["evidence"])
                except: pass
            if isinstance(d["event_ids"], str):
                try: d["event_ids"] = json.loads(d["event_ids"])
                except: pass
            results.append(d)
        return results

    def dismiss_finding(self, finding_id: str) -> bool:
        self.conn.execute("UPDATE findings SET dismissed = TRUE WHERE id = ?", [finding_id])
        return True

    # ── Investigations ────────────────────────────────────────────────

    def save_investigation(self, inv: dict) -> None:
        import json
        self.conn.execute(
            """INSERT OR REPLACE INTO investigations
            (id, trigger, trigger_type, timestamp, severity_assessment, kill_chain_phase,
             mitre_techniques, narrative, recommendations, confidence, status,
             duration_seconds, related_events_count, related_hosts_count,
             related_processes_count, timeline_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                inv["id"], inv["trigger"], inv["trigger_type"], inv["timestamp"],
                inv.get("severity_assessment", ""), inv.get("kill_chain_phase", ""),
                json.dumps(inv.get("mitre_techniques", [])),
                inv.get("narrative", ""), json.dumps(inv.get("recommendations", [])),
                inv.get("confidence", 0.0), inv.get("status", "complete"),
                inv.get("duration_seconds", 0.0),
                inv.get("related_events_count", 0), inv.get("related_hosts_count", 0),
                inv.get("related_processes_count", 0), inv.get("timeline_count", 0),
            ],
        )

    def get_investigations(self, limit: int = 20) -> list[dict]:
        import json
        rows = self.conn.execute(
            "SELECT * FROM investigations ORDER BY timestamp DESC LIMIT ?", [limit]
        ).fetchall()
        cols = ["id", "trigger", "trigger_type", "timestamp", "severity_assessment",
                "kill_chain_phase", "mitre_techniques", "narrative", "recommendations",
                "confidence", "status", "duration_seconds", "related_events_count",
                "related_hosts_count", "related_processes_count", "timeline_count"]
        results = []
        for r in rows:
            d = dict(zip(cols, r))
            for k in ("mitre_techniques", "recommendations"):
                if isinstance(d[k], str):
                    try: d[k] = json.loads(d[k])
                    except: pass
            results.append(d)
        return results

    # ── Scan Results ──────────────────────────────────────────────────

    def save_scan_finding(self, finding: dict) -> None:
        import json
        self.conn.execute(
            """INSERT INTO scan_results
            (id, timestamp, target, scanner, severity, category, title, description,
             technical_detail, evidence, remediation, cve, mitre_id, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                finding["id"], finding.get("timestamp", 0.0), finding.get("target", ""),
                finding.get("scanner", ""), finding["severity"], finding["category"],
                finding["title"], finding.get("description", ""),
                finding.get("technical_detail", ""), json.dumps(finding.get("evidence", {})),
                finding.get("remediation", ""), finding.get("cve", ""),
                finding.get("mitre_id", ""), finding.get("confidence", 1.0),
            ],
        )

    def get_scan_history(self, limit: int = 100) -> list[dict]:
        import json
        rows = self.conn.execute(
            "SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT ?", [limit]
        ).fetchall()
        cols = ["id", "timestamp", "target", "scanner", "severity", "category",
                "title", "description", "technical_detail", "evidence",
                "remediation", "cve", "mitre_id", "confidence"]
        results = []
        for r in rows:
            d = dict(zip(cols, r))
            if isinstance(d["evidence"], str):
                try: d["evidence"] = json.loads(d["evidence"])
                except: pass
            results.append(d)
        return results

    # ── Plain Alerts ──────────────────────────────────────────────────

    def save_plain_alert(self, alert: dict) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO plain_alerts
            (id, timestamp, event_type, severity, headline, plain, action, technical, dismissed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                alert["id"], alert["timestamp"], alert.get("event_type", ""),
                alert.get("severity", 0), alert["headline"], alert["plain"],
                alert.get("action", ""), alert.get("technical", ""),
                alert.get("dismissed", False),
            ],
        )

    def get_plain_alerts(self, limit: int = 50, active_only: bool = True) -> list[dict]:
        where = "WHERE dismissed = FALSE" if active_only else ""
        rows = self.conn.execute(
            f"SELECT * FROM plain_alerts {where} ORDER BY timestamp DESC LIMIT ?", [limit]
        ).fetchall()
        cols = ["id", "timestamp", "event_type", "severity", "headline",
                "plain", "action", "technical", "dismissed"]
        return [dict(zip(cols, r)) for r in rows]

    def dismiss_plain_alert(self, alert_id: str) -> bool:
        self.conn.execute("UPDATE plain_alerts SET dismissed = TRUE WHERE id = ?", [alert_id])
        return True

    # ── Score History ─────────────────────────────────────────────────

    def record_score(self, score: int, label: str, finding_count: int, events_24h: int) -> None:
        self.conn.execute(
            """INSERT INTO score_history (id, timestamp, score, label, finding_count, events_24h)
            VALUES (nextval('score_history_seq'), now(), ?, ?, ?, ?)""",
            [score, label, finding_count, events_24h],
        )

    def get_score_history(self, hours: int = 168) -> list[dict]:
        rows = self.conn.execute(
            f"""SELECT timestamp, score, label, finding_count, events_24h
            FROM score_history
            WHERE timestamp > now() - INTERVAL '{hours} hours'
            ORDER BY timestamp""",
        ).fetchall()
        return [
            {"time": str(r[0]), "score": r[1], "label": r[2],
             "findings": r[3], "events_24h": r[4]}
            for r in rows
        ]

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
