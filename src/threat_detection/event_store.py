from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


class EventConflictError(ValueError):
    pass


class EventStore:
    """Stores predictions and triage metadata, never raw network features."""

    def __init__(self, database_path: str = ":memory:") -> None:
        self._lock = threading.RLock()
        if database_path == ":memory:":
            self._connection = sqlite3.connect(
                database_path, check_same_thread=False
            )
        else:
            path = Path(database_path)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.touch(mode=0o600, exist_ok=True)
            path.chmod(0o600)
            self._connection = sqlite3.connect(
                path, check_same_thread=False, timeout=5
            )
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.row_factory = sqlite3.Row
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS network_events (
                tenant_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                prediction_json TEXT NOT NULL,
                evidence_refs_json TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                triage_status TEXT NOT NULL DEFAULT 'open',
                reviewed_by TEXT,
                splunk_status TEXT NOT NULL DEFAULT 'pending',
                PRIMARY KEY (tenant_id, event_id)
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS triage_decisions (
                tenant_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                reviewed_by TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, event_id, recorded_at)
            )
            """
        )
        columns = {
            row["name"]
            for row in self._connection.execute("PRAGMA table_info(network_events)")
        }
        if "reviewed_by" not in columns:
            self._connection.execute(
                "ALTER TABLE network_events ADD COLUMN reviewed_by TEXT"
            )
        self._connection.execute(
            "UPDATE network_events SET splunk_status = 'pending' "
            "WHERE splunk_status = 'sending'"
        )
        self._connection.commit()

    def lookup(
        self, tenant_id: str, event_id: str, payload_digest: str
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM network_events WHERE tenant_id = ? AND event_id = ?",
                (tenant_id, event_id),
            ).fetchone()
        if row is None:
            return None
        if row["payload_digest"] != payload_digest:
            raise EventConflictError("event_id was already used for a different event")
        return self._to_dict(row)

    def insert(
        self,
        tenant_id: str,
        event_id: str,
        payload_digest: str,
        prediction: dict[str, Any],
        evidence_refs: list[str],
        ingested_at: str,
    ) -> tuple[dict[str, Any], bool]:
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT * FROM network_events WHERE tenant_id = ? AND event_id = ?",
                (tenant_id, event_id),
            ).fetchone()
            if existing is not None:
                if existing["payload_digest"] != payload_digest:
                    raise EventConflictError(
                        "event_id was already used for a different event"
                    )
                return self._to_dict(existing), False
            self._connection.execute(
                """
                INSERT INTO network_events (
                    tenant_id, event_id, payload_digest, prediction_json,
                    evidence_refs_json, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    event_id,
                    payload_digest,
                    json.dumps(prediction, separators=(",", ":"), sort_keys=True),
                    json.dumps(evidence_refs, separators=(",", ":")),
                    ingested_at,
                ),
            )
            row = self._connection.execute(
                "SELECT * FROM network_events WHERE tenant_id = ? AND event_id = ?",
                (tenant_id, event_id),
            ).fetchone()
            return self._to_dict(row), True

    def get(self, tenant_id: str, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM network_events WHERE tenant_id = ? AND event_id = ?",
                (tenant_id, event_id),
            ).fetchone()
        return self._to_dict(row) if row is not None else None

    def list_incidents(self, tenant_id: str, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM network_events
                WHERE tenant_id = ? AND json_extract(prediction_json, '$.prediction') = 1
                ORDER BY ingested_at DESC, event_id DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        return [self._to_dict(row) for row in rows]

    def triage(
        self,
        tenant_id: str,
        event_id: str,
        decision: str,
        reviewed_by: str,
        recorded_at: str,
    ) -> dict[str, Any] | None:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE network_events
                SET triage_status = ?, reviewed_by = ?
                WHERE tenant_id = ? AND event_id = ?
                  AND json_extract(prediction_json, '$.prediction') = 1
                """,
                (decision, reviewed_by, tenant_id, event_id),
            )
            if cursor.rowcount != 1:
                return None
            self._connection.execute(
                """
                INSERT INTO triage_decisions (
                    tenant_id, event_id, decision, reviewed_by, recorded_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (tenant_id, event_id, decision, reviewed_by, recorded_at),
            )
            row = self._connection.execute(
                "SELECT * FROM network_events WHERE tenant_id = ? AND event_id = ?",
                (tenant_id, event_id),
            ).fetchone()
        return self._to_dict(row)

    def claim_splunk_delivery(self, tenant_id: str, event_id: str) -> bool:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE network_events SET splunk_status = 'sending'
                WHERE tenant_id = ? AND event_id = ? AND splunk_status = 'pending'
                """,
                (tenant_id, event_id),
            )
            return cursor.rowcount == 1

    def finish_splunk_delivery(
        self, tenant_id: str, event_id: str, succeeded: bool
    ) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                UPDATE network_events SET splunk_status = ?
                WHERE tenant_id = ? AND event_id = ? AND splunk_status = 'sending'
                """,
                ("delivered" if succeeded else "pending", tenant_id, event_id),
            )

    def _to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        prediction = json.loads(row["prediction_json"])
        with self._lock:
            history = self._connection.execute(
                """
                SELECT decision, reviewed_by, recorded_at
                FROM triage_decisions
                WHERE tenant_id = ? AND event_id = ?
                ORDER BY recorded_at, rowid
                """,
                (row["tenant_id"], row["event_id"]),
            ).fetchall()
        return {
            "event_id": row["event_id"],
            "prediction": prediction,
            "evidence_refs": json.loads(row["evidence_refs_json"]),
            "ingested_at": row["ingested_at"],
            "triage_status": row["triage_status"],
            "reviewed_by": row["reviewed_by"],
            "triage_history": [
                {
                    "decision": entry["decision"],
                    "reviewed_by": entry["reviewed_by"],
                    "recorded_at": entry["recorded_at"],
                }
                for entry in history
            ],
            "splunk_status": row["splunk_status"],
        }

    def close(self) -> None:
        with self._lock:
            self._connection.close()
