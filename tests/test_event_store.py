from __future__ import annotations

import os
import stat

from threat_detection.event_store import EventStore


def test_persistent_event_store_is_tenant_scoped_and_stores_no_features(
    tmp_path,
) -> None:
    database = tmp_path / "private" / "events.sqlite3"
    store = EventStore(str(database))
    prediction = {
        "event_id": "event-1",
        "prediction": 1,
        "class_label": "attack",
        "model_score": 0.81,
        "model_id": "approved-model",
        "schema_version": "1.0.0",
        "predicted_at": "2026-10-22T12:00:01Z",
    }
    stored, created = store.insert(
        tenant_id="tenant-a",
        event_id="event-1",
        payload_digest="digest-1",
        prediction=prediction,
        evidence_refs=["source://event-1"],
        ingested_at="2026-10-22T12:00:01Z",
    )
    assert created is True
    assert "features" not in stored["prediction"]
    assert store.get("tenant-b", "event-1") is None
    assert store.claim_splunk_delivery("tenant-a", "event-1") is True
    store.finish_splunk_delivery("tenant-a", "event-1", succeeded=False)
    assert store.claim_splunk_delivery("tenant-a", "event-1") is True
    store.finish_splunk_delivery("tenant-a", "event-1", succeeded=True)
    store.close()

    reopened = EventStore(str(database))
    record = reopened.get("tenant-a", "event-1")
    assert record is not None
    assert record["splunk_status"] == "delivered"
    assert reopened.lookup("tenant-a", "event-1", "digest-1") == record
    assert stat.S_IMODE(os.stat(database).st_mode) == 0o600
    reopened.close()
