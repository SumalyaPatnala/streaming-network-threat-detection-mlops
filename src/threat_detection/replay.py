from __future__ import annotations

import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

DEFAULT_EVENTS_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "samples" / "network-events.jsonl"
)


def service_url(value: str) -> str:
    parsed = urlparse(value)
    if (
        not parsed.netloc
        or parsed.scheme not in {"http", "https"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("THREAT_API_URL must be an HTTP(S) service URL")
    if parsed.scheme != "https" and parsed.hostname not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        raise ValueError("Bearer tokens may only be sent over HTTPS or loopback HTTP")
    path = parsed.path.rstrip("/") + "/v1/ingest"
    return urlunparse(parsed._replace(path=path, params="", query="", fragment=""))


def replay(events_path: Path, endpoint: str, token: str) -> int:
    count = 0
    for line_number, line in enumerate(
        events_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"Invalid JSON on fixture line {line_number}") from error
        payload = json.dumps(
            {"events": [event]}, separators=(",", ":")
        ).encode("utf-8")
        request = Request(
            endpoint,
            data=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                result = json.loads(response.read())
                if not 200 <= response.status < 300:
                    raise RuntimeError(
                        f"Ingestion failed for fixture line {line_number}: HTTP {response.status}"
                    )
        except HTTPError as error:
            raise RuntimeError(
                f"Ingestion failed for fixture line {line_number}: HTTP {error.code}"
            ) from error
        except URLError as error:
            raise RuntimeError(
                f"Unable to reach inference service for fixture line {line_number}"
            ) from error
        if not isinstance(result, list) or len(result) != 1:
            raise RuntimeError("Inference service returned an unexpected response shape")
        print(json.dumps(result[0], separators=(",", ":")))
        count += 1
    return count
