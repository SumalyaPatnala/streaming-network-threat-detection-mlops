from __future__ import annotations

import os
import sys
from pathlib import Path

from threat_detection.replay import DEFAULT_EVENTS_PATH, replay, service_url


def main() -> int:
    endpoint_value = os.environ.get("THREAT_API_URL", "http://127.0.0.1:8000")
    token = os.environ.get("THREAT_API_TOKEN")
    if not token:
        print("THREAT_API_TOKEN must contain an OIDC access token", file=sys.stderr)
        return 2
    events_path = Path(os.environ.get("THREAT_EVENTS_PATH", str(DEFAULT_EVENTS_PATH)))
    try:
        total = replay(events_path, service_url(endpoint_value), token)
    except (OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(f"Replayed {total} events", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
