from __future__ import annotations

import json

import pytest

from threat_detection.replay import DEFAULT_EVENTS_PATH, replay, service_url


def test_replayer_posts_fixture_events_with_bearer_token_without_echoing_secret(
    monkeypatch, capsys
) -> None:
    requests = []

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return b'[{"event_id":"demo-flow-001"}]'

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        return FakeResponse()

    monkeypatch.setattr("threat_detection.replay.urlopen", fake_urlopen)

    count = replay(
        DEFAULT_EVENTS_PATH,
        service_url("http://127.0.0.1:8000"),
        "private-demo-token",
    )
    output = capsys.readouterr().out

    assert count == 2
    assert len(requests) == 2
    assert all(
        request.get_header("Authorization") == "Bearer private-demo-token"
        for request, _timeout in requests
    )
    assert all(timeout == 10 for _request, timeout in requests)
    assert "private-demo-token" not in output
    assert json.loads(requests[0][0].data)["events"][0]["event_id"] == "demo-flow-001"


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.test",
        "ftp://127.0.0.1",
        "https://api.example.test/?x=1",
    ],
)
def test_replayer_rejects_insecure_or_malformed_service_urls(url: str) -> None:
    with pytest.raises(ValueError):
        service_url(url)


def test_replayer_allows_https_remote_services() -> None:
    assert (
        service_url("https://api.example.test/")
        == "https://api.example.test/v1/ingest"
    )
