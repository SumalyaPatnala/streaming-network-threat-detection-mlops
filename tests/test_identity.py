from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWKClientConnectionError

from threat_detection.identity import (
    AuthenticationError,
    IdentityProviderUnavailableError,
    OIDCVerifier,
)


class FakeSigningKey:
    def __init__(self, key) -> None:
        self.key = key


class FakeJwksClient:
    def __init__(self, key) -> None:
        self.signing_key = FakeSigningKey(key)

    def get_signing_key_from_jwt(self, _token: str) -> FakeSigningKey:
        return self.signing_key


@pytest.fixture
def verifier_and_key() -> tuple[OIDCVerifier, rsa.RSAPrivateKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = OIDCVerifier(
        issuer="https://identity.example.test/",
        audience="threat-detection-api",
        jwks_uri="https://identity.example.test/.well-known/jwks.json",
    )
    verifier._jwks = FakeJwksClient(private_key.public_key())
    return verifier, private_key


def encode_token(private_key, **overrides) -> str:
    claims = {
        "iss": "https://identity.example.test/",
        "aud": "threat-detection-api",
        "sub": "analyst-17",
        "tenant_id": "tenant-a",
        "roles": ["analyst", "events:write"],
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=5),
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256")


def test_verifies_signed_oidc_claims_and_uses_trusted_tenant(
    verifier_and_key,
) -> None:
    verifier, private_key = verifier_and_key

    principal = verifier.verify(encode_token(private_key))

    assert principal.tenant_id == "tenant-a"
    assert principal.subject == "analyst-17"
    assert principal.roles == {"analyst", "events:write"}


@pytest.mark.parametrize(
    "overrides",
    [
        {"tenant_id": None},
        {"tenant_id": "../tenant-b"},
        {"roles": []},
        {"iss": "https://attacker.example/"},
        {"aud": "another-api"},
        {"exp": datetime.now(UTC) - timedelta(minutes=1)},
    ],
)
def test_rejects_invalid_identity_claims(verifier_and_key, overrides) -> None:
    verifier, private_key = verifier_and_key

    with pytest.raises(AuthenticationError):
        verifier.verify(encode_token(private_key, **overrides))


def test_requires_complete_oidc_environment(monkeypatch) -> None:
    monkeypatch.setenv("OIDC_ISSUER", "https://identity.example.test/")
    monkeypatch.delenv("OIDC_AUDIENCE", raising=False)
    monkeypatch.delenv("OIDC_JWKS_URL", raising=False)

    with pytest.raises(RuntimeError, match="must be configured together"):
        OIDCVerifier.from_environment()


def test_rejects_non_https_jwks_url() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        OIDCVerifier(
            issuer="https://identity.example.test/",
            audience="api",
            jwks_uri="http://identity.example.test/jwks",
        )


def test_jwks_network_failure_is_distinguished_from_invalid_token(
    verifier_and_key,
) -> None:
    verifier, _private_key = verifier_and_key

    class UnavailableJwks:
        def get_signing_key_from_jwt(self, _token: str):
            raise PyJWKClientConnectionError("provider unavailable")

    verifier._jwks = UnavailableJwks()

    with pytest.raises(IdentityProviderUnavailableError):
        verifier.verify("signed-token")
