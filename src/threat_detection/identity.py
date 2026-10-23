from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import jwt
from jwt import PyJWKClient, PyJWKClientConnectionError, PyJWKClientError

TENANT_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class AuthenticationError(ValueError):
    pass


class IdentityProviderUnavailableError(RuntimeError):
    pass


@dataclass(frozen=True)
class TenantPrincipal:
    tenant_id: str
    subject: str
    roles: frozenset[str]


class OIDCVerifier:
    def __init__(self, issuer: str, audience: str, jwks_uri: str) -> None:
        parsed_jwks_uri = urlparse(jwks_uri)
        parsed_issuer = urlparse(issuer)
        if (
            not issuer
            or parsed_issuer.scheme != "https"
            or not parsed_issuer.netloc
            or not audience
            or parsed_jwks_uri.scheme != "https"
            or not parsed_jwks_uri.netloc
            or parsed_jwks_uri.username
            or parsed_jwks_uri.password
            or parsed_jwks_uri.fragment
        ):
            raise ValueError(
                "OIDC issuer, audience, and an HTTPS OIDC_JWKS_URL are required"
            )
        self.issuer = issuer
        self.audience = audience
        self._jwks = PyJWKClient(jwks_uri, cache_jwk_set=True, timeout=5)

    @classmethod
    def from_environment(cls) -> OIDCVerifier | None:
        values = {
            "issuer": os.environ.get("OIDC_ISSUER"),
            "audience": os.environ.get("OIDC_AUDIENCE"),
            "jwks_uri": os.environ.get("OIDC_JWKS_URL"),
        }
        if not any(values.values()):
            return None
        if not all(values.values()):
            raise RuntimeError(
                "OIDC_ISSUER, OIDC_AUDIENCE, and OIDC_JWKS_URL must be configured together"
            )
        issuer, audience, jwks_uri = (
            values["issuer"],
            values["audience"],
            values["jwks_uri"],
        )
        if issuer is None or audience is None or jwks_uri is None:
            raise RuntimeError("OIDC configuration is incomplete")
        return cls(issuer=issuer, audience=audience, jwks_uri=jwks_uri)

    def verify(self, token: str) -> TenantPrincipal:
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token).key
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256", "ES256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "sub"]},
            )
        except PyJWKClientConnectionError as error:
            raise IdentityProviderUnavailableError(
                "Unable to retrieve OIDC signing keys"
            ) from error
        except (jwt.PyJWTError, PyJWKClientError) as error:
            raise AuthenticationError("Invalid bearer token") from error

        tenant_id = claims.get("tenant_id")
        subject = claims.get("sub")
        roles = claims.get("roles")
        if (
            not isinstance(tenant_id, str)
            or not TENANT_PATTERN.fullmatch(tenant_id)
            or not isinstance(subject, str)
            or not subject
            or len(subject) > 256
            or not isinstance(roles, list)
            or not roles
            or any(not isinstance(role, str) or not role for role in roles)
        ):
            raise AuthenticationError("Required tenant identity claims are missing")
        return TenantPrincipal(
            tenant_id=tenant_id,
            subject=subject,
            roles=frozenset(roles),
        )
