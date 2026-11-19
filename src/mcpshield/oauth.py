"""Validate signed OAuth access tokens for the proxy's resource audience."""

import re

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+")


class JWTBearer:
    """Verify RFC 9068 access tokens with a configured RSA public key."""

    def __init__(self, public_key, issuer, audience):
        if not issuer or not audience:
            raise ValueError("issuer and audience are required")
        self.key = load_pem_public_key(public_key)
        if not isinstance(self.key, RSAPublicKey) or self.key.key_size < 2048:
            raise ValueError("an RSA public key of at least 2048 bits is required")
        self.issuer = issuer
        self.audience = audience

    async def __call__(self, token):
        try:
            verified = jwt.decode_complete(
                token, self.key, algorithms=["RS256"], issuer=self.issuer,
                audience=self.audience,
                options={"require": ["iss", "aud", "exp", "iat", "sub", "client_id", "jti"]},
            )
        except jwt.InvalidTokenError:
            return None
        if verified["header"].get("typ") not in {"at+jwt", "application/at+jwt"}:
            return None
        claims = verified["payload"]
        if any(not isinstance(claims[key], str) or not claims[key]
               for key in ("sub", "client_id", "jti")):
            return None
        raw_scope = claims.get("scope", "")
        if not isinstance(raw_scope, str):
            return None
        scopes = raw_scope.split(" ") if raw_scope else []
        if any(not SCOPE_TOKEN.fullmatch(scope) for scope in scopes):
            return None
        return frozenset(scopes)
