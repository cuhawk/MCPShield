import asyncio
from time import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mcpshield.oauth import JWTBearer


@pytest.fixture(scope="module")
def keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return key, JWTBearer(public, "https://issuer.example", "https://resource.example")


@pytest.mark.parametrize(("overrides", "token_type", "expected"), [
    ({}, "at+jwt", frozenset({"mcp:write", "files"})),
    ({"aud": "different"}, "at+jwt", None),
    ({"iss": "different"}, "at+jwt", None),
    ({"exp": 1}, "at+jwt", None),
    ({"scope": "files\tmcp:write"}, "at+jwt", None),
    ({"scope": []}, "at+jwt", None),
    ({}, "JWT", None),
    ({"sub": ""}, "at+jwt", None),
])
def test_oauth_validation(keys, overrides, token_type, expected):
    key, verifier = keys
    now = int(time())
    claims = {"iss": verifier.issuer, "aud": verifier.audience, "iat": now,
              "exp": now + 60, "sub": "user", "client_id": "client", "jti": "test",
              "scope": "mcp:write files"}
    token = jwt.encode(claims | overrides, key, algorithm="RS256", headers={"typ": token_type})
    assert asyncio.run(verifier(token)) == expected


def test_untrusted_signature(keys):
    _, verifier = keys
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode({}, other, algorithm="RS256", headers={"typ": "at+jwt"})
    assert asyncio.run(verifier(token)) is None
