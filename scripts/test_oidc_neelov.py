"""Small security smoke test; run inside the Neelov backend image."""

import asyncio
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi import HTTPException, Request
from jose import jwt
from jose.utils import base64url_encode

from backend.app.api.v1.endpoints import oidc


class ReachedDatabase(Exception):
    pass


class FakeSession:
    async def execute(self, statement):
        raise ReachedDatabase


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self.data


class FakeClient:
    def __init__(self, token, jwk):
        self.token = token
        self.jwk = jwk

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def get(self, url):
        if url.endswith(".well-known/openid-configuration"):
            return FakeResponse({
                "issuer": "https://auth.example/application/o/familybudget/",
                "authorization_endpoint": "https://auth.example/authorize",
                "token_endpoint": "https://auth.example/token",
                "jwks_uri": "https://auth.example/jwks",
            })
        return FakeResponse({"keys": [self.jwk]})

    async def post(self, url, data):
        return FakeResponse({"id_token": self.token})


def request(state="state", nonce="nonce", query_state=None):
    cookies = f"oidc_state=state; oidc_nonce={nonce}; oidc_verifier=verifier"
    return Request({
        "type": "http", "method": "GET", "path": "/api/v1/auth/oidc-callback",
        "headers": [(b"cookie", cookies.encode())],
        "query_string": urlencode({"state": query_state or state, "code": "code"}).encode(),
    })


async def expect_status(expected, req):
    try:
        await oidc.oidc_callback(req, FakeSession())
    except HTTPException as exc:
        assert exc.status_code == expected, (exc.status_code, expected)
    else:
        raise AssertionError(f"Expected HTTP {expected}")


async def main():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256",
        "n": base64url_encode(public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")).decode(),
        "e": base64url_encode(public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")).decode(),
    }
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    claims = {
        "iss": "https://auth.example/application/o/familybudget/",
        "aud": "familybudget", "sub": "stable-subject", "nonce": "nonce",
        "email": "user@example.com", "email_verified": False,
        "groups": ["app-familybudget-users"],
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }

    def client_for(payload, signing_key=pem):
        token = jwt.encode(payload, signing_key, algorithm="RS256", headers={"kid": "test"})
        oidc.httpx.AsyncClient = lambda **kwargs: FakeClient(token, jwk)

    # State is rejected before any token exchange.
    client_for(claims)
    await expect_status(400, request(query_state="wrong"))

    # A signed, group-authorized token passes every cryptographic check.
    try:
        await oidc.oidc_callback(request(), FakeSession())
    except ReachedDatabase:
        pass
    else:
        raise AssertionError("Valid identity did not reach account lookup")

    client_for({**claims, "nonce": "other"})
    await expect_status(401, request())

    client_for({**claims, "groups": []})
    await expect_status(403, request())

    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    client_for(claims, signing_key=other_pem)
    await expect_status(401, request())
    print("OIDC state, signature, nonce, group, and valid-token checks passed")


if __name__ == "__main__":
    asyncio.run(main())
