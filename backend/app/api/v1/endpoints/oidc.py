"""Authentik OpenID Connect login for the Neelov Family Budget deployment."""

import base64
import hashlib
import logging
import secrets
from datetime import datetime
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from jose import JWTError, jwt
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from backend.app.core.config import get_settings
from backend.app.db.session import get_session
from backend.app.models.refresh_token import RefreshToken
from backend.app.models.user import User
from backend.app.services.jwt import (
    create_access_token,
    create_refresh_token,
    hash_token,
)
from backend.app.services.user_service import create_initial_history, update_user_profile

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)


def _configuration():
    settings = get_settings()
    if not all((settings.OIDC_DISCOVERY_URL, settings.OIDC_CLIENT_ID,
                settings.OIDC_CLIENT_SECRET, settings.OIDC_REDIRECT_URI)):
        raise HTTPException(status_code=503, detail="OIDC is not configured")
    return settings


async def _discovery(client: httpx.AsyncClient, url: str) -> dict:
    try:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()
        if not all(data.get(key) for key in (
            "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"
        )):
            raise ValueError("Incomplete OIDC discovery document")
        return data
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("OIDC discovery failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Identity provider unavailable") from exc


@router.get("/oidc-login")
async def oidc_login() -> RedirectResponse:
    settings = _configuration()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    async with httpx.AsyncClient(timeout=10.0) as client:
        discovery = await _discovery(client, settings.OIDC_DISCOVERY_URL)

    query = urlencode({
        "response_type": "code",
        "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": settings.OIDC_REDIRECT_URI,
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    response = RedirectResponse(f"{discovery['authorization_endpoint']}?{query}", status_code=302)
    for name, value in (("oidc_state", state), ("oidc_nonce", nonce), ("oidc_verifier", verifier)):
        response.set_cookie(name, value, max_age=300, secure=settings.APP_ENV == "production",
                            httponly=True, samesite="lax", path="/api/v1/auth/oidc-callback")
    return response


@router.get("/oidc-callback")
async def oidc_callback(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    settings = _configuration()
    state = request.query_params.get("state", "")
    code = request.query_params.get("code", "")
    expected_state = request.cookies.get("oidc_state", "")
    nonce = request.cookies.get("oidc_nonce", "")
    verifier = request.cookies.get("oidc_verifier", "")
    if (not code or not state or not expected_state or not nonce or not verifier
            or not secrets.compare_digest(state, expected_state)):
        raise HTTPException(status_code=400, detail="Invalid OIDC callback")

    async with httpx.AsyncClient(timeout=10.0) as client:
        discovery = await _discovery(client, settings.OIDC_DISCOVERY_URL)
        try:
            token_response = await client.post(
                discovery["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": settings.OIDC_REDIRECT_URI,
                    "client_id": settings.OIDC_CLIENT_ID,
                    "client_secret": settings.OIDC_CLIENT_SECRET,
                    "code_verifier": verifier,
                },
            )
            token_response.raise_for_status()
            tokens = token_response.json()
            jwks_response = await client.get(discovery["jwks_uri"])
            jwks_response.raise_for_status()
            jwks = jwks_response.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("OIDC exchange failed: %s", type(exc).__name__)
            raise HTTPException(status_code=502, detail="OIDC token exchange failed") from exc

    id_token = tokens.get("id_token")
    if not isinstance(id_token, str):
        raise HTTPException(status_code=401, detail="OIDC ID token missing")
    try:
        header = jwt.get_unverified_header(id_token)
        if header.get("alg") != "RS256" or not header.get("kid"):
            raise ValueError("Unsupported OIDC signing key")
        key = next(key for key in jwks["keys"] if key.get("kid") == header["kid"])
        claims = jwt.decode(
            id_token, key, algorithms=["RS256"],
            audience=settings.OIDC_CLIENT_ID, issuer=discovery["issuer"],
        )
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise ValueError("OIDC nonce mismatch")
    except (JWTError, ValueError, KeyError, StopIteration, TypeError) as exc:
        logger.warning("OIDC ID token rejected: %s", type(exc).__name__)
        raise HTTPException(status_code=401, detail="Invalid OIDC ID token") from exc

    subject = claims.get("sub")
    email = claims.get("email")
    groups = claims.get("groups", [])
    if (not isinstance(subject, str) or not subject or len(subject) > 255
            or not isinstance(email, str) or not email.strip() or len(email) > 320
            or not isinstance(groups, list) or not all(isinstance(group, str) for group in groups)):
        raise HTTPException(status_code=403, detail="Required OIDC identity claims missing")
    email = email.strip().lower()
    group_set = set(groups)
    if not group_set.intersection({settings.OIDC_USERS_GROUP, settings.OIDC_ADMINS_GROUP}):
        raise HTTPException(status_code=403, detail="Family Budget group membership required")
    is_admin = settings.OIDC_ADMINS_GROUP in group_set

    user = (await session.execute(select(User).where(User.oidc_sub == subject))).scalar_one_or_none()
    if user is None:
        # Never link an OIDC identity to an existing account by email alone.
        if (await session.execute(select(User).where(User.email == email))).scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email belongs to another account")
        user = User(
            oidc_sub=subject, email=email,
            first_name=claims.get("given_name") or None,
            last_name=claims.get("family_name") or None,
            is_admin=is_admin, is_active=True,
        )
        session.add(user)
        try:
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="Identity already exists") from exc
        await session.refresh(user)
        await create_initial_history(session, user)
    else:
        if user.email != email:
            existing = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
            if existing is not None:
                raise HTTPException(status_code=409, detail="Email belongs to another account")
        user = await update_user_profile(
            session, user,
            {"email": email, "is_admin": is_admin, "is_active": True},
            change_type="LOGIN", changed_by_user_id=None,
        )

    user.last_login_at = datetime.utcnow()
    session.add(user)
    access_token = create_access_token(user_id=user.id, telegram_id=None)
    refresh_token, refresh_expires = create_refresh_token(user_id=user.id)
    session.add(RefreshToken(
        user_id=user.id, token_hash=hash_token(refresh_token), expires_at=refresh_expires,
    ))
    await session.commit()

    # Upstream uses this page to initialize its client-side storage before the dashboard.
    from backend.app.main import templates
    response = templates.TemplateResponse("auth_redirect.html", {
        "request": request, "target_url": "/",
    })
    for name, value, max_age in (
        ("access_token", access_token, settings.JWT_EXPIRE_DAYS * 86400),
        ("refresh_token", refresh_token, 86400),
    ):
        response.set_cookie(name, value, max_age=max_age, secure=settings.APP_ENV == "production",
                            httponly=True, samesite="lax", path="/")
    for name in ("oidc_state", "oidc_nonce", "oidc_verifier"):
        response.delete_cookie(name, path="/api/v1/auth/oidc-callback")
    return response
