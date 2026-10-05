# Neelov Authentik OIDC profile

`Dockerfile.neelov` derives from upstream backend `0.8.79` at a fixed OCI digest.
It copies only the modules changed for native Authentik login. PostgreSQL and
Redis use the upstream images. The Kubernetes manifests and secrets template are
maintained in `mambastick/neelov-cloud/familybudget/`.

Required environment: `DATABASE_URL`, `JWT_SECRET`, `API_INTERNAL_KEY`,
`CORS_ORIGINS`, `OIDC_DISCOVERY_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
`OIDC_REDIRECT_URI`, and `OIDC_ONLY=true`. The Authentik OAuth2 provider must
use a strict callback URI and include the `openid`, `email`, and `profile`
property mappings. The default Authentik profile mapping includes `groups`.
The application requires membership in `app-familybudget-users` or
`app-familybudget-admins`; the latter grants application admin access.

Accounts are keyed by the signed OIDC `sub` claim. Email is required by the
upstream user schema, but an existing account is never linked by matching email.
Authentik's default email mapping sets `email_verified=false`; this deployment
uses the administratively managed Authentik email after validating the signed
ID token, issuer, audience, nonce, authorization code PKCE, and group claims.

`OIDC_ONLY` closes the upstream Telegram, email/password, WebAuthn, and Telegram
WebApp login endpoints. The local access and refresh tokens expire after one
day in this profile. Existing sessions may remain valid until then after group
membership is removed. The browser starts a new Authentik login when needed.

Build from the repository root:

```bash
docker build -f Dockerfile.neelov -t ghcr.io/mambastick/familybudget-backend:<tag> .
```

The app image runs Alembic `upgrade head` as a Kubernetes init container.
The added migration creates the unique `oidc_sub` column. Keep the upstream
base image digest and the overlay in sync when updating the application.
