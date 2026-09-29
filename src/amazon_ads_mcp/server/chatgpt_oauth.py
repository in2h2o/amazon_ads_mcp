"""ChatGPT OAuth bridge to Login with Amazon, using FastMCP's OAuth proxy.

Amazon credentials stay server-side. MCP access tokens are audience-bound
reference tokens, not Amazon tokens. The SDK owns DCR, consent, state, PKCE,
one-use codes, refresh rotation, and encrypted token storage.
"""

import hashlib
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from fastmcp.server.auth import OAuthProxy, TokenVerifier
from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.dependencies import get_access_token

from ..exceptions import AuthenticationError
from ..models import AuthCredentials

ADS_SCOPE = "advertising::campaign_management"


def oauth_enabled() -> bool:
    return os.getenv("MCP_OAUTH_ENABLED", "false").lower() == "true"


class AmazonAdsTokenVerifier(TokenVerifier):
    """Validate opaque Amazon tokens with a read-only, client-bound API call."""

    def __init__(self, client_id: str, api_base_url: str):
        super().__init__(required_scopes=[ADS_SCOPE])
        self.client_id = client_id
        self.api_base_url = api_base_url

    async def verify_token(self, token: str) -> AccessToken | None:
        # Headers avoid leaking the bearer token in request URLs or HTTP logs.
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
                response = await client.get(
                    f"{self.api_base_url}/v2/profiles",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Amazon-Advertising-API-ClientId": self.client_id,
                    },
                )
            if response.status_code != 200 or not isinstance(response.json(), list):
                return None
        except (httpx.HTTPError, ValueError):
            return None
        return AccessToken(
            token=token,
            client_id=self.client_id,
            scopes=[ADS_SCOPE],
            expires_at=int(time.time()) + 60,
            claims={"amazon_ads_verified": True},
        )


def create_chatgpt_oauth(settings, provider) -> OAuthProxy | None:
    if not oauth_enabled():
        return None
    if provider.provider_type != "direct":
        raise ValueError("MCP OAuth requires AUTH_METHOD=direct")
    base_url = (
        os.getenv("AMAZON_ADS_PUBLIC_BASE_URL")
        or os.getenv("RENDER_EXTERNAL_URL")
        or ""
    ).rstrip("/")
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path
    ):
        raise ValueError("MCP OAuth requires a canonical HTTPS public base URL")
    if os.getenv("MCP_ALLOW_UNAUTH_HTTP", "").lower() in {"true", "1", "yes", "on"}:
        raise ValueError("MCP OAuth cannot be combined with unauthenticated HTTP")
    return OAuthProxy(
        upstream_authorization_endpoint="https://www.amazon.com/ap/oa",
        upstream_token_endpoint="https://api.amazon.com/auth/o2/token",
        upstream_client_id=settings.effective_client_id,
        upstream_client_secret=settings.effective_client_secret,
        token_verifier=AmazonAdsTokenVerifier(
            settings.effective_client_id, provider.get_region_endpoint()
        ),
        base_url=base_url,
        redirect_path="/auth/callback",
        valid_scopes=[ADS_SCOPE],
        allowed_client_redirect_uris=[
            "https://chatgpt.com/connector/oauth/*",
            "https://chat.openai.com/aip/*",
            # Work Mode uses a loopback listener with a per-login port/path.
            # FastMCP validates URL components and rejects userinfo injection.
            "http://127.0.0.1:*/callback/*",
        ],
        # Amazon's confidential web flow uses client_secret_post; PKCE remains
        # mandatory on the downstream ChatGPT-to-MCP authorization-code flow.
        forward_pkce=False,
        forward_resource=False,
        token_endpoint_auth_method="client_secret_post",
        require_authorization_consent=True,
        enable_cimd=False,
    )


def request_amazon_credentials(provider) -> AuthCredentials:
    """Use only this request's verified Amazon token; never shared defaults."""
    token = get_access_token()
    if not token or not token.claims.get("amazon_ads_verified"):
        raise AuthenticationError("Connect Amazon Ads Direct through OAuth first")
    return AuthCredentials(
        identity_id="oauth-" + hashlib.sha256(token.token.encode()).hexdigest(),
        access_token=token.token,
        expires_at=datetime.fromtimestamp(token.expires_at, timezone.utc),
        base_url=provider.get_region_endpoint(),
        headers={"Amazon-Advertising-API-ClientId": provider.client_id},
    )
