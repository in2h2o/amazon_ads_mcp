"""OAuth regression tests. All Amazon traffic is mocked; no ad writes."""

import hashlib
import base64
import time
import re
import json
from types import SimpleNamespace
from urllib.parse import urlsplit, parse_qs

import httpx
import pytest
from fastmcp import FastMCP
from fastmcp.server.auth.auth import AccessToken
from key_value.aio.stores.memory import MemoryStore

from amazon_ads_mcp.server import chatgpt_oauth as oauth


@pytest.fixture
def provider(monkeypatch):
    monkeypatch.setenv("MCP_OAUTH_ENABLED", "true")
    monkeypatch.setenv("AMAZON_ADS_PUBLIC_BASE_URL", "https://ads.example.com")
    settings = SimpleNamespace(
        effective_client_id="amazon-client", effective_client_secret="test-secret-only"
    )
    direct = SimpleNamespace(
        provider_type="direct",
        client_id="amazon-client",
        get_region_endpoint=lambda: "https://advertising-api.amazon.com",
    )
    # Keep tests independent of the user's filesystem and credentials.
    real = oauth.OAuthProxy
    monkeypatch.setattr(
        oauth, "OAuthProxy", lambda **kw: real(**kw, client_storage=MemoryStore())
    )
    return oauth.create_chatgpt_oauth(settings, direct)


@pytest.mark.asyncio
async def test_discovery_and_unauthenticated_mcp(provider):
    app = FastMCP("oauth-test", auth=provider).http_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://ads.example.com"
    ) as c:
        for path in ["/mcp", "/mcp/"]:
            r = await c.post(
                path,
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                follow_redirects=True,
            )
            assert r.status_code == 401
            assert "resource_metadata=" in r.headers["www-authenticate"]
        discovery = (await c.get("/.well-known/oauth-authorization-server")).json()
        assert (
            discovery["authorization_endpoint"] == "https://ads.example.com/authorize"
        )
        assert "S256" in discovery["code_challenge_methods_supported"]
        resource = (await c.get("/.well-known/oauth-protected-resource/mcp")).json()
        assert resource["resource"] == "https://ads.example.com/mcp"
        assert resource["authorization_servers"] == ["https://ads.example.com/"]


@pytest.mark.asyncio
@pytest.mark.parametrize("callback", [
    "https://chatgpt.com/connector/oauth/test-callback",
    "http://127.0.0.1:51671/callback/test-callback",
])
async def test_registration_redirect_and_pkce(provider, callback):
    app = FastMCP("oauth-test", auth=provider).http_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://ads.example.com"
    ) as c:
        client = await c.post(
            "/register",
            json={
                "redirect_uris": [callback],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )
        assert client.status_code == 201, client.text
        client_id = client.json()["client_id"]
        verifier = "a" * 64
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        params = {
            "client_id": client_id,
            "redirect_uri": callback,
            "response_type": "code",
            "scope": oauth.ADS_SCOPE,
            "state": "chatgpt-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": "https://ads.example.com/mcp",
        }
        r = await c.get("/authorize", params=params)
        assert r.status_code in (302, 303), r.text
        assert urlsplit(r.headers["location"]).path == "/consent"
        bad = await c.get(
            "/authorize",
            params={**params, "redirect_uri": "https://evil.example/callback"},
        )
        assert bad.status_code == 400
        for rejected in [
            "http://127.0.0.1:51671@evil.example/callback/test",
            "http://127.0.0.1.evil.example:51671/callback/test",
            "http://192.168.1.1:51671/callback/test",
            "http://127.0.0.1:51671/unrelated/test",
        ]:
            bad = await c.get(
                "/authorize", params={**params, "redirect_uri": rejected}
            )
            assert bad.status_code == 400
        missing_pkce = {
            k: v for k, v in params.items() if not k.startswith("code_challenge")
        }
        bad = await c.get("/authorize", params=missing_pkce)
        assert bad.status_code == 400 or "error=" in bad.headers.get("location", "")
        fake_code = await c.post(
            "/token",
            data={
                "client_id": client_id,
                "grant_type": "authorization_code",
                "code": "forged",
                "code_verifier": verifier,
                "redirect_uri": callback,
            },
        )
        assert fake_code.status_code in (400, 401)
        # A forged Amazon callback cannot seed credentials.
        callback_response = await c.get(
            "/auth/callback", params={"code": "forged", "state": "forged"}
        )
        assert callback_response.status_code == 400


@pytest.mark.asyncio
async def test_verifier_read_only_and_fail_closed(respx_mock):
    verifier = oauth.AmazonAdsTokenVerifier(
        "client", "https://advertising-api.amazon.com"
    )
    route = respx_mock.get("https://advertising-api.amazon.com/v2/profiles").mock(
        return_value=httpx.Response(200, json=[{"profileId": 123}])
    )
    token = await verifier.verify_token("amazon-access")
    assert token.claims["amazon_ads_verified"]
    assert route.calls[0].request.headers["Amazon-Advertising-API-ClientId"] == "client"
    assert "amazon-access" not in str(route.calls[0].request.url)
    route.mock(return_value=httpx.Response(401))
    assert await verifier.verify_token("invalid") is None
    route.mock(return_value=httpx.Response(200, json={"error": "bad"}))
    assert await verifier.verify_token("invalid") is None


def test_request_credentials_never_fall_back_to_shared_token(monkeypatch):
    direct = SimpleNamespace(
        client_id="client",
        get_region_endpoint=lambda: "https://advertising-api.amazon.com",
    )
    monkeypatch.setattr(oauth, "get_access_token", lambda: None)
    with pytest.raises(oauth.AuthenticationError):
        oauth.request_amazon_credentials(direct)
    identities = []
    for name in ["alice", "bob"]:
        token = AccessToken(
            token=name,
            client_id="client",
            scopes=[oauth.ADS_SCOPE],
            expires_at=int(time.time()) + 60,
            claims={"amazon_ads_verified": True},
        )
        monkeypatch.setattr(oauth, "get_access_token", lambda: token)
        credentials = oauth.request_amazon_credentials(direct)
        assert credentials.access_token == name
        identities.append(credentials.identity_id)
    assert identities[0] != identities[1]


def test_secure_configuration(provider, monkeypatch):
    monkeypatch.setenv("MCP_ALLOW_UNAUTH_HTTP", "true")
    settings = SimpleNamespace(
        effective_client_id="client", effective_client_secret="secret"
    )
    direct = SimpleNamespace(
        provider_type="direct",
        get_region_endpoint=lambda: "https://advertising-api.amazon.com",
    )
    with pytest.raises(ValueError, match="unauthenticated"):
        oauth.create_chatgpt_oauth(settings, direct)


@pytest.mark.asyncio
async def test_static_token_cannot_bypass_oauth(provider, monkeypatch):
    monkeypatch.setenv("MCP_INBOUND_TOKEN", "x" * 40)
    app = FastMCP("oauth-test", auth=provider).http_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://ads.example.com"
    ) as c:
        r = await c.post(
            "/mcp",
            headers={"Authorization": "Bearer " + "x" * 40},
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        )
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_complete_oauth_exchange_refresh_and_replay(provider, respx_mock):
    """Exercise the real SDK routes, with only Amazon endpoints mocked."""
    respx_mock.post("https://api.amazon.com/auth/o2/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "upstream-access",
                "refresh_token": "upstream-refresh",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": oauth.ADS_SCOPE,
            },
        )
    )
    respx_mock.get("https://advertising-api.amazon.com/v2/profiles").mock(
        return_value=httpx.Response(200, json=[{"profileId": 123}])
    )
    mcp = FastMCP("oauth-test", auth=provider)
    app = mcp.http_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://ads.example.com"
    ) as c:
        callback = "https://chatgpt.com/connector/oauth/test-callback"
        client = (
            await c.post(
                "/register",
                json={
                    "redirect_uris": [callback],
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                },
            )
        ).json()
        verifier = "a" * 64
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        r = await c.get(
            "/authorize",
            params={
                "client_id": client["client_id"],
                "redirect_uri": callback,
                "response_type": "code",
                "scope": oauth.ADS_SCOPE,
                "state": "original-state",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": "https://ads.example.com/mcp",
            },
        )
        consent = await c.get(r.headers["location"])
        txn = re.search(r'name="txn_id" value="([^"]+)"', consent.text).group(1)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', consent.text).group(1)
        approve = await c.post(
            "/consent", data={"txn_id": txn, "csrf_token": csrf, "action": "approve"}
        )
        assert approve.status_code == 302
        amazon_url = urlsplit(approve.headers["location"])
        assert amazon_url.netloc == "www.amazon.com"
        amazon_params = parse_qs(amazon_url.query)
        assert amazon_params["redirect_uri"] == [
            "https://ads.example.com/auth/callback"
        ]
        complete = await c.get(
            "/auth/callback",
            params={"state": amazon_params["state"][0], "code": "amazon-code"},
        )
        assert complete.status_code == 302, complete.text
        returned = parse_qs(urlsplit(complete.headers["location"]).query)
        assert returned["state"] == ["original-state"]
        exchange = {
            "grant_type": "authorization_code",
            "client_id": client["client_id"],
            "code": returned["code"][0],
            "redirect_uri": callback,
            "code_verifier": verifier,
            "resource": "https://ads.example.com/mcp",
        }
        wrong = await c.post("/token", data={**exchange, "code_verifier": "b" * 64})
        assert wrong.status_code in (400, 401)
        result = await c.post("/token", data=exchange)
        assert result.status_code == 200, result.text
        tokens = result.json()
        assert tokens["access_token"] != "upstream-access"
        assert tokens["refresh_token"] != "upstream-refresh"
        verified = await provider.verify_token(tokens["access_token"])
        assert verified.token == "upstream-access"
        replay = await c.post("/token", data=exchange)
        assert replay.status_code in (400, 401)
        refreshed = await c.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client["client_id"],
                "refresh_token": tokens["refresh_token"],
            },
        )
        assert refreshed.status_code == 200, refreshed.text
        assert await provider.verify_token(refreshed.json()["access_token"])
        old_refresh = await c.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client["client_id"],
                "refresh_token": tokens["refresh_token"],
            },
        )
        assert old_refresh.status_code in (400, 401)


@pytest.mark.asyncio
async def test_authenticated_mcp_calls_keep_credentials_and_profiles_isolated(
    provider, monkeypatch
):
    from amazon_ads_mcp.auth.manager import get_auth_manager
    from amazon_ads_mcp.server.inbound_auth import create_inbound_http_auth_middleware
    from amazon_ads_mcp.middleware.authentication import AuthSessionStateMiddleware

    manager = get_auth_manager()

    async def verify(token):
        if token not in {"alice", "bob"}:
            return None
        return AccessToken(
            token=token,
            client_id="amazon-client",
            scopes=[oauth.ADS_SCOPE],
            expires_at=int(time.time()) + 3600,
            claims={"amazon_ads_verified": True},
        )

    monkeypatch.setattr(provider, "verify_token", verify)
    mcp = FastMCP("isolation-test", auth=provider, tasks=False)
    mcp.add_middleware(create_inbound_http_auth_middleware(manager, "0.0.0.0"))
    mcp.add_middleware(AuthSessionStateMiddleware())

    @mcp.tool
    async def probe(profile: str | None = None) -> dict:
        if profile:
            manager.set_active_profile_id(profile)
        return {
            "token": (await manager.get_active_credentials()).access_token,
            "profile": manager.get_active_profile_id(),
            "identity": manager.get_active_identity_id(),
        }

    app = mcp.http_app(json_response=True)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://ads.example.com"
        ) as c:
            headers = {
                "Authorization": "Bearer alice",
                "Accept": "application/json, text/event-stream",
            }
            initialized = await c.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "1"},
                    },
                },
            )
            assert initialized.status_code == 200, initialized.text
            headers["Mcp-Session-Id"] = initialized.headers["mcp-session-id"]
            await c.post(
                "/mcp",
                headers=headers,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            )

            async def call(arguments):
                response = await c.post(
                    "/mcp",
                    headers=headers,
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "probe", "arguments": arguments},
                    },
                )
                assert response.status_code == 200, response.text
                result = response.json()["result"]
                assert not result.get("isError"), result
                return json.loads(result["content"][0]["text"])

            alice = await call({"profile": "123"})
            assert alice["token"] == "alice" and alice["profile"] == "123"
            again = await call({})
            assert again["profile"] == "123"
            headers["Authorization"] = "Bearer bob"
            bob = await call({})
            assert bob["token"] == "bob" and bob["profile"] is None
            assert bob["identity"] != alice["identity"]
