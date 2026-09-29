# ChatGPT OAuth on Render Free

This fork adds an opt-in FastMCP OAuthProxy for direct Amazon Ads authentication.
It uses the existing Amazon client ID and secret. No paid auth provider, paid
database, or new hosting service is required.

## Render configuration

Keep the existing service and Free compute plan. Deploy the `fix/chatgpt-oauth`
branch of your editable copy, with these environment variables:

```text
AUTH_METHOD=direct
MCP_OAUTH_ENABLED=true
AMAZON_ADS_PUBLIC_BASE_URL=https://amazon-ads-direct.onrender.com
```

Keep `AMAZON_AD_API_CLIENT_ID` and `AMAZON_AD_API_CLIENT_SECRET` in Render's
secret environment variables. Do not commit them. An environment refresh token
is not needed in OAuth mode and is never used as a fallback for requests.
Do not enable `MCP_ALLOW_UNAUTH_HTTP`.

Amazon's security profile must have this exact Allowed Return URL:
`https://amazon-ads-direct.onrender.com/auth/callback`.
The server-to-server flow does not require a browser Allowed Origin.

Connect ChatGPT to `https://amazon-ads-direct.onrender.com/mcp`, select OAuth,
and use dynamic client registration (leave the ChatGPT-side client ID/secret
empty). The Amazon credentials belong only in Render, not ChatGPT's fields.
Approve the MCP consent page, then authenticate with Amazon. The Amazon scope
is `advertising::campaign_management`, the existing Ads API scope. This repair
and its tests do not invoke campaign/bid mutation APIs.

## Authentication and isolation

FastMCP handles discovery metadata, authorization-code + S256 PKCE, dynamic
client registration, browser-bound consent, callback state, one-use codes,
audience-bound reference access tokens, refresh rotation, and encrypted storage.
Only ChatGPT callback URL patterns are allowed. Amazon uses a confidential
client-secret POST exchange; downstream PKCE is always enforced.

Each incoming token is validated via a read-only Amazon profiles call with
the registered Amazon client ID. API calls and profile caches use the current
request's verified Amazon credential. Anonymous and static-token requests fail
closed. Existing non-OAuth deployments retain their original behavior.

OAuth mode disables background tasks, legacy shared OAuth management tools,
and local disk download routes/tools, whose storage was not isolated by OAuth
grant. Amazon report creation/status API tools remain available. Local disk
downloads require a separate grant-scoped storage implementation before they
can be safely enabled for multiple OAuth users.

## Free hosting limitation

The OAuth proxy's token/client store is encrypted on the container filesystem.
Render Free has no persistent disk. A redeploy or instance replacement can
discard that store; reconnect/re-authorize ChatGPT after that happens. This
fails closed and does not expose credentials. Keeping a permanent connection
across instance replacements would require a separately configured durable
store. No paid store is added by this change.

## Validation and rollback

Run `uv sync`, `uv run ruff check --fix`, and `uv run pytest` before release.
`tests/unit/test_chatgpt_oauth.py` mocks Amazon and covers discovery, authorization,
PKCE errors, callback state, code replay, refresh replay, static-token rejection,
request credential isolation, and the read-only token verification request.

After deployment, verify public discovery endpoints and HTTP 401 on anonymous
`/mcp`. Finish with an authenticated profile-list call in ChatGPT. Never use
a bid or campaign write as a smoke test.

To roll back, deploy upstream commit
`45c79b4518311127a5526bc9ddcd7bfd051b094c` and remove `MCP_OAUTH_ENABLED`.
Keep authentication enabled; do not use the unauthenticated HTTP bypass.
