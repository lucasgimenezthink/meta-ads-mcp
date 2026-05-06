"""Regression tests for token scrubbing in error payloads.

Graph API echoes the full request URL (including ?access_token=... and
&appsecret_proof=...) back in error responses. We must redact those before
returning the payload to MCP clients — otherwise long-lived System User
tokens and the appsecret_proof leak on every 4xx response.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest

from meta_ads_mcp.core.api import scrub_tokens, make_api_request


class TestScrubTokens:
    def test_redacts_access_token_in_url(self):
        url = "https://graph.facebook.com/v24.0/123/adcreatives?fields=id&access_token=EAAGm0PXSECRET&appsecret_proof=abc123"
        out = scrub_tokens(url)
        assert "EAAGm0PXSECRET" not in out
        assert "abc123" not in out
        assert "access_token=[REDACTED]" in out
        assert "appsecret_proof=[REDACTED]" in out

    def test_redacts_in_nested_dict_and_list(self):
        payload = {
            "error": {
                "message": "bad",
                "url": "https://x/y?access_token=SECRET",
            },
            "trail": [
                {"request_url": "https://x/z?appsecret_proof=PROOF&foo=1"},
            ],
            "access_token": "SECRET",
        }
        out = scrub_tokens(payload)
        assert "SECRET" not in json.dumps(out)
        assert "PROOF" not in json.dumps(out)
        assert out["access_token"] == "[REDACTED]"

    def test_passthrough_non_strings(self):
        assert scrub_tokens(42) == 42
        assert scrub_tokens(None) is None
        assert scrub_tokens(True) is True


@pytest.mark.asyncio
class TestMakeApiRequestErrorScrubbing:
    """Ensure make_api_request never leaks tokens on 4xx responses."""

    async def test_http_error_payload_contains_no_token(self):
        import httpx

        secret_token = "EAAGm0PXSUPERSECRETLONGTOKENVALUE"
        secret_proof = "deadbeefcafef00d"

        request = httpx.Request(
            "GET",
            f"https://graph.facebook.com/v24.0/123/adcreatives?fields=id&access_token={secret_token}&appsecret_proof={secret_proof}",
        )
        response = httpx.Response(
            400,
            request=request,
            json={
                "error": {
                    "message": "(#100) Tried accessing nonexisting field (adcreatives) on node type (Ad)",
                    "type": "OAuthException",
                    "code": 100,
                    "fbtrace_id": "abc",
                }
            },
        )
        # Mimic httpx's url echo — response.url normally equals request.url
        response._request = request

        async def fake_get(self, *args, **kwargs):
            return response

        with patch("httpx.AsyncClient.get", new=fake_get):
            result = await make_api_request("123/adcreatives", secret_token, {"fields": "id"})

        serialized = json.dumps(result)
        assert secret_token not in serialized, "access_token leaked in error payload"
        assert secret_proof not in serialized, "appsecret_proof leaked in error payload"
        assert "[REDACTED]" in serialized
