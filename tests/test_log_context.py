"""Derivation and caching of the identity fields bound to every log line."""

import time

import pytest
from gg_api_core.log_context import (
    _IDENTITY_CACHE_MAX_ENTRIES,
    _IDENTITY_TTL_SECONDS,
    _identity_cache,
    _identity_cache_key,
    clear_caller_identity_cache,
    derive_caller_identity,
    derive_client_identity,
    resolve_caller_identity,
    scopes_fingerprint,
)

# Shape of a real GET /api_tokens/self response, trimmed to the fields we read.
TOKEN_INFO = {
    "id": "d0ca9877-641f-4c37-8857-c08e0ae148c4",
    "name": "ggmcp CI",
    "type": "personal_access_token",
    "scopes": ["scan", "incidents:read"],
    "member_id": 480870,
    "workspace_id": 8,
    "status": "active",
}


@pytest.fixture(autouse=True)
def _clean_cache():
    clear_caller_identity_cache(all_tokens=True)
    yield
    clear_caller_identity_cache(all_tokens=True)


class TestScopesFingerprint:
    def test_is_order_independent(self):
        """
        GIVEN the same scope set listed in two orders
        WHEN each is fingerprinted
        THEN both produce the same digest
        """
        assert scopes_fingerprint(["a", "b"]) == scopes_fingerprint(["b", "a"])

    def test_differs_for_a_different_scope_set(self):
        """
        GIVEN two different scope sets
        WHEN each is fingerprinted
        THEN the digests differ
        """
        assert scopes_fingerprint(["a", "b"]) != scopes_fingerprint(["a", "b", "c"])


class TestDeriveCallerIdentity:
    def test_maps_the_api_payload_to_log_fields(self):
        """
        GIVEN a token info payload and an API URL
        WHEN caller identity is derived
        THEN workspace, member, token and host identifiers are returned
        """
        identity = derive_caller_identity(TOKEN_INFO, api_url="https://api.eu1.gitguardian.com/v1")

        assert identity["account_id"] == 8
        assert identity["workspace_id"] == 8
        assert identity["member_id"] == 480870
        assert identity["token_id"] == TOKEN_INFO["id"]
        assert identity["token_type"] == "personal_access_token"
        assert identity["gg_host"] == "api.eu1.gitguardian.com"
        assert identity["token_scopes_hash"] == scopes_fingerprint(TOKEN_INFO["scopes"])

    def test_never_returns_the_scope_list_or_token_name(self):
        """
        GIVEN a token info payload
        WHEN caller identity is derived
        THEN the raw scope list is reduced to a fingerprint
        """
        identity = derive_caller_identity(TOKEN_INFO)

        assert "scopes" not in identity
        assert TOKEN_INFO["scopes"][0] not in str(identity)

    def test_omits_fields_the_payload_does_not_carry(self):
        """
        GIVEN a payload missing most fields
        WHEN caller identity is derived
        THEN absent fields are omitted rather than bound as None
        """
        identity = derive_caller_identity({"workspace_id": 8})

        assert identity == {"account_id": 8, "workspace_id": 8}


class TestDeriveClientIdentity:
    def test_maps_client_info_and_protocol_version(self):
        """
        GIVEN an initialize payload's clientInfo and protocol version
        WHEN client identity is derived
        THEN name, version and protocol revision are returned
        """
        from types import SimpleNamespace

        identity = derive_client_identity(SimpleNamespace(name="cursor", version="1.4.0"), "2025-06-18")

        assert identity == {
            "client_name": "cursor",
            "client_version": "1.4.0",
            "protocol_version": "2025-06-18",
        }

    def test_tolerates_a_missing_client_info(self):
        """
        GIVEN an initialize payload with no clientInfo
        WHEN client identity is derived
        THEN an empty mapping is returned
        """
        assert derive_client_identity(None) == {}


class TestResolveCallerIdentity:
    async def test_fetches_once_per_token(self):
        """
        GIVEN two lookups for the same token
        WHEN caller identity is resolved
        THEN the API is queried only the first time
        """
        calls = 0

        async def fetch():
            nonlocal calls
            calls += 1
            return TOKEN_INFO

        first = await resolve_caller_identity(fetch, token="tok-a")
        second = await resolve_caller_identity(fetch, token="tok-a")

        assert first == second
        assert calls == 1

    async def test_does_not_share_identity_between_tokens(self):
        """
        GIVEN two different tokens
        WHEN caller identity is resolved for each
        THEN each gets its own payload
        """

        async def fetch_a():
            return TOKEN_INFO

        async def fetch_b():
            return {**TOKEN_INFO, "workspace_id": 99, "member_id": 1}

        a = await resolve_caller_identity(fetch_a, token="tok-a")
        b = await resolve_caller_identity(fetch_b, token="tok-b")

        assert a["workspace_id"] == 8
        assert b["workspace_id"] == 99

    async def test_returns_nothing_when_the_token_is_rejected(self):
        """
        GIVEN a token the API rejects
        WHEN caller identity is resolved
        THEN an empty mapping is returned rather than raising
        """

        async def fetch():
            raise RuntimeError("401 Unauthorized")

        assert await resolve_caller_identity(fetch, token="tok-bad") == {}

    async def test_does_not_retry_a_rejected_token_on_every_message(self):
        """
        GIVEN a token the API rejects
        WHEN identity is resolved repeatedly
        THEN the failed lookup is not repeated
        """
        calls = 0

        async def fetch():
            nonlocal calls
            calls += 1
            raise RuntimeError("401 Unauthorized")

        for _ in range(3):
            await resolve_caller_identity(fetch, token="tok-bad")

        assert calls == 1

    async def test_caches_when_the_server_holds_no_token(self):
        """
        GIVEN no bearer token (stdio modes resolve it inside the client)
        WHEN caller identity is resolved twice
        THEN the lookup is still cached under a fixed key
        """
        calls = 0

        async def fetch():
            nonlocal calls
            calls += 1
            return TOKEN_INFO

        await resolve_caller_identity(fetch, token=None)
        await resolve_caller_identity(fetch, token=None)

        assert calls == 1

    async def test_does_not_retry_a_failing_lookup_when_the_server_holds_no_token(self):
        """
        GIVEN no bearer token and a GitGuardian API that is failing
        WHEN identity is resolved repeatedly
        THEN the failed lookup is not repeated
        """
        calls = 0

        async def fetch():
            nonlocal calls
            calls += 1
            raise RuntimeError("connection refused")

        for _ in range(5):
            await resolve_caller_identity(fetch, token=None)

        assert calls == 1

    async def test_evicts_one_entry_at_a_time_when_full(self):
        """
        GIVEN a cache filled to its bound
        WHEN one more token is resolved
        THEN only the oldest entry is dropped
        """

        async def fetch():
            return TOKEN_INFO

        for i in range(_IDENTITY_CACHE_MAX_ENTRIES):
            await resolve_caller_identity(fetch, token=f"tok-{i}")
        assert len(_identity_cache) == _IDENTITY_CACHE_MAX_ENTRIES

        await resolve_caller_identity(fetch, token="tok-new")

        assert len(_identity_cache) == _IDENTITY_CACHE_MAX_ENTRIES
        assert _identity_cache_key("tok-0") not in _identity_cache
        assert _identity_cache_key("tok-new") in _identity_cache

    async def test_expires_after_the_ttl(self, monkeypatch):
        """
        GIVEN a cached identity older than the TTL
        WHEN it is resolved again
        THEN the API is queried afresh
        """
        calls = 0

        async def fetch():
            nonlocal calls
            calls += 1
            return TOKEN_INFO

        await resolve_caller_identity(fetch, token="tok-a")
        clock = [time.monotonic() + _IDENTITY_TTL_SECONDS + 1]
        monkeypatch.setattr(time, "monotonic", lambda: clock[0])

        await resolve_caller_identity(fetch, token="tok-a")

        assert calls == 2


class TestClearCallerIdentityCache:
    async def test_revoking_one_token_leaves_other_tenants_cached(self):
        """
        GIVEN two tenants with cached identities
        WHEN one token's entry is cleared
        THEN the other tenant's entry survives
        """
        calls: dict[str, int] = {"a": 0, "b": 0}

        def fetcher(name):
            async def fetch():
                calls[name] += 1
                return TOKEN_INFO

            return fetch

        await resolve_caller_identity(fetcher("a"), token="tok-a")
        await resolve_caller_identity(fetcher("b"), token="tok-b")

        clear_caller_identity_cache("tok-a")

        await resolve_caller_identity(fetcher("a"), token="tok-a")
        await resolve_caller_identity(fetcher("b"), token="tok-b")

        assert calls == {"a": 2, "b": 1}
