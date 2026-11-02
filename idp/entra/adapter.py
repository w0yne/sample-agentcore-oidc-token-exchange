"""Microsoft Entra ID adapter for managed Gateway and HTTP API JWT authorizers.

Tokens are returned to callers, never printed or verified by this module.
"""

import json
import os
import pathlib
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from lib import idp

NAME, PROVIDER = "entra", f"{idp.PREFIX}-entra"
USER_ID_CLAIM = "oid"  # Entra sub is pairwise per application; oid is stable within this tenant.
P = idp.PREFIX


def state() -> dict[str, Any]:
    """Read non-secret identifiers and refuse a different explicitly selected tenant."""
    with open(idp.state_file(NAME, "state"), encoding="utf-8") as file:
        value = json.load(file)
    if os.environ.get("ENTRA_TENANT_ID") and value["tenantId"] != os.environ["ENTRA_TENANT_ID"]:
        raise ValueError("Entra state does not match ENTRA_TENANT_ID")
    if value.get("prefix", P) != P:
        raise ValueError("Entra state does not match SAMPLE_PREFIX")
    return value


def issuer() -> str:
    """Return the tenant-specific v2 issuer, not a common or organizations issuer."""
    return f"https://login.microsoftonline.com/{state()['tenantId']}/v2.0"


def _scope(resource: str, value: str) -> str:
    return f"{state()[resource]['audience']}/{value}"


def login_raw(user: str, scope: str, client: str = "app") -> dict[str, Any]:
    """Use password grant for disposable tests only; real clients must use authorization code with PKCE."""
    if client not in ("app", "gateway", "noscope"):
        raise ValueError("client must be app, gateway or noscope")
    c = idp.secret(idp.secret_id(NAME, f"{client}-client"))
    users = idp.secret(idp.secret_id(NAME, "users"))
    return idp.post_form(
        f"https://login.microsoftonline.com/{state()['tenantId']}/oauth2/v2.0/token",
        {
            "grant_type": "password",
            "client_id": c["client_id"],
            "client_secret": c["client_secret"],
            "username": users[f"{P}-{user}"]["upn"],
            "password": users[f"{P}-{user}"]["password"],
            "scope": scope,
        },
    )


def token(user: str, resource: str) -> str:
    """Return an access token for the selected API."""
    value = {"gateway": "access", "resource": "resource.read"}[resource]
    return login_raw(user, _scope(resource, value))["access_token"]


def id_token(user: str) -> str:
    """Return an ID token for the client application, not either API."""
    return login_raw(user, _scope("resource", "resource.read") + " openid profile email")["id_token"]


def token_without_resource_scope(user: str) -> str:
    """Mint a resource-audience access token with only the negative-test scope."""
    return login_raw(user, _scope("resource", "resource.other"), client="noscope")["access_token"]


def other_resource_token(user: str) -> str:
    """Return an unrelated Microsoft Graph token for the audience-denial test."""
    return login_raw(user, "https://graph.microsoft.com/User.Read")["access_token"]


def other_client_token(user: str) -> str:
    """Mint a Gateway token from the middle-tier client to test the inbound azp gate."""
    return login_raw(user, _scope("gateway", "access"), client="gateway")["access_token"]


def door() -> dict[str, Any]:
    """Limit Gateway admission to its own app audience and the test client's azp."""
    s = state()
    return {
        "discovery_url": issuer() + "/.well-known/openid-configuration",
        "audiences": [s["gateway"]["appId"]],
        "client_claim": "azp",
        "client_value": s["app"]["appId"],
    }


def resource_api_config() -> dict[str, Any]:
    """Configure only the managed JWT issuer, GUID audience and route scope."""
    return {"issuer": issuer(), "audiences": [state()["resource"]["appId"]], "required_scope": "resource.read"}


def provider_input() -> tuple[str, dict[str, Any]]:
    """Use Identity's Microsoft provider with its preset on-behalf-of exchange."""
    s, gw = state(), idp.secret(idp.secret_id(NAME, "gateway-client"))
    if gw["tenant_id"] != s["tenantId"] or gw["client_id"] != s["gateway"]["appId"]:
        raise ValueError("Entra gateway credentials do not match state; use a separate prefix/state")
    return "MicrosoftOauth2", {
        "microsoftOauth2ProviderConfig": {
            "clientId": gw["client_id"],
            "clientSecret": gw["client_secret"],
            "tenantId": s["tenantId"],
        }
    }


def exchange_params() -> dict[str, Any]:
    """Gateway requests TOKEN_EXCHANGE; MicrosoftOauth2 supplies the OBO grant internally."""
    return {"scopes": [_scope("resource", "resource.read")], "custom": {}, "grant": "TOKEN_EXCHANGE"}


def expected_exchanged_azp() -> str:
    """Return the middle-tier application's GUID expected in T2."""
    return state()["gateway"]["appId"]


def expected_resource_aud() -> str:
    """Return the resource application's GUID expected in v2 T2."""
    return state()["resource"]["appId"]


def unconsented_scope() -> list[str]:
    """Return a scope for which the middle tier has no delegated consent."""
    return ["https://graph.microsoft.com/User.Read"]
