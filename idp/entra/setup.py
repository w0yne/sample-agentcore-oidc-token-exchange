#!/usr/bin/env python3
"""Set up disposable Entra apps, delegated consent and two synthetic users.

Requires IDP=entra, ENTRA_TENANT_ID and an interactive tenant-admin az login with MFA.
No security policies are changed. Client secrets expire after 90 days. Credentials
are stored only in Secrets Manager; local state contains identifiers, not secrets.
"""

import datetime
import json
import os
import pathlib
import re
import secrets
import string
import subprocess
import sys
import tempfile
import uuid
from typing import Any

import boto3

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from lib import idp

GRAPH = "https://graph.microsoft.com/v1.0"
P = idp.PREFIX
TAGS = [{"Key": "project", "Value": P}]
GRAPH_APP = "00000003-0000-0000-c000-000000000000"


def az(method: str, url: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run a fixed Graph command, with secret-bearing bodies in a mode-600 temporary file."""
    if method not in ("GET", "PATCH", "POST") or not url.startswith(GRAPH + "/"):
        raise ValueError("Only setup operations on Microsoft Graph are allowed")
    extra: list[str] = []
    tmp = None
    try:
        if body is not None:
            tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json")
            os.chmod(tmp.name, 0o600)
            json.dump(body, tmp)
            tmp.close()
            extra = ["--body", "@" + tmp.name, "--headers", "Content-Type=application/json"]
        response = subprocess.run(  # noqa: S603  fixed argv, no shell
            ["az", "rest", "--method", method, "--url", url, "-o", "json", *extra],  # noqa: S607  operator CLI
            capture_output=True,
            text=True,
        )
    finally:
        if tmp:
            tmp.close()
            os.unlink(tmp.name)
    if response.returncode:
        # CLI diagnostics can contain the request body; never print them with passwords.
        raise SystemExit(f"Graph {method} failed (exit {response.returncode}); check login, consent and tenant policy")
    return json.loads(response.stdout) if response.stdout.strip() else {}


def find(kind: str, field: str, value: str) -> str | None:
    """Find exactly one object; refuse ambiguous names rather than modifying an arbitrary object."""
    escaped = value.replace("'", "''")
    rows = az("GET", f"{GRAPH}/{kind}?$filter={field} eq '{escaped}'&$select=id")["value"]
    if len(rows) > 1:
        raise SystemExit(f"Multiple {kind} match {field}; use a fresh unique SAMPLE_PREFIX")
    return rows[0]["id"] if rows else None


def scope(existing: list[dict[str, Any]], value: str, desc: str) -> dict[str, Any]:
    """Build an enabled delegated scope, preserving its identifier across setup reruns."""
    old = next((s for s in existing if s["value"] == value), None)
    return {
        "id": old["id"] if old else str(uuid.uuid4()),
        "value": value,
        "type": "Admin",
        "isEnabled": True,
        "adminConsentDisplayName": desc,
        "adminConsentDescription": desc,
    }


def get_or_create_app(name: str, body: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Create or update an app and its service principal using its exact display name."""
    oid = find("applications", "displayName", name)
    if oid is None:
        oid = az("POST", f"{GRAPH}/applications", {"displayName": name, "signInAudience": "AzureADMyOrg"})["id"]
    current = az("GET", f"{GRAPH}/applications/{oid}")
    if "api" in body:
        # api://<appId> is the tenant-safe identifier URI; arbitrary prefix-only URIs can be refused.
        body = {**body, "identifierUris": [f"api://{current['appId']}"]}
        old = current.get("api", {}).get("oauth2PermissionScopes", [])
        body["api"]["oauth2PermissionScopes"] = [
            scope(old, s["value"], s["adminConsentDescription"]) for s in body["api"]["oauth2PermissionScopes"]
        ]
    az("PATCH", f"{GRAPH}/applications/{oid}", body)
    app = az("GET", f"{GRAPH}/applications/{oid}")
    sp = find("servicePrincipals", "appId", app["appId"])
    if sp is None:
        sp = az("POST", f"{GRAPH}/servicePrincipals", {"appId": app["appId"]})["id"]
    return app, sp


def grant(client_sp: str, resource_sp: str, scopes: str) -> None:
    """Create or update tenant-wide admin consent in this disposable test tenant only."""
    rows = az(
        "GET", f"{GRAPH}/oauth2PermissionGrants?$filter=clientId eq '{client_sp}' and resourceId eq '{resource_sp}'"
    )["value"]
    # Never replace a single-user grant with an all-users grant accidentally.
    rows = [r for r in rows if r.get("consentType") == "AllPrincipals"]
    if len(rows) > 1:
        raise SystemExit("Multiple admin consent grants found; review the dedicated test tenant")
    if rows:
        az("PATCH", f"{GRAPH}/oauth2PermissionGrants/{rows[0]['id']}", {"scope": scopes})
    else:
        az(
            "POST",
            f"{GRAPH}/oauth2PermissionGrants",
            {"clientId": client_sp, "consentType": "AllPrincipals", "resourceId": resource_sp, "scope": scopes},
        )


def new_secret(app_oid: str, label: str) -> tuple[str, str]:
    """Add a client secret that expires after 90 days; return secret text and expiry."""
    end = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
    response = az(
        "POST",
        f"{GRAPH}/applications/{app_oid}/addPassword",
        {"passwordCredential": {"displayName": label, "endDateTime": end}},
    )
    return response["secretText"], end


def main() -> None:
    """Create the selected tenant's sample objects without changing its authentication policies."""
    tid = os.environ.get("ENTRA_TENANT_ID", "")
    try:
        uuid.UUID(tid)
    except ValueError:
        raise SystemExit("Set ENTRA_TENANT_ID to the dedicated disposable tenant GUID") from None
    if idp.selected_name() != "entra" or not re.fullmatch(r"[a-z][a-z0-9-]{2,39}", P):
        raise SystemExit("Use IDP=entra and a unique SAMPLE_PREFIX of 3-40 lowercase letters, digits or hyphens")
    tenant = az("GET", f"{GRAPH}/organization?$select=id,verifiedDomains")["value"]
    if len(tenant) != 1 or tenant[0]["id"] != tid:
        raise SystemExit("The signed-in Azure tenant does not match ENTRA_TENANT_ID; no objects changed")
    domain = next(d["name"] for d in tenant[0]["verifiedDomains"] if d["isDefault"])
    sm = boto3.client("secretsmanager", region_name=idp.SECRETS_REGION)
    existing_credentials = {}
    # Check retained secrets before creating apps or changing tenant-wide consent.
    for kind in ("app", "gateway"):
        try:
            stored = json.loads(sm.get_secret_value(SecretId=idp.secret_id("entra", f"{kind}-client"))["SecretString"])
        except sm.exceptions.ResourceNotFoundException:
            stored = None
        oid = find("applications", "displayName", f"{P}-{kind}")
        if stored is not None:
            if stored.get("tenant_id") != tid or oid is None:
                raise SystemExit("Stored Entra credentials do not match this tenant/application; use a fresh prefix")
            current = az("GET", f"{GRAPH}/applications/{oid}")
            if stored.get("client_id") != current["appId"]:
                raise SystemExit("Stored Entra credentials do not match this application; use a fresh prefix")
        existing_credentials[kind] = stored
    resource, resource_sp = get_or_create_app(
        f"{P}-resource-api",
        {
            "signInAudience": "AzureADMyOrg",
            "api": {
                "requestedAccessTokenVersion": 2,
                "oauth2PermissionScopes": [
                    scope([], "resource.read", "Read the signed-in user's identity"),
                    scope([], "resource.other", "Negative scope test only; does not grant API access"),
                ],
            },
        },
    )
    resource_scopes = {s["value"]: s["id"] for s in resource["api"]["oauth2PermissionScopes"]}
    resource_access = {
        "resourceAppId": resource["appId"],
        "resourceAccess": [{"id": resource_scopes["resource.read"], "type": "Scope"}],
    }
    gateway, gateway_sp = get_or_create_app(
        f"{P}-gateway",
        {
            "signInAudience": "AzureADMyOrg",
            "api": {
                "requestedAccessTokenVersion": 2,
                "oauth2PermissionScopes": [scope([], "access", "Call the Gateway as the signed-in user")],
            },
            "requiredResourceAccess": [resource_access],
        },
    )
    gateway_access = {
        "resourceAppId": gateway["appId"],
        "resourceAccess": [{"id": gateway["api"]["oauth2PermissionScopes"][0]["id"], "type": "Scope"}],
    }
    # The middle tier can request its own audience solely to exercise the wrong-client rejection.
    az(
        "PATCH",
        f"{GRAPH}/applications/{gateway['id']}",
        {"requiredResourceAccess": [resource_access, gateway_access]},
    )
    graph_sp = find("servicePrincipals", "appId", GRAPH_APP)
    if graph_sp is None:
        raise SystemExit("Microsoft Graph service principal not found; ask the disposable tenant administrator")
    app, app_sp = get_or_create_app(
        f"{P}-app",
        {
            "signInAudience": "AzureADMyOrg",
            "web": {"redirectUris": ["http://localhost:8400/callback"]},
            "requiredResourceAccess": [
                {
                    "resourceAppId": resource["appId"],
                    "resourceAccess": [{"id": value, "type": "Scope"} for value in resource_scopes.values()],
                },
                gateway_access,
                {
                    "resourceAppId": GRAPH_APP,
                    "resourceAccess": [
                        {"id": value, "type": "Scope"}
                        for value in (
                            "37f7f235-527c-4136-accd-4a02d197296e",  # openid
                            "14dad69e-099b-42c9-810b-d002981feec1",  # profile
                            "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0",  # email
                            "e1fe6dd8-ba31-4d61-89e7-88639da4683d",  # User.Read: wrong-audience test
                        )
                    ],
                },
            ],
        },
    )
    grant(app_sp, resource_sp, "resource.read resource.other")
    grant(app_sp, gateway_sp, "access")
    grant(app_sp, graph_sp, "openid profile email User.Read")
    grant(gateway_sp, resource_sp, "resource.read")
    grant(gateway_sp, gateway_sp, "access")
    for application, kind in ((app, "app"), (gateway, "gateway")):
        name = idp.secret_id("entra", f"{kind}-client")
        stored = existing_credentials[kind]
        if stored is None:
            secret, end = new_secret(application["id"], f"{P}-{kind}-sample")
            idp.put_secret(
                name,
                {"tenant_id": tid, "client_id": application["appId"], "client_secret": secret, "expires": end},
                TAGS,
            )
        elif stored["client_id"] != application["appId"]:
            raise SystemExit("Entra application changed during setup; stop concurrent setup runs")

    users_secret = idp.secret_id("entra", "users")
    try:
        passwords = json.loads(sm.get_secret_value(SecretId=users_secret)["SecretString"])
    except sm.exceptions.ResourceNotFoundException:
        passwords = {}
    users = {}
    for user in idp.USERS:
        name = f"{P}-{user}"
        upn = f"{name}@{domain}"
        uid = find("users", "userPrincipalName", upn)
        if uid is None:
            password = "Aa1!" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(28))
            uid = az(
                "POST",
                f"{GRAPH}/users",
                {
                    "accountEnabled": True,
                    "displayName": name,
                    "mailNickname": name,
                    "userPrincipalName": upn,
                    "passwordProfile": {"password": password, "forceChangePasswordNextSignIn": False},
                },
            )["id"]
            passwords[name] = {"upn": upn, "password": password}
            idp.put_secret(users_secret, passwords, TAGS)
        elif name not in passwords or passwords[name].get("upn") != upn:
            raise SystemExit("Existing test user has no matching stored password; do not reset it, use a fresh prefix")
        users[name] = uid
    state = {
        "tenantId": tid,
        "domain": domain,
        "prefix": P,
        "resource": {
            "appId": resource["appId"],
            "objectId": resource["id"],
            "spId": resource_sp,
            "audience": resource["identifierUris"][0],
        },
        "gateway": {
            "appId": gateway["appId"],
            "objectId": gateway["id"],
            "spId": gateway_sp,
            "audience": gateway["identifierUris"][0],
        },
        "app": {"appId": app["appId"], "objectId": app["id"], "spId": app_sp},
        "users": users,
    }
    with open(idp.state_file("entra", "state"), "w", encoding="utf-8") as file:
        json.dump(state, file, indent=2)
    print("Entra setup complete; identifiers saved, credentials stored in Secrets Manager")


if __name__ == "__main__":
    main()
