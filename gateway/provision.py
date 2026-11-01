#!/usr/bin/env python3
"""Provision AgentCore Identity and a Gateway for the selected IdP, in SAMPLE_REGION.

Builds aws and aws-cn ARNs (regional feature availability must be confirmed) and creates:
  * OAuth2 credential provider holding the IdP's `gateway` client (the token-exchange middle tier), from the adapter;
  * Gateway `<prefix>-<idp>-gw` with CUSTOM_JWT inbound auth against the IdP's OIDC discovery document;
  * OpenAPI target `resource` with TOKEN_EXCHANGE to the managed identity echo API
    (MicrosoftOauth2's preset OBO for Entra; CustomOauth2 with RFC 8693 for Keycloak).
Usage: python gateway/provision.py
  SAMPLE_GATEWAY_DEBUG=1  sets the Gateway exceptionLevel to DEBUG (detailed error messages in responses to callers);
                          off by default
"""

import json
import os
import pathlib
import sys
from collections.abc import Callable
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from lib import idp, wait

A = idp.load()
sess = idp.session()
GW, TAGS = f"{idp.PREFIX}-{A.NAME}-gw", {"project": idp.PREFIX}
with open(idp.state_file(A.NAME, "resource-api"), encoding="utf-8") as resource_state:
    resource_url = json.load(resource_state)["url"].rstrip("/")
ctl, iam = sess.client("bedrock-agentcore-control"), sess.client("iam")
acct = sess.client("sts").get_caller_identity()["Account"]

vendor, cfg = A.provider_input()
provider = A.PROVIDER
prov = next((p for p in ctl.list_oauth2_credential_providers()["credentialProviders"] if p["name"] == provider), None)
if prov:
    # The list response does not include the managed client secret's ARN.
    prov = ctl.get_oauth2_credential_provider(name=provider)
else:
    prov = ctl.create_oauth2_credential_provider(
        name=provider, credentialProviderVendor=vendor, oauth2ProviderConfigInput=cfg, tags=TAGS
    )
prov_arn = prov["credentialProviderArn"]
secret_arn = prov["clientSecretArn"]["secretArn"]
print("provider", prov_arn)

role_name = f"{idp.PREFIX}-{A.NAME}-gateway-role"
ARN = f"arn:{idp.PARTITION}:bedrock-agentcore:{idp.REGION}:{acct}"
trust = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {"aws:SourceAccount": acct},
                "ArnLike": {"aws:SourceArn": f"{ARN}:gateway/{GW}-*"},
            },
        }
    ],
}
try:
    role = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(trust))
except iam.exceptions.NoSuchEntityException:
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
    )["Role"]["Arn"]
iam.put_role_policy(
    RoleName=role_name,
    PolicyName="token-exchange",
    PolicyDocument=json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "bedrock-agentcore:GetWorkloadAccessToken",
                        "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                        "bedrock-agentcore:GetResourceOauth2Token",
                    ],
                    # found by trial: the token vault itself AND the provider;
                    # the documentation example's token-vault/* alone is not enough
                    "Resource": [
                        f"{ARN}:workload-identity-directory/default",
                        f"{ARN}:workload-identity-directory/default/workload-identity/{GW}-*",
                        f"{ARN}:token-vault/default",
                        prov_arn,
                    ],
                },
                {
                    "Effect": "Allow",
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": secret_arn,
                },
            ],
        }
    ),
)
iam.get_waiter("role_exists").wait(RoleName=role_name)


def role_not_ready(e: Exception) -> bool:
    """True for the error a service returns while a just-created or just-updated role is not yet usable."""
    code = getattr(e, "response", {}).get("Error", {}).get("Code")
    return code in ("ValidationException", "AccessDeniedException") and "role" in str(e).lower()


def settled(fetch: Callable[[], dict[str, Any]]) -> dict[str, Any] | None:
    """Return the resource from `fetch` once its status is READY or FAILED, otherwise None (for wait.until)."""
    r = fetch()
    return r if r["status"] in ("READY", "FAILED") else None


d = A.door()
jwt = {"discoveryUrl": d["discovery_url"], "allowedAudience": d["audiences"]}
jwt["customClaims"] = [
    {
        "inboundTokenClaimName": d["client_claim"],
        "inboundTokenClaimValueType": "STRING",
        "authorizingClaimMatchValue": {
            "claimMatchValue": {"matchValueString": d["client_value"]},
            "claimMatchOperator": "EQUALS",
        },
    }
]
gw = next((g for g in ctl.list_gateways()["items"] if g["name"] == GW), None)
args = dict(
    name=GW,
    roleArn=role,
    protocolType="MCP",
    authorizerType="CUSTOM_JWT",
    authorizerConfiguration={"customJWTAuthorizer": jwt},
)
if os.environ.get("SAMPLE_GATEWAY_DEBUG") == "1":
    # Detailed exception messages in Gateway responses to callers; omitted (the default) = generic errors.
    # update_gateway applies the full configuration; omitting the variable restores generic errors.
    args["exceptionLevel"] = "DEBUG"
if gw:
    gid = gw["gatewayId"]
    wait.retry(lambda: ctl.update_gateway(gatewayIdentifier=gid, **args), role_not_ready, "the gateway role")
else:
    gid = wait.retry(lambda: ctl.create_gateway(tags=TAGS, **args), role_not_ready, "the gateway role")["gatewayId"]
g = wait.until(lambda: settled(lambda: ctl.get_gateway(gatewayIdentifier=gid)), f"gateway {gid}")
print("gateway", gid, g["status"], g.get("gatewayUrl"), g.get("statusReasons", ""))

schema = {
    "openapi": "3.0.1",
    "info": {"title": "sample resource API", "version": "1"},
    "servers": [{"url": resource_url}],
    "paths": {
        "/v1/me": {
            "get": {
                "operationId": "whoami",
                "summary": "Echo the identity claims validated by API Gateway",
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
}
x = A.exchange_params()
# Gateway's grant stays TOKEN_EXCHANGE for both vendors; MicrosoftOauth2 handles the OBO wire protocol.
oauth = {
    "providerArn": prov_arn,
    "grantType": "TOKEN_EXCHANGE",
    "scopes": x["scopes"],
    **({"customParameters": x["custom"]} if x["custom"] else {}),
}
target = dict(
    gatewayIdentifier=gid,
    name="resource",
    targetConfiguration={"mcp": {"openApiSchema": {"inlinePayload": json.dumps(schema)}}},
    credentialProviderConfigurations=[
        {"credentialProviderType": "OAUTH", "credentialProvider": {"oauthCredentialProvider": oauth}}
    ],
)
tg = next((t for t in ctl.list_gateway_targets(gatewayIdentifier=gid)["items"] if t["name"] == "resource"), None)
if tg:
    ctl.update_gateway_target(targetId=tg["targetId"], **target)
    tid_ = tg["targetId"]
else:
    tid_ = ctl.create_gateway_target(**target)["targetId"]
t = wait.until(lambda: settled(lambda: ctl.get_gateway_target(gatewayIdentifier=gid, targetId=tid_)), f"target {tid_}")
print("target", tid_, t["status"], t.get("statusReasons", ""))
with open(idp.state_file(A.NAME, f"gateway-{idp.REGION}"), "w", encoding="utf-8") as gateway_state:
    json.dump(
        {
            "gatewayId": gid,
            "gatewayUrl": g.get("gatewayUrl"),
            "targetId": tid_,
            "providerArn": prov_arn,
            "roleArn": role,
        },
        gateway_state,
        indent=1,
    )
