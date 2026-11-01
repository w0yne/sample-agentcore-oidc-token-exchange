#!/usr/bin/env python3
"""Exercise managed on-behalf-of exchange and compare the API's echoed subject."""

import json
import pathlib
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from lib import idp, net

A = idp.load()
session = idp.session()
ctl, dp = session.client("bedrock-agentcore-control"), session.client("bedrock-agentcore")
workload = f"{idp.PREFIX}-{A.NAME}-workload"
if not any(w["name"] == workload for w in ctl.list_workload_identities()["workloadIdentities"]):
    ctl.create_workload_identity(name=workload, tags={"project": idp.PREFIX})
with open(idp.state_file(A.NAME, "resource-api"), encoding="utf-8") as file:
    url = json.load(file)["url"].rstrip("/")
x = A.exchange_params()
results = []
for user in idp.USERS:
    workload_token = dp.get_workload_access_token_for_jwt(workloadName=workload, userToken=A.token(user, "gateway"))[
        "workloadAccessToken"
    ]
    token = dp.get_resource_oauth2_token(
        workloadIdentityToken=workload_token,
        resourceCredentialProviderName=A.PROVIDER,
        oauth2Flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
        scopes=x["scopes"],
        customParameters=x["custom"],
    )["accessToken"]
    request = urllib.request.Request(url + "/v1/me", headers={"authorization": "Bearer " + token})
    with net.open_https(request, timeout=30) as response:
        claims = json.load(response)
    passed = (
        claims.get(A.USER_ID_CLAIM) == A.state()["users"][f"{idp.PREFIX}-{user}"]
        and claims.get("azp") == A.expected_exchanged_azp()
    )
    results.append({"user": user, "pass": passed})
    print("PASS" if passed else "FAIL", user)
with open(idp.evidence_path(f"identity-direct-{idp.REGION}.json"), "w", encoding="utf-8") as file:
    json.dump(results, file, indent=2)
sys.exit(0 if all(r["pass"] for r in results) else 1)
