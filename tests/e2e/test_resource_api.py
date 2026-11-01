#!/usr/bin/env python3
"""Check managed HTTP API authorization and identity echo in a deployed sandbox."""

import json
import pathlib
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from lib import idp, net

A = idp.load()
with open(idp.state_file(A.NAME, "resource-api"), encoding="utf-8") as file:
    url = json.load(file)["url"].rstrip("/")
results = []


def call(token):
    headers = {"authorization": "Bearer " + token} if token else {}
    request = urllib.request.Request(url + "/v1/me", headers=headers)
    try:
        with net.open_https(request, timeout=30) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        with error:
            return error.code, {}


def check(name, passed):
    results.append({"check": name, "pass": bool(passed)})
    print("PASS" if passed else "FAIL", name)


for user in idp.USERS:
    status, claims = call(A.token(user, "resource"))
    check(
        f"{user}: subject echoed",
        status == 200 and claims.get(A.USER_ID_CLAIM) == A.state()["users"][f"{idp.PREFIX}-{user}"],
    )
for label, token in (
    ("missing", None),
    ("malformed", "not-a-token"),
    ("ID", A.id_token("user-a")),
    ("wrong audience", A.token("user-a", "gateway")),
    ("missing required scope", A.token_without_resource_scope("user-a")),
):
    status, _ = call(token)
    check(f"{label} token denied by API Gateway", status in (401, 403))
with open(idp.evidence_path("resource-api-direct.json"), "w", encoding="utf-8") as file:
    json.dump(results, file, indent=2)
sys.exit(0 if all(r["pass"] for r in results) else 1)
