#!/usr/bin/env python3
"""Check the managed Gateway and exchanged identity. Requires a deployed sandbox."""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from lib import idp, mcp

A = idp.load()
with open(idp.state_file(A.NAME, f"gateway-{idp.REGION}"), encoding="utf-8") as file:
    url = json.load(file)["gatewayUrl"]
results = []


def check(name, passed):
    results.append({"check": name, "pass": bool(passed)})
    print("PASS" if passed else "FAIL", name)


for user in idp.USERS:
    status, response = mcp.tool(url, A.token(user, "gateway"), "resource___whoami", {})
    result = response.get("result", {})
    text = next((c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"), "{}")
    try:
        claims = json.loads(text)
    except ValueError:
        claims = {}
    expected = A.state()["users"][f"{idp.PREFIX}-{user}"]
    check(
        f"{user}: exchanged identity echoed",
        status == 200
        and not result.get("isError")
        and claims.get(A.USER_ID_CLAIM) == expected
        and claims.get("azp") == A.expected_exchanged_azp(),
    )
for label, token in (
    ("missing", None),
    ("malformed", "not-a-token"),
    ("ID", A.id_token("user-a")),
    ("wrong audience", A.other_resource_token("user-a")),
    ("wrong client", A.other_client_token("user-a")),
):
    status, _ = mcp.tool(url, token, "resource___whoami", {})
    check(f"{label} token denied by managed Gateway", status in (401, 403))
with open(idp.evidence_path(f"gateway-{idp.REGION}.json"), "w", encoding="utf-8") as file:
    json.dump(results, file, indent=2)
sys.exit(0 if all(r["pass"] for r in results) else 1)
