#!/usr/bin/env python3
"""Delete what this sample created, scoped by SAMPLE_PREFIX.

DRY RUN by default: prints what would be deleted; --execute deletes.

  scripts/cleanup.py [--execute] [--region R ...] [--idp keycloak|entra ...] [--skip-entra-objects]

For each --region (default SAMPLE_REGION; SAMPLE_PROFILE selects the AWS profile): Gateway targets and gateways
<prefix>-<idp>-gw, the Identity OAuth2 provider <prefix>-<idp>, the workload identities
<prefix>-<idp>-workload, the roles <prefix>-<idp>-gateway-role, and wherever the resource API was deployed:
the HTTP API, the Lambda and the role <prefix>-<idp>-resource-api. --idp selects the IdPs;
without it, only AWS application resources for IDP (default keycloak) are considered.
With --idp keycloak: the EC2 instance <prefix>-kc, its Elastic IP / security group / role + instance profile,
the DNS A record (needs KC_HOSTNAME and KC_HOSTED_ZONE_ID; ONLY that record is deleted) and the secrets
<prefix>/keycloak/*.
With --idp entra: the uniquely named Entra apps and exact test-user UPNs, plus <prefix>/entra/* secrets.
Entra object cleanup requires ENTRA_TENANT_ID and a matching tenant-admin az login.
--skip-entra-objects retains only Entra objects, not AWS resources or source secrets.
Failed Entra listing is NOT CHECKED and exits nonzero, including during dry run.
Resources are selected by their exact names, which all start with the prefix. The one exception is the Keycloak
Elastic IP, which has no name of its own: it is selected by the tag project=<prefix> together with either
Name=<prefix>-kc or no Name tag at all (infra.py adopts such an address), so do not give other Elastic IPs the project
tag of this prefix. The Lambda log group /aws/lambda/<function> is deleted with the function;
logs of other services (for example API Gateway access logs, which this sample does not enable) are not touched.

Limits: only the first page of each listing call is read, which is enough for a sandbox account; a deletion that fails
is reported as "failed", the script goes on, and it exits with status 1 at the end. Always finish with a dry run: it
must list nothing, and report nothing as NOT CHECKED, before you consider the account clean.
"""

import argparse
import contextlib
import json
import os
import pathlib
import re
import subprocess
import sys
import uuid
from collections.abc import Callable
from typing import Any

import boto3

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from lib import idp, wait

ap = argparse.ArgumentParser()
ap.add_argument("--execute", action="store_true")
ap.add_argument("--region", action="append")
ap.add_argument("--idp", choices=["keycloak", "entra"], action="append", default=[])
ap.add_argument(
    "--skip-entra-objects",
    action="store_true",
    help="keep Entra apps/users without running az; AWS application resources and source secrets are still deleted",
)
args = ap.parse_args()
P, X = idp.PREFIX, args.execute
SELECTED = list(dict.fromkeys(args.idp or [idp.selected_name()]))
FAILED: list[str] = []


def do(what: str, fn: Callable[[], Any]) -> None:
    """Print the action and, with --execute, run it; a failing deletion is reported, remembered and skipped."""
    print(("deleting: " if X else "would delete: ") + what)
    if X:
        try:
            fn()
        except Exception as e:
            print("   failed:", type(e).__name__, str(e)[:160])
            FAILED.append(what)


def az_json(method: str, url: str) -> dict[str, Any]:
    """Call Graph without logging CLI diagnostics that may contain credentials."""
    result = subprocess.run(  # noqa: S603  fixed argv, no shell
        ["az", "rest", "--method", method, "--url", url, "-o", "json"],  # noqa: S607  operator CLI
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(f"Graph {method} failed (exit {result.returncode}); check Azure login and permissions")
    return json.loads(result.stdout) if result.stdout.strip() else {}


ENTRA_OBJECTS: list[tuple[str, dict[str, Any]]] = []
if "entra" in SELECTED and not re.fullmatch(r"[a-z][a-z0-9-]{2,39}", P):
    raise SystemExit("Use a unique SAMPLE_PREFIX of 3-40 lowercase letters, digits or hyphens")
if "entra" in args.idp and not args.skip_entra_objects:
    graph = "https://graph.microsoft.com/v1.0"
    try:
        tenant = os.environ.get("ENTRA_TENANT_ID", "")
        uuid.UUID(tenant)
        orgs = az_json("GET", f"{graph}/organization?$select=id,verifiedDomains")["value"]
        if len(orgs) != 1 or orgs[0]["id"] != tenant:
            raise ValueError("Azure login does not match ENTRA_TENANT_ID")
        domain = next((d["name"] for d in orgs[0]["verifiedDomains"] if d["isDefault"]), None)
        if not domain:
            raise ValueError("Entra default domain could not be determined")
        exact = {
            "applications": ("displayName", [f"{P}-resource-api", f"{P}-gateway", f"{P}-app"]),
            "users": ("userPrincipalName", [f"{P}-{user}@{domain}" for user in idp.USERS]),
        }
        for kind, (field, names) in exact.items():
            query = " or ".join(f"{field} eq '{name}'" for name in names)
            found = az_json("GET", f"{graph}/{kind}?$filter={query}&$select=id,{field}")
            if found.get("@odata.nextLink"):
                raise ValueError("Entra listing is paginated; review it before cleanup")
            for name in names:
                matches = [obj for obj in found["value"] if obj.get(field) == name]
                if len(matches) > 1:
                    raise ValueError("Ambiguous Entra object name; review object IDs before cleanup")
                if matches:
                    ENTRA_OBJECTS.append((kind, {**matches[0], "label": name}))
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        print(f"NOT CHECKED: Entra objects ({type(error).__name__}); verify ENTRA_TENANT_ID and tenant-admin az login")
        sys.exit(1)


for region in args.region or [idp.REGION]:
    sess = idp.session(region)
    ctl, iam, lam, api = (
        sess.client("bedrock-agentcore-control"),
        sess.client("iam"),
        sess.client("lambda"),
        sess.client("apigatewayv2"),
    )
    for g in [g for g in ctl.list_gateways()["items"] if g["name"] in [f"{P}-{i}-gw" for i in SELECTED]]:
        for t in ctl.list_gateway_targets(gatewayIdentifier=g["gatewayId"])["items"]:
            do(
                f"[{region}] gateway target {g['name']}/{t['name']}",
                lambda g=g, t=t, ctl=ctl: ctl.delete_gateway_target(
                    gatewayIdentifier=g["gatewayId"], targetId=t["targetId"]
                ),
            )

        def drop_gateway(g: dict[str, Any] = g, ctl: Any = ctl) -> None:
            """Wait up to 60 s for the gateway's targets to disappear, then delete the gateway."""
            with contextlib.suppress(TimeoutError):  # target deletion is asynchronous; delete_gateway reports leftovers
                wait.until(
                    lambda: True if not ctl.list_gateway_targets(gatewayIdentifier=g["gatewayId"])["items"] else None,
                    f"the targets of {g['name']}",
                    timeout=60,
                    most=4,
                )
            ctl.delete_gateway(gatewayIdentifier=g["gatewayId"])

        do(f"[{region}] gateway {g['name']} ({g['gatewayId']})", drop_gateway)
    for p in [
        p
        for p in ctl.list_oauth2_credential_providers()["credentialProviders"]
        if p["name"] in [f"{P}-{i}" for i in SELECTED]
    ]:
        do(
            f"[{region}] oauth2 credential provider {p['name']}",
            lambda p=p, ctl=ctl: ctl.delete_oauth2_credential_provider(name=p["name"]),
        )
    for w in [
        w
        for w in ctl.list_workload_identities()["workloadIdentities"]
        if w["name"] in [f"{P}-{i}-workload" for i in SELECTED]
    ]:
        do(
            f"[{region}] workload identity {w['name']}",
            lambda w=w, ctl=ctl: ctl.delete_workload_identity(name=w["name"]),
        )
    names = [f"{P}-{i}-{what}" for i in SELECTED for what in ("gateway-role", "resource-api")]
    for role in names:
        try:
            iam.get_role(RoleName=role)
        except iam.exceptions.NoSuchEntityException:
            continue

        def drop(role: str = role, iam: Any = iam) -> None:
            """Delete the role together with its inline and attached policies."""
            for n in iam.list_role_policies(RoleName=role)["PolicyNames"]:
                iam.delete_role_policy(RoleName=role, PolicyName=n)
            for a in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=role, PolicyArn=a["PolicyArn"])
            iam.delete_role(RoleName=role)

        do(f"[{region}] IAM role {role} (+ its policies)", drop)
    api_names = [f"{P}-{i}-resource-api{suffix}" for i in SELECTED for suffix in ("", "-jwt")]
    for a in [a for a in api.get_apis()["Items"] if a["Name"] in api_names]:
        do(f"[{region}] HTTP API {a['Name']} ({a['ApiId']})", lambda a=a, api=api: api.delete_api(ApiId=a["ApiId"]))
    for fn in [n for n in names if n.endswith("resource-api")]:
        try:
            lam.get_function(FunctionName=fn)
            do(f"[{region}] Lambda {fn}", lambda fn=fn, lam=lam: lam.delete_function(FunctionName=fn))
        except lam.exceptions.ResourceNotFoundException:
            pass
    logs = sess.client("logs")
    for fn in [n for n in names if n.endswith("resource-api")]:
        group = f"/aws/lambda/{fn}"
        if any(g["logGroupName"] == group for g in logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]):
            do(
                f"[{region}] CloudWatch log group {group}",
                lambda group=group, logs=logs: logs.delete_log_group(logGroupName=group),
            )

sm = boto3.client("secretsmanager", region_name=idp.SECRETS_REGION)
for kind, obj in ENTRA_OBJECTS:
    do(
        f"Entra {kind[:-1]} {obj['label']} ({obj['id']})",
        lambda kind=kind, obj=obj: az_json("DELETE", f"https://graph.microsoft.com/v1.0/{kind}/{obj['id']}"),
    )
for which in args.idp:
    if which == "keycloak":
        kr = os.environ.get("KC_REGION", "us-west-2")
        ec2, iam = boto3.client("ec2", region_name=kr), boto3.client("iam")
        name = f"{P}-kc"
        for r in ec2.describe_instances(
            Filters=[
                {"Name": "tag:Name", "Values": [name]},
                {"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]},
            ]
        )["Reservations"]:
            for i in r["Instances"]:
                do(
                    f"[{kr}] EC2 instance {i['InstanceId']} ({name})",
                    lambda i=i, ec2=ec2: (
                        ec2.terminate_instances(InstanceIds=[i["InstanceId"]]),
                        ec2.get_waiter("instance_terminated").wait(InstanceIds=[i["InstanceId"]]),
                    ),
                )
        for a in sum(idp.keycloak_eips(ec2, name), []):
            do(
                f"[{kr}] Elastic IP {a['PublicIp']}",
                lambda a=a, ec2=ec2: ec2.release_address(AllocationId=a["AllocationId"]),
            )
        for g in ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [name]}])["SecurityGroups"]:
            do(
                f"[{kr}] security group {g['GroupId']} ({name})",
                lambda g=g, ec2=ec2: ec2.delete_security_group(GroupId=g["GroupId"]),
            )

        def drop_profile(iam: Any = iam, name: str = name) -> None:
            """Delete the instance profile and the role of the Keycloak instance."""
            iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=name)
            iam.delete_instance_profile(InstanceProfileName=name)
            for n in iam.list_role_policies(RoleName=name)["PolicyNames"]:
                iam.delete_role_policy(RoleName=name, PolicyName=n)
            for a in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=name, PolicyArn=a["PolicyArn"])
            iam.delete_role(RoleName=name)

        try:
            iam.get_role(RoleName=name)
            do(f"IAM role + instance profile {name}", drop_profile)
        except iam.exceptions.NoSuchEntityException:
            pass
        host, zone = os.environ.get("KC_HOSTNAME"), os.environ.get("KC_HOSTED_ZONE_ID")
        if host and zone:
            r53 = boto3.client("route53")
            for rr in r53.list_resource_record_sets(
                HostedZoneId=zone, StartRecordName=host, StartRecordType="A", MaxItems="1"
            )["ResourceRecordSets"]:
                if rr["Name"].rstrip(".") == host and rr["Type"] == "A":
                    do(
                        f"Route 53 A record {host} (only this record)",
                        lambda rr=rr, r53=r53, zone=zone: r53.change_resource_record_sets(
                            HostedZoneId=zone, ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rr}]}
                        ),
                    )
        else:
            print("note: set KC_HOSTNAME and KC_HOSTED_ZONE_ID to also delete the DNS record")
    for s in sm.list_secrets(Filters=[{"Key": "name", "Values": [f"{P}/{which}/"]}])["SecretList"]:
        if s["Name"].startswith(f"{P}/{which}/"):
            do(f"secret {s['Name']}", lambda s=s: sm.delete_secret(SecretId=s["Name"], ForceDeleteWithoutRecovery=True))
if not X:
    print("\n(dry run: nothing was deleted; add --execute)")
elif FAILED:
    print(f"\n{len(FAILED)} deletion(s) failed; fix the cause and run again, then finish with a dry run:")
    for what in FAILED:
        print("  -", what)
if FAILED:
    sys.exit(1)
