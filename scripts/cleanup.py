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
Applications, users and their service principals are permanently purged from deletedItems.
Entra object cleanup requires ENTRA_TENANT_ID and a matching tenant-admin az login.
--skip-entra-objects retains only Entra objects, not AWS resources or source secrets.
Failed Entra listing is NOT CHECKED and exits nonzero, including during dry run.
Resources are selected by their exact names, which all start with the prefix. The one exception is the Keycloak
Elastic IP, which has no name of its own: it is selected by the tag project=<prefix> together with either
Name=<prefix>-kc or no Name tag at all (infra.py adopts such an address), so do not give other Elastic IPs the project
tag of this prefix. The Lambda log group /aws/lambda/<function> is deleted with the function;
logs of other services (for example API Gateway access logs, which this sample does not enable) are not touched.

Limits: AWS listings use the first page (small sandbox only); Graph listings follow all pages.
AWS reads that fail are NOT CHECKED; deletions that fail are FAILED. Independent cleanup continues,
including Entra cleanup after AWS failures, and any error results in exit status 1. Always finish with a dry run: it
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
from botocore.exceptions import BotoCoreError, ClientError

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
UNCHECKED: list[str] = []


def do(what: str, fn: Callable[[], Any]) -> bool:
    """Print the action and, with --execute, run it; a failing deletion is reported, remembered and skipped."""
    print(("deleting: " if X else "would delete: ") + what)
    if X:
        try:
            fn()
        except Exception as e:
            print(f"FAILED: {what} ({type(e).__name__})")
            FAILED.append(what)
            return False
    return True


def read(what: str, fn: Callable[[], Any], missing: tuple[type[Exception], ...] = ()) -> Any:
    """Record SDK reads/credential failures and let independent cleanup continue."""
    try:
        return fn()
    except missing:
        return None
    except (ClientError, BotoCoreError, OSError, json.JSONDecodeError) as error:
        print(f"NOT CHECKED: {what} ({type(error).__name__})")
        UNCHECKED.append(what)
        return None


def rows(what: str, client: Any, operation: str, key: str, **kwargs: Any) -> list[Any]:
    """Read one AWS listing page; an unavailable client was already recorded by read()."""
    if client is None:
        return []
    result = read(what, lambda: getattr(client, operation)(**kwargs))
    return result[key] if result is not None else []


def az_json(method: str, url: str) -> dict[str, Any]:
    """Call Graph without logging CLI diagnostics that may contain credentials."""
    if method not in ("GET", "DELETE") or not url.startswith("https://graph.microsoft.com/v1.0/"):
        raise ValueError("Refusing an unsupported Graph cleanup request")
    result = subprocess.run(  # noqa: S603  fixed argv, no shell
        ["az", "rest", "--method", method, "--url", url, "-o", "json"],  # noqa: S607  operator CLI
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(f"Graph {method} failed (exit {result.returncode}); check Azure login and permissions")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def graph_rows(url: str) -> list[dict[str, Any]]:
    """Read every Graph page, rejecting external or cyclic next links."""
    objects: dict[str, dict[str, Any]] = {}
    seen = set()
    while url:
        if url in seen:
            raise ValueError("Cyclic Graph next link")
        seen.add(url)
        page = az_json("GET", url)
        for obj in page["value"]:
            objects[obj["id"]] = obj
        url = page.get("@odata.nextLink")
    return list(objects.values())


def exact_objects(objects: list[dict[str, Any]], field: str, names: list[str]) -> list[dict[str, Any]]:
    """Resolve unique exact names across active and soft-deleted objects before any writes."""
    picked = []
    for name in names:
        matches = {obj["id"]: obj for obj in objects if obj.get(field) == name}
        if len(matches) > 1:
            raise ValueError("Ambiguous Entra object name; review object IDs before cleanup")
        if matches:
            picked.append({**next(iter(matches.values())), "label": name})
    return picked


ENTRA_OBJECTS: list[tuple[str, dict[str, Any]]] = []
ENTRA_DELETED: dict[str, tuple[str, dict[str, Any]]] = {}
ENTRA_SERVICE_PRINCIPALS: list[dict[str, Any]] = []
DELETED_APP_IDS: set[str] = set()
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
        app_names = [f"{P}-{suffix}" for suffix in ("resource-api", "gateway", "app", "noscope")]
        exact = {
            "applications": ("displayName", app_names),
            "users": ("userPrincipalName", [f"{P}-{user}@{domain}" for user in idp.USERS]),
        }
        scoped_apps = []
        for kind, (field, names) in exact.items():
            query = " or ".join(f"{field} eq '{name}'" for name in names)
            fields = "id,displayName,appId" if kind == "applications" else "id,userPrincipalName"
            active = graph_rows(f"{graph}/{kind}?$filter={query}&$select={fields}")
            deleted = graph_rows(f"{graph}/directory/deletedItems/microsoft.graph.{kind[:-1]}?$select={fields}")
            active_ids = {obj["id"] for obj in active}
            for obj in exact_objects(active + deleted, field, names):
                if obj["id"] in active_ids:
                    ENTRA_OBJECTS.append((kind, obj))
                else:
                    ENTRA_DELETED[obj["id"]] = (kind, obj)
                    if kind == "applications":
                        DELETED_APP_IDS.add(obj["appId"])
                if kind == "applications":
                    scoped_apps.append(obj)
        app_ids_by_name = {obj["label"]: obj["appId"] for obj in scoped_apps}
        state_file = idp.STATE / "entra-state.json"
        if state_file.exists():
            with open(state_file, encoding="utf-8") as file:
                saved = json.load(file)
            if saved.get("tenantId") != tenant or saved.get("prefix") != P:
                raise ValueError("Entra state does not match cleanup tenant/prefix")
            for suffix, key in (
                ("resource-api", "resource"),
                ("gateway", "gateway"),
                ("app", "app"),
                ("noscope", "noscope"),
            ):
                if saved.get(key, {}).get("appId"):
                    app_ids_by_name.setdefault(f"{P}-{suffix}", saved[key]["appId"])
        app_ids = set(app_ids_by_name.values())
        if app_ids:
            query = " or ".join(f"appId eq '{app_id}'" for app_id in sorted(app_ids))
            ENTRA_SERVICE_PRINCIPALS = [
                obj
                for obj in graph_rows(f"{graph}/servicePrincipals?$filter={query}&$select=id,appId,displayName")
                if obj["appId"] in app_ids
            ]
        deleted_sps = graph_rows(
            f"{graph}/directory/deletedItems/microsoft.graph.servicePrincipal?$select=id,appId,displayName"
        )
        for obj in deleted_sps:
            if obj["appId"] in app_ids:
                ENTRA_DELETED[obj["id"]] = ("servicePrincipals", {**obj, "label": obj.get("displayName", obj["appId"])})
            elif obj.get("displayName") in app_names and obj["displayName"] not in app_ids_by_name:
                what = f"Entra orphaned deleted SP {obj['id']}: appId ownership unavailable; retain state for retry"
                print(f"NOT CHECKED: {what}")
                UNCHECKED.append(what)
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        print(f"NOT CHECKED: Entra objects ({type(error).__name__}); verify ENTRA_TENANT_ID and tenant-admin az login")
        sys.exit(1)


for region in args.region or [idp.REGION]:
    sess = read(f"[{region}] AWS session", lambda region=region: idp.session(region))
    if sess is None:
        continue
    ctl, iam, lam, api = (
        read(f"[{region}] AgentCore client", lambda sess=sess: sess.client("bedrock-agentcore-control")),
        read(f"[{region}] IAM client", lambda sess=sess: sess.client("iam")),
        read(f"[{region}] Lambda client", lambda sess=sess: sess.client("lambda")),
        read(f"[{region}] API Gateway client", lambda sess=sess: sess.client("apigatewayv2")),
    )
    for g in [
        g
        for g in rows(f"[{region}] AgentCore gateways", ctl, "list_gateways", "items")
        if g["name"] in [f"{P}-{i}-gw" for i in SELECTED]
    ]:
        for t in rows(
            f"[{region}] AgentCore targets {g['name']}",
            ctl,
            "list_gateway_targets",
            "items",
            gatewayIdentifier=g["gatewayId"],
        ):
            do(
                f"[{region}] gateway target {g['name']}/{t['name']}",
                lambda g=g, t=t, ctl=ctl: ctl.delete_gateway_target(
                    gatewayIdentifier=g["gatewayId"], targetId=t["targetId"]
                ),
            )

        def drop_gateway(g: dict[str, Any] = g, ctl: Any = ctl, region: str = region) -> None:
            """Wait up to 60 s for the gateway's targets to disappear, then delete the gateway."""

            def targets_gone() -> bool | None:
                remaining = read(
                    f"[{region}] AgentCore targets {g['name']}",
                    lambda: ctl.list_gateway_targets(gatewayIdentifier=g["gatewayId"]),
                )
                if remaining is None:
                    raise RuntimeError("Cannot verify Gateway target deletion")
                return True if not remaining["items"] else None

            with contextlib.suppress(TimeoutError):  # target deletion is asynchronous; delete_gateway reports leftovers
                wait.until(
                    targets_gone,
                    f"the targets of {g['name']}",
                    timeout=60,
                    most=4,
                )
            ctl.delete_gateway(gatewayIdentifier=g["gatewayId"])

        do(f"[{region}] gateway {g['name']} ({g['gatewayId']})", drop_gateway)
    for p in [
        p
        for p in rows(f"[{region}] Identity providers", ctl, "list_oauth2_credential_providers", "credentialProviders")
        if p["name"] in [f"{P}-{i}" for i in SELECTED]
    ]:
        do(
            f"[{region}] oauth2 credential provider {p['name']}",
            lambda p=p, ctl=ctl: ctl.delete_oauth2_credential_provider(name=p["name"]),
        )
    for w in [
        w
        for w in rows(f"[{region}] Identity workloads", ctl, "list_workload_identities", "workloadIdentities")
        if w["name"] in [f"{P}-{i}-workload" for i in SELECTED]
    ]:
        do(
            f"[{region}] workload identity {w['name']}",
            lambda w=w, ctl=ctl: ctl.delete_workload_identity(name=w["name"]),
        )
    names = [f"{P}-{i}-{what}" for i in SELECTED for what in ("gateway-role", "resource-api")]
    for role in names:
        if (
            iam is None
            or read(
                f"[{region}] IAM role {role}",
                lambda iam=iam, role=role: iam.get_role(RoleName=role),
                missing=(iam.exceptions.NoSuchEntityException,),
            )
            is None
        ):
            continue

        def drop(role: str = role, iam: Any = iam) -> None:
            """Delete the role together with its inline and attached policies."""
            for n in rows(f"IAM inline policies {role}", iam, "list_role_policies", "PolicyNames", RoleName=role):
                do(f"IAM inline policy {role}/{n}", lambda n=n: iam.delete_role_policy(RoleName=role, PolicyName=n))
            for a in rows(
                f"IAM attached policies {role}", iam, "list_attached_role_policies", "AttachedPolicies", RoleName=role
            ):
                do(
                    f"IAM attached policy {role}/{a['PolicyArn']}",
                    lambda a=a: iam.detach_role_policy(RoleName=role, PolicyArn=a["PolicyArn"]),
                )
            iam.delete_role(RoleName=role)

        do(f"[{region}] IAM role {role} (+ its policies)", drop)
    api_names = [f"{P}-{i}-resource-api{suffix}" for i in SELECTED for suffix in ("", "-jwt")]
    for a in [a for a in rows(f"[{region}] HTTP APIs", api, "get_apis", "Items") if a["Name"] in api_names]:
        do(f"[{region}] HTTP API {a['Name']} ({a['ApiId']})", lambda a=a, api=api: api.delete_api(ApiId=a["ApiId"]))
    for fn in [n for n in names if n.endswith("resource-api")]:
        if (
            lam is not None
            and read(
                f"[{region}] Lambda {fn}",
                lambda lam=lam, fn=fn: lam.get_function(FunctionName=fn),
                missing=(lam.exceptions.ResourceNotFoundException,),
            )
            is not None
        ):
            do(f"[{region}] Lambda {fn}", lambda fn=fn, lam=lam: lam.delete_function(FunctionName=fn))
    logs = read(f"[{region}] CloudWatch Logs client", lambda sess=sess: sess.client("logs"))
    for fn in [n for n in names if n.endswith("resource-api")]:
        group = f"/aws/lambda/{fn}"
        if any(
            g["logGroupName"] == group
            for g in rows(
                f"[{region}] log groups {group}", logs, "describe_log_groups", "logGroups", logGroupNamePrefix=group
            )
        ):
            do(
                f"[{region}] CloudWatch log group {group}",
                lambda group=group, logs=logs: logs.delete_log_group(logGroupName=group),
            )

sm = read("Secrets Manager client", lambda: boto3.client("secretsmanager", region_name=idp.SECRETS_REGION))
for kind, obj in ENTRA_OBJECTS:
    deleted = do(
        f"Entra {kind[:-1]} {obj['label']} ({obj['id']})",
        lambda kind=kind, obj=obj: az_json("DELETE", f"https://graph.microsoft.com/v1.0/{kind}/{obj['id']}"),
    )
    if deleted:
        ENTRA_DELETED[obj["id"]] = (kind, obj)
        if kind == "applications":
            DELETED_APP_IDS.add(obj["appId"])
for obj in ENTRA_SERVICE_PRINCIPALS:
    if obj["appId"] in DELETED_APP_IDS:
        ENTRA_DELETED[obj["id"]] = ("servicePrincipals", {**obj, "label": obj.get("displayName", obj["appId"])})
failed_sp_apps = set()
for kind, obj in sorted(ENTRA_DELETED.values(), key=lambda entry: entry[0] != "servicePrincipals"):
    if kind == "applications" and obj["appId"] in failed_sp_apps:
        what = f"Entra application purge {obj['label']} ({obj['id']}) retained for failed service-principal retry"
        print(f"FAILED: {what}")
        FAILED.append(what)
        continue
    purged = do(
        f"Entra deletedItems purge {kind[:-1]} {obj['label']} ({obj['id']})",
        lambda obj=obj: az_json("DELETE", f"https://graph.microsoft.com/v1.0/directory/deletedItems/{obj['id']}"),
    )
    if not purged and kind == "servicePrincipals":
        failed_sp_apps.add(obj["appId"])
for which in args.idp:
    if which == "keycloak":
        kr = os.environ.get("KC_REGION", "us-west-2")
        ec2 = read(f"[{kr}] EC2 client", lambda kr=kr: boto3.client("ec2", region_name=kr))
        iam = read("IAM client for Keycloak", lambda: boto3.client("iam"))
        name = f"{P}-kc"
        for r in rows(
            f"[{kr}] Keycloak EC2 instances",
            ec2,
            "describe_instances",
            "Reservations",
            Filters=[
                {"Name": "tag:Name", "Values": [name]},
                {"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]},
            ],
        ):
            for i in r["Instances"]:
                do(
                    f"[{kr}] EC2 instance {i['InstanceId']} ({name})",
                    lambda i=i, ec2=ec2: (
                        ec2.terminate_instances(InstanceIds=[i["InstanceId"]]),
                        ec2.get_waiter("instance_terminated").wait(InstanceIds=[i["InstanceId"]]),
                    ),
                )
        eips = (
            read(f"[{kr}] Keycloak EIPs", lambda ec2=ec2, name=name: idp.keycloak_eips(ec2, name))
            if ec2 is not None
            else None
        )
        for a in sum(eips or ([], []), []):
            do(
                f"[{kr}] Elastic IP {a['PublicIp']}",
                lambda a=a, ec2=ec2: ec2.release_address(AllocationId=a["AllocationId"]),
            )
        for g in rows(
            f"[{kr}] Keycloak security groups",
            ec2,
            "describe_security_groups",
            "SecurityGroups",
            Filters=[{"Name": "group-name", "Values": [name]}],
        ):
            do(
                f"[{kr}] security group {g['GroupId']} ({name})",
                lambda g=g, ec2=ec2: ec2.delete_security_group(GroupId=g["GroupId"]),
            )

        def drop_profile(iam: Any = iam, name: str = name) -> None:
            """Delete the instance profile and the role of the Keycloak instance."""
            do(
                f"detach instance profile role {name}",
                lambda: iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=name),
            )
            do(f"instance profile {name}", lambda: iam.delete_instance_profile(InstanceProfileName=name))
            for n in rows(f"IAM inline policies {name}", iam, "list_role_policies", "PolicyNames", RoleName=name):
                do(f"IAM inline policy {name}/{n}", lambda n=n: iam.delete_role_policy(RoleName=name, PolicyName=n))
            for a in rows(
                f"IAM attached policies {name}", iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name
            ):
                do(
                    f"IAM attached policy {name}/{a['PolicyArn']}",
                    lambda a=a: iam.detach_role_policy(RoleName=name, PolicyArn=a["PolicyArn"]),
                )
            iam.delete_role(RoleName=name)

        if (
            iam is not None
            and read(
                f"IAM role {name}",
                lambda iam=iam, name=name: iam.get_role(RoleName=name),
                missing=(iam.exceptions.NoSuchEntityException,),
            )
            is not None
        ):
            do(f"IAM role + instance profile {name}", drop_profile)
        host, zone = os.environ.get("KC_HOSTNAME"), os.environ.get("KC_HOSTED_ZONE_ID")
        if host and zone:
            r53 = read("Route 53 client", lambda: boto3.client("route53"))
            for rr in rows(
                f"Route 53 record {host}",
                r53,
                "list_resource_record_sets",
                "ResourceRecordSets",
                HostedZoneId=zone,
                StartRecordName=host,
                StartRecordType="A",
                MaxItems="1",
            ):
                if rr["Name"].rstrip(".") == host and rr["Type"] == "A":
                    do(
                        f"Route 53 A record {host} (only this record)",
                        lambda rr=rr, r53=r53, zone=zone: r53.change_resource_record_sets(
                            HostedZoneId=zone, ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rr}]}
                        ),
                    )
        else:
            print("note: set KC_HOSTNAME and KC_HOSTED_ZONE_ID to also delete the DNS record")
    for s in rows(
        f"Secrets Manager {P}/{which}/",
        sm,
        "list_secrets",
        "SecretList",
        Filters=[{"Key": "name", "Values": [f"{P}/{which}/"]}],
    ):
        if s["Name"].startswith(f"{P}/{which}/"):
            do(f"secret {s['Name']}", lambda s=s: sm.delete_secret(SecretId=s["Name"], ForceDeleteWithoutRecovery=True))
if not X:
    print("\n(dry run: nothing was deleted; add --execute)")
elif FAILED:
    print(f"\n{len(FAILED)} deletion(s) failed; fix the cause and run again, then finish with a dry run:")
    for what in FAILED:
        print("  -", what)
if UNCHECKED:
    print(f"\nNOT CHECKED: {len(UNCHECKED)} resource check(s) incomplete; resolve the reported issues and retry.")
if FAILED or UNCHECKED:
    sys.exit(1)
