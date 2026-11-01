"""Shared plumbing for the selected IdP: state, naming and API clients.

Environment (all optional):
  IDP                 keycloak (default) | entra
  SAMPLE_PREFIX       name prefix of every AWS resource and secret (default sample-oidc)
  SAMPLE_REGION       region of the resource API, Gateway and Identity
                      (default us-west-2; partition is derived; regional features need confirmation)
  SAMPLE_PROFILE      AWS profile for those resources (default: the default credential chain)
  SECRETS_REGION      region of the Secrets Manager secrets that hold IdP credentials, read with the default
                      credential chain (default us-west-2); the Gateway side never needs them, only the
                      Identity provider is created from them
"""

import importlib.util
import json
import os
import pathlib
import urllib.error
import urllib.parse
import urllib.request
from types import ModuleType
from typing import Any

import boto3

from lib import net

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE = pathlib.Path(os.environ.get("SAMPLE_STATE", ROOT / ".state"))
PREFIX = os.environ.get("SAMPLE_PREFIX", "sample-oidc")
REGION = os.environ.get("SAMPLE_REGION", "us-west-2")
PROFILE = os.environ.get("SAMPLE_PROFILE") or None
SECRETS_REGION = os.environ.get("SECRETS_REGION", "us-west-2")
PARTITION = "aws-cn" if REGION.startswith("cn-") else "aws"
USERS = ("user-a", "user-b")


def load(name: str | None = None) -> ModuleType:
    """Load the selected Keycloak or Microsoft Entra ID adapter."""
    name = selected_name(name)
    spec = importlib.util.spec_from_file_location(f"adapter_{name}", ROOT / "idp" / name / "adapter.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def selected_name(name: str | None = None) -> str:
    """Resolve and validate an IdP name before using it in a path."""
    name = name if name is not None else os.environ.get("IDP", "keycloak")
    if name not in ("keycloak", "entra"):
        raise ValueError("IDP must be keycloak or entra")
    return name


def state_file(idp: str, kind: str) -> pathlib.Path:
    """Return the path of the state file for an IdP and kind, creating the state directory."""
    STATE.mkdir(exist_ok=True)
    return STATE / f"{idp}-{kind}.json"


def evidence_path(name: str) -> pathlib.Path:
    """Return the path of an evidence file for the current IdP, creating its directory."""
    d = ROOT / "evidence" / selected_name()
    d.mkdir(parents=True, exist_ok=True)
    return d / name


def session(region: str | None = None) -> boto3.Session:
    """Return a boto3 session for the sample profile and the given (or default) region."""
    return boto3.Session(profile_name=PROFILE, region_name=region or REGION)


def secret_id(idp: str, what: str) -> str:
    """Return the Secrets Manager name of a sample secret."""
    return f"{PREFIX}/{idp}/{what}"


def secret(name: str) -> dict[str, Any]:
    """Read a JSON secret from Secrets Manager."""
    return json.loads(
        boto3.client("secretsmanager", region_name=SECRETS_REGION).get_secret_value(SecretId=name)["SecretString"]
    )


def put_secret(name: str, value: dict[str, Any], tags: list[dict[str, str]]) -> None:
    """Create a JSON secret, or write a new version if it already exists."""
    sm = boto3.client("secretsmanager", region_name=SECRETS_REGION)
    try:
        sm.create_secret(Name=name, SecretString=json.dumps(value), Tags=tags)
    except sm.exceptions.ResourceExistsException:
        sm.put_secret_value(SecretId=name, SecretString=json.dumps(value))


def post_form(url: str, form: dict[str, str]) -> dict[str, Any]:
    """POST a form and return the JSON response (also for HTTP error responses)."""
    req = urllib.request.Request(  # noqa: S310  URL comes from the IdP configuration, not user input
        url, urllib.parse.urlencode(form).encode(), {"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with net.open_https(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def keycloak_eips(ec2: Any, name: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return the Elastic IPs of the Keycloak instance `name` as ``(named, untagged)``.

    Both carry the tag project=<prefix>. `named` also has Name=`name`; `untagged` has no Name tag at all
    (infra.py adopts it and adds the Name tag). Elastic IPs with a different Name are not ours and are ignored.
    """
    named, untagged = [], []
    for a in ec2.describe_addresses(Filters=[{"Name": "tag:project", "Values": [PREFIX]}])["Addresses"]:
        names = [t["Value"] for t in a.get("Tags", []) if t["Key"] == "Name"]
        if names == [name]:
            named.append(a)
        elif not names:
            untagged.append(a)
    return named, untagged


def claim_keycloak_eip(ec2: Any, name: str, tags: list[dict[str, str]]) -> dict[str, Any]:
    """Return the Elastic IP of Keycloak instance `name`, adopting an untagged one or allocating a new one.

    A single untagged Elastic IP (tag project only) is adopted by adding the Name tag before anything is associated, so
    the DNS record that already points to it stays valid. More than one candidate is ambiguous and is refused.
    """
    named, untagged = keycloak_eips(ec2, name)
    found = named + untagged
    if len(found) > 1:
        ips = ", ".join(a["PublicIp"] for a in found)
        raise SystemExit(
            f"{len(found)} Elastic IPs carry project={PREFIX} ({ips}); release or re-tag the extra ones first"
        )
    if named:
        return named[0]
    if untagged:
        ec2.create_tags(Resources=[untagged[0]["AllocationId"]], Tags=[{"Key": "Name", "Value": name}])
        return untagged[0]
    alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": [*tags, {"Key": "Name", "Value": name}]}],
    )
    return {"AllocationId": alloc["AllocationId"], "PublicIp": alloc["PublicIp"]}
