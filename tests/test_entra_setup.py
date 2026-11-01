"""Exercise setup against an in-memory Graph and Secrets Manager."""

import contextlib
import io
import json
import os
import pathlib
import runpy
import sys
import tempfile
import unittest
from unittest import mock

from entra_fixtures import TENANT, enter_context

from lib import idp

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "idp/entra/setup.py"


class MissingSecretError(Exception):
    pass


class FakeGraph:
    def __init__(self):
        self.objects = {"applications": {}, "servicePrincipals": {}, "users": {}, "oauth2PermissionGrants": {}}
        self.objects["servicePrincipals"]["graph"] = {"id": "graph", "appId": "00000003-0000-0000-c000-000000000000"}
        self.calls = []
        self.passwords_created = 0

    def __call__(self, method, url, body=None, **kwargs):
        self.calls.append((method, url, body))
        path = url.split("/v1.0/")[1]
        if path.startswith("organization?"):
            return {"value": [{"id": TENANT, "verifiedDomains": [{"name": "example.com", "isDefault": True}]}]}
        if path.endswith("/addPassword"):
            self.passwords_created += 1
            return {"secretText": "synthetic-client-secret", "keyId": "key"}
        bare, _, query = path.partition("?")
        kind, _, oid = bare.partition("/")
        objects = self.objects[kind]
        if method == "GET" and oid:
            return objects[oid]
        if method == "GET":
            rows = list(objects.values())
            if "$filter=" in query:
                for condition in query.split("$filter=")[1].split("&")[0].split(" and "):
                    field, value = condition.split(" eq ")
                    rows = [row for row in rows if row.get(field) == value.strip("'")]
            return {"value": rows}
        if method == "POST":
            oid = f"{kind}-{len(objects)}"
            value = {"id": oid, **body}
            if kind == "applications":
                value["appId"] = f"app-guid-{len(objects)}"
            objects[oid] = value
            return value
        if method == "PATCH":
            objects[oid].update(body)
            return {}
        raise AssertionError((method, url))


class EntraSetupTest(unittest.TestCase):
    def setUp(self):
        enter_context(self, mock.patch.object(idp, "PREFIX", "sample-oidc"))
        enter_context(self, mock.patch.dict(os.environ, {"IDP": "entra", "ENTRA_TENANT_ID": TENANT}))
        self.assertTrue(SCRIPT.exists(), "Entra setup must be restored")
        with mock.patch.object(sys, "path", list(sys.path)):
            self.module = runpy.run_path(str(SCRIPT))
        self.main = self.module["main"]
        self.graph = FakeGraph()
        self.store = {}
        self.sm = mock.Mock()
        self.sm.exceptions.ResourceNotFoundException = MissingSecretError

        def get_secret(**kwargs):
            name = kwargs["SecretId"]
            if name not in self.store:
                raise MissingSecretError
            return {"SecretString": json.dumps(self.store[name])}

        self.sm.get_secret_value.side_effect = get_secret
        enter_context(self, mock.patch.dict(self.main.__globals__, {"az": self.graph}))
        enter_context(self, mock.patch("boto3.client", return_value=self.sm))
        enter_context(self, mock.patch.object(idp, "put_secret", side_effect=lambda n, v, t: self.store.update({n: v})))
        directory = enter_context(self, tempfile.TemporaryDirectory())
        enter_context(self, mock.patch.object(idp, "STATE", pathlib.Path(directory)))
        enter_context(self, contextlib.redirect_stdout(io.StringIO()))

    def test_setup_creates_only_apps_users_and_scopes_and_rerun_is_idempotent(self):
        self.main()
        first_calls = list(self.graph.calls)
        self.main()
        self.assertEqual(len(self.graph.objects["applications"]), 3)
        self.assertEqual(len(self.graph.objects["users"]), 2)
        self.assertEqual(self.graph.passwords_created, 2)
        resource = next(
            a for a in self.graph.objects["applications"].values() if a["displayName"] == "sample-oidc-resource-api"
        )
        self.assertEqual(resource["api"]["requestedAccessTokenVersion"], 2)
        self.assertEqual(resource["identifierUris"], [f"api://{resource['appId']}"])
        self.assertEqual(
            {s["value"] for s in resource["api"]["oauth2PermissionScopes"]}, {"resource.read", "resource.other"}
        )
        self.assertNotIn("groupMembershipClaims", resource)
        self.assertFalse(any("/groups" in url for _, url, _ in self.graph.calls))
        with open(idp.state_file("entra", "state"), encoding="utf-8") as file:
            state = json.load(file)
        self.assertEqual(state["tenantId"], TENANT)
        self.assertEqual(state["prefix"], "sample-oidc")
        self.assertEqual(set(state["users"]), {"sample-oidc-user-a", "sample-oidc-user-b"})
        self.assertNotIn("synthetic-client-secret", json.dumps(state))
        self.assertTrue(any("/oauth2PermissionGrants" in url for _, url, _ in first_calls))
        gateway = next(
            a for a in self.graph.objects["applications"].values() if a["displayName"] == "sample-oidc-gateway"
        )
        gw_sp = next(
            a["id"] for a in self.graph.objects["servicePrincipals"].values() if a["appId"] == gateway["appId"]
        )
        grants = [g for g in self.graph.objects["oauth2PermissionGrants"].values() if g["clientId"] == gw_sp]
        self.assertEqual({g["scope"] for g in grants}, {"access", "resource.read"})

    def test_wrong_tenant_is_rejected_before_mutations(self):
        with mock.patch.dict(os.environ, {"ENTRA_TENANT_ID": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}):
            with self.assertRaises(SystemExit):
                self.main()
        self.assertFalse(any(method != "GET" for method, _, _ in self.graph.calls))
        self.sm.get_secret_value.assert_not_called()

    def test_missing_tenant_fails_before_graph_calls(self):
        with mock.patch.dict(os.environ, {"ENTRA_TENANT_ID": ""}), self.assertRaises(SystemExit):
            self.main()
        self.assertEqual(self.graph.calls, [])

    def test_existing_user_without_stored_password_is_not_reset(self):
        self.main()
        self.store.pop("sample-oidc/entra/users")
        with self.assertRaises(SystemExit):
            self.main()
        self.assertFalse(any(method == "PATCH" and "/users/" in url for method, url, _ in self.graph.calls))

    def test_stale_credentials_stop_before_graph_mutations_or_secret_writes(self):
        self.main()
        for mismatch in ("tenant", "client", "missing_app"):
            with self.subTest(mismatch=mismatch):
                original = dict(self.store["sample-oidc/entra/app-client"])
                if mismatch == "tenant":
                    self.store["sample-oidc/entra/app-client"]["tenant_id"] = "other-tenant"
                elif mismatch == "client":
                    self.store["sample-oidc/entra/app-client"]["client_id"] = "other-client"
                else:
                    oid = next(
                        key
                        for key, value in self.graph.objects["applications"].items()
                        if value["displayName"] == "sample-oidc-app"
                    )
                    self.graph.objects["applications"].pop(oid)
                self.graph.calls.clear()
                idp.put_secret.reset_mock()
                with self.assertRaises(SystemExit):
                    self.main()
                self.assertFalse(any(method != "GET" for method, _, _ in self.graph.calls))
                idp.put_secret.assert_not_called()
                self.store["sample-oidc/entra/app-client"] = original
