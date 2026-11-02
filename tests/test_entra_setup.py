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
        self.client_secrets = {}
        self.issued_tokens = {}

    def __call__(self, method, url, body=None, **kwargs):
        self.calls.append((method, url, body))
        path = url.split("/v1.0/")[1]
        if path.startswith("organization?"):
            return {"value": [{"id": TENANT, "verifiedDomains": [{"name": "example.com", "isDefault": True}]}]}
        if path.endswith("/addPassword"):
            self.passwords_created += 1
            app = self.objects["applications"][path.split("/")[1]]
            secret = f"synthetic-client-secret-{self.passwords_created}"
            self.client_secrets[app["appId"]] = secret
            return {"secretText": secret, "keyId": "key"}
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

    def post_token(self, url, form):
        if url != f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token":
            raise AssertionError(url)
        if form["grant_type"] != "password" or form["client_secret"] != self.client_secrets[form["client_id"]]:
            raise AssertionError("Expected valid confidential-client password grant")
        audience, requested_scope = form["scope"].rsplit("/", 1)
        resource = next(a for a in self.objects["applications"].values() if audience in a.get("identifierUris", []))
        sp_ids = {sp["appId"]: sp["id"] for sp in self.objects["servicePrincipals"].values()}
        # Entra includes every consented delegated scope for this client/resource,
        # not just the scope requested in this password grant.
        scopes = {
            scope
            for grant in self.objects["oauth2PermissionGrants"].values()
            if grant["clientId"] == sp_ids[form["client_id"]]
            and grant["resourceId"] == sp_ids[resource["appId"]]
            and grant["consentType"] == "AllPrincipals"
            for scope in grant["scope"].split()
        }
        if requested_scope not in scopes:
            raise AssertionError("Requested scope has no delegated consent")
        token = f"opaque-test-token-{len(self.issued_tokens)}"
        self.issued_tokens[token] = {
            "aud": resource["appId"],
            "azp": form["client_id"],
            "scp": " ".join(sorted(scopes)),
        }
        return {"access_token": token}


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
        self.assertEqual(len(self.graph.objects["applications"]), 4)
        self.assertEqual(len(self.graph.objects["servicePrincipals"]), 5)  # Includes Microsoft Graph.
        self.assertEqual(len(self.graph.objects["users"]), 2)
        self.assertEqual(self.graph.passwords_created, 3)
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

    def test_noscope_is_confidential_and_persists_only_identifiers_in_state(self):
        self.main()
        applications = {a["displayName"]: a for a in self.graph.objects["applications"].values()}
        self.assertIn("sample-oidc-noscope", applications)
        noscope = applications["sample-oidc-noscope"]
        self.assertEqual(noscope["signInAudience"], "AzureADMyOrg")
        self.assertEqual(noscope["web"], applications["sample-oidc-app"]["web"])
        self.assertFalse(noscope.get("isFallbackPublicClient", False))
        sp = next(s for s in self.graph.objects["servicePrincipals"].values() if s["appId"] == noscope["appId"])
        credentials = self.store["sample-oidc/entra/noscope-client"]
        self.assertEqual(credentials["tenant_id"], TENANT)
        self.assertEqual(credentials["client_id"], noscope["appId"])
        self.assertEqual(credentials["client_secret"], self.graph.client_secrets[noscope["appId"]])
        password_call = next(
            body
            for method, url, body in self.graph.calls
            if method == "POST" and url.endswith(f"/applications/{noscope['id']}/addPassword")
        )
        self.assertEqual(password_call["passwordCredential"]["displayName"], "sample-oidc-noscope-sample")
        self.assertEqual(credentials["expires"], password_call["passwordCredential"]["endDateTime"])
        with open(idp.state_file("entra", "state"), encoding="utf-8") as file:
            state = json.load(file)
        self.assertEqual(state["noscope"], {"appId": noscope["appId"], "objectId": noscope["id"], "spId": sp["id"]})
        self.assertNotIn(credentials["client_secret"], json.dumps(state))

    def test_resource_permissions_and_consents_are_isolated_without_changing_other_grants(self):
        self.main()
        applications = {a["displayName"]: a for a in self.graph.objects["applications"].values()}
        self.assertIn("sample-oidc-noscope", applications)
        resource = applications["sample-oidc-resource-api"]
        scope_ids = {s["value"]: s["id"] for s in resource["api"]["oauth2PermissionScopes"]}
        for kind, scope in (("app", "resource.read"), ("gateway", "resource.read"), ("noscope", "resource.other")):
            with self.subTest(client=kind):
                name = f"sample-oidc-{kind}"
                access = [
                    r for r in applications[name]["requiredResourceAccess"] if r["resourceAppId"] == resource["appId"]
                ]
                self.assertEqual(
                    access,
                    [
                        {
                            "resourceAppId": resource["appId"],
                            "resourceAccess": [{"id": scope_ids[scope], "type": "Scope"}],
                        }
                    ],
                )
        self.assertEqual(len(applications["sample-oidc-noscope"]["requiredResourceAccess"]), 1)
        sp_names = {
            sp["id"]: next(
                (a["displayName"] for a in applications.values() if a["appId"] == sp["appId"]), "Microsoft Graph"
            )
            for sp in self.graph.objects["servicePrincipals"].values()
        }
        grants = self.graph.objects["oauth2PermissionGrants"].values()
        self.assertEqual(len(grants), 6)
        self.assertEqual(
            {(sp_names[g["clientId"]], sp_names[g["resourceId"]], g["consentType"], g["scope"]) for g in grants},
            {
                ("sample-oidc-app", "sample-oidc-resource-api", "AllPrincipals", "resource.read"),
                ("sample-oidc-app", "sample-oidc-gateway", "AllPrincipals", "access"),
                ("sample-oidc-app", "Microsoft Graph", "AllPrincipals", "openid profile email User.Read"),
                ("sample-oidc-gateway", "sample-oidc-resource-api", "AllPrincipals", "resource.read"),
                ("sample-oidc-gateway", "sample-oidc-gateway", "AllPrincipals", "access"),
                ("sample-oidc-noscope", "sample-oidc-resource-api", "AllPrincipals", "resource.other"),
            },
        )

    def test_negative_token_excludes_required_scope_when_entra_returns_all_consented_scopes(self):
        self.main()
        adapter = idp.load("entra")
        with (
            mock.patch.object(idp, "secret", side_effect=self.store.__getitem__),
            mock.patch.object(idp, "post_form", side_effect=self.graph.post_token),
        ):
            positive = self.graph.issued_tokens[adapter.token("user-a", "resource")]
            negative = self.graph.issued_tokens[adapter.token_without_resource_scope("user-a")]
        self.assertNotIn("resource.read", negative["scp"].split())
        self.assertEqual(negative["scp"], "resource.other")
        self.assertEqual(positive["scp"], "resource.read")
        self.assertEqual(negative["aud"], positive["aud"])
        self.assertEqual(negative["aud"], adapter.expected_resource_aud())
        self.assertNotEqual(negative["azp"], positive["azp"])
        self.assertEqual(negative["azp"], adapter.state()["noscope"]["appId"])

    def test_rerun_removes_legacy_main_client_scope_from_permissions_and_consent(self):
        self.main()
        applications = {a["displayName"]: a for a in self.graph.objects["applications"].values()}
        resource = applications["sample-oidc-resource-api"]
        app = applications["sample-oidc-app"]
        scope_ids = {s["value"]: s["id"] for s in resource["api"]["oauth2PermissionScopes"]}
        access = next(r for r in app["requiredResourceAccess"] if r["resourceAppId"] == resource["appId"])
        access["resourceAccess"] = [{"id": value, "type": "Scope"} for value in scope_ids.values()]
        sp_ids = {sp["appId"]: sp["id"] for sp in self.graph.objects["servicePrincipals"].values()}
        grant = next(
            g
            for g in self.graph.objects["oauth2PermissionGrants"].values()
            if g["clientId"] == sp_ids[app["appId"]] and g["resourceId"] == sp_ids[resource["appId"]]
        )
        grant["scope"] = "resource.read resource.other"
        credentials_before = json.dumps(self.store, sort_keys=True)
        self.main()
        access = next(r for r in app["requiredResourceAccess"] if r["resourceAppId"] == resource["appId"])
        self.assertEqual(grant["scope"], "resource.read")
        self.assertEqual(access["resourceAccess"], [{"id": scope_ids["resource.read"], "type": "Scope"}])
        self.assertEqual(json.dumps(self.store, sort_keys=True), credentials_before)

    def test_stale_noscope_credentials_stop_before_graph_mutations_or_secret_writes(self):
        for mismatch in ("tenant", "client", "missing_app"):
            with self.subTest(mismatch=mismatch):
                graph = FakeGraph()
                app = graph("POST", f"{self.module['GRAPH']}/applications", {"displayName": "sample-oidc-noscope"})
                self.store.clear()
                self.store["sample-oidc/entra/noscope-client"] = {
                    "tenant_id": "other-tenant" if mismatch == "tenant" else TENANT,
                    "client_id": "other-client" if mismatch == "client" else app["appId"],
                    "client_secret": "retained-synthetic-secret",
                }
                if mismatch == "missing_app":
                    graph.objects["applications"].clear()
                graph.calls.clear()
                idp.put_secret.reset_mock()
                with mock.patch.dict(self.main.__globals__, {"az": graph}):
                    with self.assertRaises(SystemExit):
                        self.main()
                self.assertFalse(any(method != "GET" for method, _, _ in graph.calls))
                idp.put_secret.assert_not_called()

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
