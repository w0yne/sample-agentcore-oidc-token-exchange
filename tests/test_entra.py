"""Entra adapter contracts; no IdP, Azure CLI or AWS calls."""

import os
import pathlib
import tempfile
import unittest
from unittest import mock

from entra_fixtures import APP, GATEWAY, RESOURCE, TENANT, adapter

from lib import idp


class IdpSelectionTest(unittest.TestCase):
    def test_entra_is_selectable_and_keycloak_remains_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(idp.load().NAME, "keycloak")
        with mock.patch.dict(os.environ, {"IDP": "entra"}):
            try:
                selected = idp.load()
            except ValueError as error:
                self.fail(f"Entra must be selectable: {error}")
            self.assertEqual(selected.NAME, "entra")
            self.assertEqual(idp.load("keycloak").NAME, "keycloak")

    def test_unknown_idp_is_rejected_before_file_access(self):
        for value in ("unknown", "../keycloak", "Entra"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                idp.load(value)

    def test_evidence_and_state_are_separate_for_each_idp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with mock.patch.multiple(idp, ROOT=root, STATE=root / ".state"):
                for name in ("keycloak", "entra"):
                    with mock.patch.dict(os.environ, {"IDP": name}):
                        self.assertEqual(idp.evidence_path("checks.json"), root / "evidence" / name / "checks.json")
                        self.assertEqual(idp.state_file(name, "state"), root / ".state" / f"{name}-state.json")


class EntraAdapterTest(unittest.TestCase):
    def setUp(self):
        self.a = adapter(self)

    def test_managed_resource_gate_uses_v2_issuer_and_only_guid_audience(self):
        self.assertEqual(
            self.a.resource_api_config(),
            {
                "issuer": f"https://login.microsoftonline.com/{TENANT}/v2.0",
                "audiences": [RESOURCE],
                "required_scope": "resource.read",
            },
        )
        self.assertEqual(self.a.USER_ID_CLAIM, "oid")
        self.assertEqual(self.a.expected_resource_aud(), RESOURCE)
        self.assertEqual(self.a.expected_exchanged_azp(), GATEWAY)

    def test_gateway_door_excludes_resource_tokens_and_requires_app_azp(self):
        self.assertEqual(
            self.a.door(),
            {
                "discovery_url": f"https://login.microsoftonline.com/{TENANT}/v2.0/.well-known/openid-configuration",
                "audiences": [GATEWAY],
                "client_claim": "azp",
                "client_value": APP,
            },
        )

    def test_identity_provider_uses_microsoft_obo_and_gateway_credentials(self):
        vendor, config = self.a.provider_input()
        self.assertEqual(vendor, "MicrosoftOauth2")
        self.assertEqual(
            config,
            {
                "microsoftOauth2ProviderConfig": {
                    "clientId": GATEWAY,
                    "clientSecret": "synthetic-client-secret",
                    "tenantId": TENANT,
                }
            },
        )
        idp.secret.assert_called_once_with("sample-oidc/entra/gateway-client")
        self.assertEqual(
            self.a.exchange_params(),
            {"scopes": [f"api://{RESOURCE}/resource.read"], "custom": {}, "grant": "TOKEN_EXCHANGE"},
        )

    def test_token_helpers_request_distinct_audiences_and_negative_scope(self):
        with mock.patch.object(self.a, "login_raw", return_value={"access_token": "token", "id_token": "id"}) as login:
            self.assertEqual(self.a.token("user-a", "resource"), "token")
            login.assert_called_with("user-a", f"api://{RESOURCE}/resource.read")
            self.a.token("user-b", "gateway")
            login.assert_called_with("user-b", f"api://{GATEWAY}/access")
            self.a.token_without_resource_scope("user-a")
            login.assert_called_with("user-a", f"api://{RESOURCE}/resource.other", client="noscope")
            self.a.other_client_token("user-a")
            login.assert_called_with("user-a", f"api://{GATEWAY}/access", client="gateway")
            self.assertEqual(self.a.id_token("user-a"), "id")

    def test_login_raw_keeps_secrets_in_post_body_and_uses_tenant_endpoint(self):
        with (
            mock.patch.object(
                idp,
                "secret",
                side_effect=[
                    {"client_id": APP, "client_secret": "synthetic-client-secret"},
                    {"sample-oidc-user-a": {"upn": "user-a@example.com", "password": "synthetic-password"}},
                ],
            ),
            mock.patch.object(idp, "post_form", return_value={"access_token": "token"}) as post,
        ):
            self.a.login_raw("user-a", f"api://{RESOURCE}/resource.read")
        self.assertEqual(post.call_args.args[0], f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token")
        self.assertEqual(post.call_args.args[1]["client_id"], APP)
        self.assertEqual(post.call_args.args[1]["grant_type"], "password")
        self.assertEqual(post.call_args.args[1]["username"], "user-a@example.com")

    def test_negative_scope_token_uses_separate_confidential_client_credentials(self):
        credentials = {
            "sample-oidc/entra/app-client": {
                "client_id": APP,
                "client_secret": "synthetic-app-secret",
            },
            "sample-oidc/entra/noscope-client": {
                "client_id": "noscope-client-id",
                "client_secret": "synthetic-noscope-secret",
            },
            "sample-oidc/entra/users": {
                "sample-oidc-user-a": {"upn": "user-a@example.com", "password": "synthetic-password"}
            },
        }
        with (
            mock.patch.object(idp, "secret", side_effect=credentials.__getitem__) as secret,
            mock.patch.object(idp, "post_form", return_value={"access_token": "negative-token"}) as post,
        ):
            self.assertEqual(self.a.token_without_resource_scope("user-a"), "negative-token")
        self.assertEqual(
            secret.call_args_list,
            [mock.call("sample-oidc/entra/noscope-client"), mock.call("sample-oidc/entra/users")],
        )
        post.assert_called_once_with(
            f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
            {
                "grant_type": "password",
                "client_id": "noscope-client-id",
                "client_secret": "synthetic-noscope-secret",
                "username": "user-a@example.com",
                "password": "synthetic-password",
                "scope": f"api://{RESOURCE}/resource.other",
            },
        )
