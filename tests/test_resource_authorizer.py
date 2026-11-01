"""Provisioning sends a managed JWT gate to AWS before enabling the endpoint."""

import contextlib
import io
import pathlib
import runpy
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from entra_fixtures import RESOURCE, TENANT
from entra_fixtures import adapter as entra_adapter

from lib import idp

ROOT = pathlib.Path(__file__).resolve().parents[1]
ACCOUNT = "123456" + "789012"


class ResourceAuthorizerTest(unittest.TestCase):
    def deploy(self, existing, fail_authorizer=False, base_api=False, reuse_integration=False, selected=None):
        name = selected.NAME if selected else "keycloak"
        timeline = mock.Mock()
        api, iam, lam, sts = (mock.Mock() for _ in range(4))
        for client_name, client in (("api", api), ("iam", iam), ("lam", lam)):
            timeline.attach_mock(client, client_name)
        endpoint = {
            "ApiId": "example",
            "Name": f"sample-oidc-{name}-resource-api-jwt",
            "ApiEndpoint": "https://api.example.com",
        }
        api.get_apis.return_value = {"Items": [endpoint] if existing else []}
        if base_api:
            api.get_apis.return_value["Items"].append(
                {
                    "ApiId": "base",
                    "Name": "sample-oidc-keycloak-resource-api",
                    "ApiEndpoint": "https://base.example.com",
                }
            )
        api.create_api.return_value = endpoint
        api.get_authorizers.return_value = {
            "Items": [{"AuthorizerId": "jwt", "Name": f"{name}-jwt"}] if existing else []
        }
        api.create_authorizer.return_value = {"AuthorizerId": "jwt"}
        api.get_routes.return_value = {
            "Items": [{"RouteId": "extra", "RouteKey": "$default"}, {"RouteId": "who", "RouteKey": "GET /v1/me"}]
            if existing
            else []
        }
        api.get_integrations.return_value = {"Items": []}
        if reuse_integration:
            api.get_integrations.return_value["Items"].append(
                {
                    "IntegrationId": "reused",
                    "IntegrationUri": "arn:aws:lambda:us-west-2:" + ACCOUNT + ":function:sample",
                }
            )
        api.create_integration.return_value = {"IntegrationId": "integration"}
        api.get_stages.return_value = {"Items": [{"StageName": "$default"}] if existing else []}
        iam.get_role.return_value = {"Role": {"Arn": "arn:aws:iam::" + ACCOUNT + ":role/example"}}
        lam.get_function.return_value = {
            "Configuration": {"FunctionArn": "arn:aws:lambda:us-west-2:" + ACCOUNT + ":function:sample"}
        }
        sts.get_caller_identity.return_value = {"Account": ACCOUNT}
        if fail_authorizer:
            api.update_authorizer.side_effect = RuntimeError("simulated authorizer failure")
        adapter = SimpleNamespace(
            NAME="keycloak",
            resource_api_config=lambda: {
                "issuer": "https://idp.example.com/realms/sample",
                "audiences": ["resource-api"],
                "required_scope": "resource.read",
            },
        )
        session = mock.Mock()
        session.client.side_effect = {"apigatewayv2": api, "iam": iam, "lambda": lam, "sts": sts}.__getitem__
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            state = pathlib.Path(directory)
            archive = state / "api.zip"
            archive.write_bytes(b"archive-fixture")
            stack.enter_context(
                mock.patch.multiple(idp, STATE=state, PARTITION="aws", REGION="us-west-2", PREFIX="sample-oidc")
            )
            stack.enter_context(mock.patch.object(idp, "load", return_value=selected or adapter))
            stack.enter_context(mock.patch.object(idp, "session", return_value=session))
            stack.enter_context(mock.patch.object(sys, "argv", [str(ROOT / "resource-api/deploy.py"), str(archive)]))
            stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            try:
                runpy.run_path(str(ROOT / "resource-api/deploy.py"), run_name="__main__")
            except RuntimeError:
                if not fail_authorizer:
                    raise
        return timeline, api, lam

    def test_new_api_has_managed_issuer_audience_scope_and_no_quick_create(self):
        _, api, _ = self.deploy(False)
        self.assertNotIn("Target", api.create_api.call_args.kwargs)
        self.assertTrue(api.create_api.call_args.kwargs["DisableExecuteApiEndpoint"])
        cfg = api.create_authorizer.call_args.kwargs
        self.assertEqual(cfg["AuthorizerType"], "JWT")
        self.assertEqual(cfg["IdentitySource"], ["$request.header.Authorization"])
        self.assertEqual(
            cfg["JwtConfiguration"], {"Issuer": "https://idp.example.com/realms/sample", "Audience": ["resource-api"]}
        )
        route = api.create_route.call_args.kwargs
        self.assertEqual(route["RouteKey"], "GET /v1/me")
        self.assertEqual(route["AuthorizationType"], "JWT")
        self.assertEqual(route["AuthorizerId"], "jwt")
        self.assertEqual(route["AuthorizationScopes"], ["resource.read"])

    def test_existing_routes_are_gated_before_echo_code_is_uploaded(self):
        timeline, api, lam = self.deploy(True)
        calls = timeline.mock_calls
        upload = next(i for i, c in enumerate(calls) if c[0] == "lam.update_function_code")
        updates = [(i, c.kwargs) for i, c in enumerate(calls) if c[0] == "api.update_route"]
        self.assertEqual({p["RouteId"] for _, p in updates}, {"extra", "who"})
        for i, params in updates[:2]:
            self.assertLess(i, upload)
            self.assertEqual(params["AuthorizationType"], "JWT")
            self.assertEqual(params["AuthorizationScopes"], ["resource.read"])
        api.delete_route.assert_called_once_with(ApiId="example", RouteId="extra")
        self.assertEqual(lam.update_function_configuration.call_args.kwargs["Environment"], {"Variables": {}})
        self.assertEqual(api.update_api.call_args.kwargs["DisableExecuteApiEndpoint"], False)

    def test_gate_failure_does_not_upload_echo_code_or_enable_endpoint(self):
        _, api, lam = self.deploy(True, fail_authorizer=True)
        lam.update_function_code.assert_not_called()
        self.assertTrue(api.update_api.call_args.kwargs["DisableExecuteApiEndpoint"])

    def test_base_named_api_is_deleted_while_invocation_is_suspended(self):
        timeline, api, _ = self.deploy(False, base_api=True)
        calls = timeline.mock_calls
        revoke = next(i for i, c in enumerate(calls) if c[0] == "lam.remove_permission")
        delete = next(i for i, c in enumerate(calls) if c[0] == "api.delete_api")
        upload = next(i for i, c in enumerate(calls) if c[0] == "lam.update_function_code")
        self.assertLess(revoke, delete)
        self.assertLess(delete, upload)
        api.delete_api.assert_called_once_with(ApiId="base")
        self.assertEqual(api.create_api.call_args.kwargs["Name"], "sample-oidc-keycloak-resource-api-jwt")
        for call in api.update_stage.call_args_list:
            self.assertNotEqual(call.kwargs["ApiId"], "base")

    def test_redeploy_reuses_existing_integration(self):
        _, api, _ = self.deploy(True, reuse_integration=True)
        api.create_integration.assert_not_called()
        self.assertEqual(api.update_integration.call_args.kwargs["IntegrationId"], "reused")
        self.assertEqual(api.update_route.call_args.kwargs["Target"], "integrations/reused")

    def test_entra_create_and_update_use_adapter_gate_without_lambda_configuration(self):
        selected = entra_adapter(self)
        for existing in (False, True):
            with self.subTest(existing=existing):
                _, api, lam = self.deploy(existing, selected=selected)
                call = api.update_authorizer if existing else api.create_authorizer
                self.assertEqual(call.call_args.kwargs["Name"], "entra-jwt")
                self.assertEqual(
                    call.call_args.kwargs["JwtConfiguration"],
                    {"Issuer": f"https://login.microsoftonline.com/{TENANT}/v2.0", "Audience": [RESOURCE]},
                )
                route = api.update_route if existing else api.create_route
                self.assertEqual(route.call_args.kwargs["AuthorizationScopes"], ["resource.read"])
                self.assertEqual(lam.update_function_configuration.call_args.kwargs["Environment"], {"Variables": {}})
