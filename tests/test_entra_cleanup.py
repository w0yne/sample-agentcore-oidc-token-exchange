"""Run cleanup with mocked SDK and CLI boundaries; never start az."""

import contextlib
import io
import json
import os
import pathlib
import runpy
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

from entra_fixtures import TENANT

from lib import idp

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts/cleanup.py"


class MissingResourceError(Exception):
    pass


class EntraCleanupTest(unittest.TestCase):
    def cleanup(self, options, az_missing=False, wrong_tenant=False, duplicate_app=False, users=None):
        ctl, iam, lam, api, logs, sm = (mock.Mock() for _ in range(6))
        ctl.list_gateways.return_value = {"items": []}
        ctl.list_oauth2_credential_providers.return_value = {
            "credentialProviders": [{"name": "sample-oidc-entra"}, {"name": "sample-oidc-keycloak"}]
        }
        ctl.list_workload_identities.return_value = {"workloadIdentities": []}
        iam.exceptions.NoSuchEntityException = MissingResourceError
        iam.get_role.side_effect = MissingResourceError
        lam.exceptions.ResourceNotFoundException = MissingResourceError
        lam.get_function.side_effect = MissingResourceError
        api.get_apis.return_value = {
            "Items": [
                {"Name": "sample-oidc-entra-resource-api-jwt", "ApiId": "entra-api"},
                {"Name": "sample-oidc-keycloak-resource-api-jwt", "ApiId": "keycloak-api"},
            ]
        }
        logs.describe_log_groups.return_value = {"logGroups": []}
        sm.list_secrets.return_value = {
            "SecretList": [
                {"Name": "sample-oidc/entra/users"},
                {"Name": "sample-oidc-extra/entra/users"},
                {"Name": "sample-oidc/keycloak/users"},
            ]
        }
        session = mock.Mock()
        session.client.side_effect = {
            "bedrock-agentcore-control": ctl,
            "iam": iam,
            "lambda": lam,
            "apigatewayv2": api,
            "logs": logs,
        }.__getitem__

        def az(argv, **kwargs):
            if az_missing:
                raise FileNotFoundError("az missing")
            if "DELETE" in argv:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            url = argv[argv.index("--url") + 1]
            if "/organization" in url:
                value = [
                    {
                        "id": "wrong" if wrong_tenant else TENANT,
                        "verifiedDomains": [{"name": "example.com", "isDefault": True}],
                    }
                ]
            elif "/applications?" in url:
                value = [
                    {"id": "app-id", "displayName": "sample-oidc-app"},
                    {"id": "unrelated", "displayName": "sample-oidc-extra-app"},
                ]
                if duplicate_app:
                    value.append({"id": "duplicate", "displayName": "sample-oidc-app"})
            elif "/users?" in url:
                value = users or []
            else:
                value = []
            return SimpleNamespace(returncode=0, stdout=json.dumps({"value": value}), stderr="")

        output = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", [str(SCRIPT), *options]))
            stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
            stack.enter_context(mock.patch.dict(os.environ, {"IDP": "entra", "ENTRA_TENANT_ID": TENANT}))
            stack.enter_context(mock.patch.multiple(idp, PREFIX="sample-oidc", REGION="us-west-2"))
            stack.enter_context(mock.patch.object(idp, "session", return_value=session))
            stack.enter_context(mock.patch("boto3.client", return_value=sm))
            cli = stack.enter_context(mock.patch("subprocess.run", side_effect=az))
            stack.enter_context(contextlib.redirect_stdout(output))
            stack.enter_context(contextlib.redirect_stderr(output))
            code = 0
            try:
                runpy.run_path(str(SCRIPT), run_name="__main__")
            except SystemExit as error:
                code = error.code
        return code, output.getvalue(), cli, api, sm, ctl

    def test_skip_keeps_entra_objects_but_removes_only_selected_aws_resources(self):
        code, _, cli, api, sm, ctl = self.cleanup(["--execute", "--idp", "entra", "--skip-entra-objects"])
        self.assertEqual(code, 0)
        cli.assert_not_called()
        api.delete_api.assert_called_once_with(ApiId="entra-api")
        ctl.delete_oauth2_credential_provider.assert_called_once_with(name="sample-oidc-entra")
        sm.delete_secret.assert_called_once_with(SecretId="sample-oidc/entra/users", ForceDeleteWithoutRecovery=True)

    def test_dry_run_lists_exact_entra_objects_without_deletions(self):
        code, text, cli, api, sm, _ = self.cleanup(["--idp", "entra"])
        self.assertEqual(code, 0)
        self.assertIn("would delete: Entra application sample-oidc-app", text)
        self.assertNotIn("sample-oidc-extra-app", text)
        self.assertFalse(any("DELETE" in c.args[0] for c in cli.call_args_list))
        api.delete_api.assert_not_called()
        sm.delete_secret.assert_not_called()

    def test_execute_deletes_exact_entra_objects(self):
        code, _, cli, _, _, _ = self.cleanup(["--execute", "--idp", "entra"])
        self.assertEqual(code, 0)
        deletes = [c.args[0] for c in cli.call_args_list if "DELETE" in c.args[0]]
        self.assertEqual(len(deletes), 1)
        self.assertIn("https://graph.microsoft.com/v1.0/applications/app-id", deletes[0])

    def test_missing_cli_or_wrong_tenant_cannot_report_clean(self):
        for options in ({"az_missing": True}, {"wrong_tenant": True}):
            with self.subTest(options=options):
                code, text, cli, _, _, _ = self.cleanup(["--idp", "entra"], **options)
                self.assertNotEqual(code, 0)
                self.assertIn("NOT CHECKED", text)
                self.assertFalse(any("DELETE" in c.args[0] for c in cli.call_args_list))

    def test_duplicate_application_names_stop_before_any_deletion(self):
        code, text, cli, api, sm, _ = self.cleanup(["--execute", "--idp", "entra"], duplicate_app=True)
        self.assertNotEqual(code, 0)
        self.assertIn("NOT CHECKED", text)
        self.assertFalse(any("DELETE" in c.args[0] for c in cli.call_args_list))
        api.delete_api.assert_not_called()
        sm.delete_secret.assert_not_called()

    def test_user_selection_uses_upn_not_shared_display_name(self):
        users = [
            {"id": "ours", "displayName": "sample-oidc-user-a", "userPrincipalName": "sample-oidc-user-a@example.com"},
            {"id": "foreign", "displayName": "sample-oidc-user-a", "userPrincipalName": "other@example.com"},
        ]
        code, _, cli, _, _, _ = self.cleanup(["--execute", "--idp", "entra"], users=users)
        self.assertEqual(code, 0)
        deleted = [c.args[0] for c in cli.call_args_list if "DELETE" in c.args[0]]
        self.assertTrue(any("https://graph.microsoft.com/v1.0/users/ours" in call for call in deleted))
        self.assertFalse(any("https://graph.microsoft.com/v1.0/users/foreign" in call for call in deleted))
