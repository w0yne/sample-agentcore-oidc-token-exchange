"""Run cleanup with mocked SDK and CLI boundaries; never start az."""

import contextlib
import io
import json
import os
import pathlib
import runpy
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from botocore.exceptions import ClientError, NoCredentialsError
from entra_fixtures import TENANT

from lib import idp

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts/cleanup.py"


class MissingResourceError(Exception):
    pass


class Directory:
    def __init__(self, active=True, users=None, duplicate_app=False, wrong_tenant=False):
        self.wrong_tenant = wrong_tenant
        self.active = {
            "applications": [
                {"id": "app-id", "appId": "app-guid", "displayName": "sample-oidc-app"},
                {"id": "unrelated", "appId": "foreign-guid", "displayName": "sample-oidc-extra-app"},
            ]
            if active
            else [],
            "users": list(users or []),
            "servicePrincipals": [
                {"id": "sp-id", "appId": "app-guid", "displayName": "renamed-service-principal"},
                {"id": "foreign-sp", "appId": "foreign-guid", "displayName": "sample-oidc-app"},
            ]
            if active
            else [],
        }
        if duplicate_app:
            self.active["applications"].append(
                {"id": "duplicate", "appId": "other-guid", "displayName": "sample-oidc-app"}
            )
        self.deleted = {"application": [], "user": [], "servicePrincipal": []}
        self.failed_purges = set()

    def __call__(self, argv, **kwargs):
        method = argv[argv.index("--method") + 1]
        url = argv[argv.index("--url") + 1]
        path = url.split("/v1.0/")[1].split("?")[0]
        value = []
        if path == "organization":
            value = [
                {
                    "id": "wrong" if self.wrong_tenant else TENANT,
                    "verifiedDomains": [{"name": "example.com", "isDefault": True}],
                }
            ]
        elif method == "GET" and path.startswith("directory/deletedItems/microsoft.graph."):
            value = self.deleted[path.rsplit(".", 1)[1]]
        elif method == "GET":
            value = self.active[path]
        elif path.startswith("directory/deletedItems/"):
            oid = path.rsplit("/", 1)[1]
            if oid in self.failed_purges:
                return SimpleNamespace(returncode=1, stdout="", stderr="purge denied")
            for kind, items in self.deleted.items():
                self.deleted[kind] = [obj for obj in items if obj["id"] != oid]
        else:
            kind, oid = path.split("/")
            objects = [obj for obj in self.active[kind] if obj["id"] == oid]
            self.active[kind] = [obj for obj in self.active[kind] if obj["id"] != oid]
            self.deleted[kind[:-1]].extend(objects)
            if kind == "applications":
                ids = {obj["appId"] for obj in objects}
                cascaded = [obj for obj in self.active["servicePrincipals"] if obj["appId"] in ids]
                self.active["servicePrincipals"] = [
                    obj for obj in self.active["servicePrincipals"] if obj["appId"] not in ids
                ]
                self.deleted["servicePrincipal"].extend(cascaded)
        return SimpleNamespace(returncode=0, stdout=json.dumps({"value": value}) if method == "GET" else "", stderr="")


class EntraCleanupTest(unittest.TestCase):
    def cleanup(
        self,
        options,
        az_missing=False,
        wrong_tenant=False,
        duplicate_app=False,
        users=None,
        directory=None,
        aws_failure=None,
        no_credentials=False,
        iam_roles=False,
        client_failure=None,
        gateways=False,
        state_data=None,
        credential_error=None,
    ):
        ctl, iam, lam, api, logs, sm = (mock.Mock() for _ in range(6))
        ctl.list_gateways.return_value = {"items": []}
        if gateways:
            ctl.list_gateways.return_value = {"items": [{"name": "sample-oidc-entra-gw", "gatewayId": "gateway-id"}]}
        ctl.list_gateway_targets.return_value = {"items": []}
        ctl.list_oauth2_credential_providers.return_value = {
            "credentialProviders": [{"name": "sample-oidc-entra"}, {"name": "sample-oidc-keycloak"}]
        }
        ctl.list_workload_identities.return_value = {"workloadIdentities": []}
        iam.exceptions.NoSuchEntityException = MissingResourceError
        iam.get_role.side_effect = MissingResourceError
        iam.list_role_policies.return_value = {"PolicyNames": ["inline"]}
        iam.list_attached_role_policies.return_value = {"AttachedPolicies": [{"PolicyArn": "arn:example:policy"}]}
        if iam_roles:
            iam.get_role.side_effect = None
            iam.get_role.return_value = {"Role": {"Arn": "arn:example:role"}}
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
        clients = {
            "bedrock-agentcore-control": ctl,
            "iam": iam,
            "lambda": lam,
            "apigatewayv2": api,
            "logs": logs,
            "secretsmanager": sm,
        }
        ec2, r53 = mock.Mock(), mock.Mock()
        ec2.describe_instances.return_value = {"Reservations": []}
        ec2.describe_addresses.return_value = {"Addresses": []}
        ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        r53.list_resource_record_sets.return_value = {"ResourceRecordSets": []}
        clients.update({"ec2": ec2, "route53": r53})
        if aws_failure:
            service, operation = aws_failure
            getattr(clients[service], operation).side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "fixture denied"}}, operation
            )
        session = mock.Mock()

        def client(name, **kwargs):
            if name == client_failure:
                raise credential_error or NoCredentialsError()
            return clients[name]

        session.client.side_effect = client
        directory = directory or Directory(users=users, duplicate_app=duplicate_app, wrong_tenant=wrong_tenant)

        def az(argv, **kwargs):
            if az_missing:
                raise FileNotFoundError("az missing")
            return directory(argv, **kwargs)

        output = io.StringIO()
        with contextlib.ExitStack() as stack:
            state_dir = pathlib.Path(stack.enter_context(tempfile.TemporaryDirectory()))
            if state_data is not None:
                (state_dir / "entra-state.json").write_text(json.dumps(state_data))
            stack.enter_context(mock.patch.object(sys, "argv", [str(SCRIPT), *options]))
            stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
            stack.enter_context(
                mock.patch.dict(
                    os.environ,
                    {
                        "IDP": "entra",
                        "ENTRA_TENANT_ID": TENANT,
                        "KC_HOSTNAME": "keycloak.example.com",
                        "KC_HOSTED_ZONE_ID": "test-zone",
                    },
                )
            )
            stack.enter_context(mock.patch.multiple(idp, PREFIX="sample-oidc", REGION="us-west-2", STATE=state_dir))
            stack.enter_context(
                mock.patch.object(
                    idp, "session", side_effect=NoCredentialsError() if no_credentials else None, return_value=session
                )
            )
            stack.enter_context(mock.patch("boto3.client", side_effect=client))
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
        self.assertEqual(len(deletes), 3)
        self.assertIn("https://graph.microsoft.com/v1.0/applications/app-id", deletes[0])
        self.assertTrue(any("https://graph.microsoft.com/v1.0/directory/deletedItems/app-id" in c for c in deletes))
        self.assertTrue(any("https://graph.microsoft.com/v1.0/directory/deletedItems/sp-id" in c for c in deletes))

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

    def test_aws_read_errors_continue_entra_and_exit_nonzero(self):
        failures = [
            ("bedrock-agentcore-control", "list_gateways"),
            ("bedrock-agentcore-control", "list_oauth2_credential_providers"),
            ("bedrock-agentcore-control", "list_workload_identities"),
            ("apigatewayv2", "get_apis"),
            ("iam", "get_role"),
            ("lambda", "get_function"),
            ("logs", "describe_log_groups"),
            ("secretsmanager", "list_secrets"),
        ]
        for failure in failures:
            with self.subTest(failure=failure):
                directory = Directory()
                code, text, _, _, _, _ = self.cleanup(
                    ["--execute", "--idp", "entra"], directory=directory, aws_failure=failure
                )
                self.assertEqual(code, 1)
                self.assertIn("NOT CHECKED:", text)
                self.assertEqual(directory.deleted["application"], [])
                self.assertFalse(any(a["id"] == "app-id" for a in directory.active["applications"]))

    def test_aws_delete_error_does_not_prevent_other_deletions_or_entra_purge(self):
        directory = Directory()
        code, text, _, _, sm, _ = self.cleanup(
            ["--execute", "--idp", "entra"], directory=directory, aws_failure=("apigatewayv2", "delete_api")
        )
        self.assertEqual(code, 1)
        self.assertIn("FAILED:", text)
        sm.delete_secret.assert_called_once()
        self.assertEqual(directory.deleted["application"], [])
        self.assertFalse(any(a["id"] == "app-id" for a in directory.active["applications"]))

    def test_aws_credentials_error_still_runs_entra(self):
        directory = Directory()
        code, text, _, _, _, _ = self.cleanup(["--execute", "--idp", "entra"], directory=directory, no_credentials=True)
        self.assertEqual(code, 1)
        self.assertIn("NOT CHECKED:", text)
        self.assertEqual(directory.deleted["application"], [])
        self.assertFalse(any(a["id"] == "app-id" for a in directory.active["applications"]))

    def test_aws_dry_run_list_error_is_not_reported_clean(self):
        directory = Directory()
        code, text, cli, _, _, _ = self.cleanup(
            ["--idp", "entra"], directory=directory, aws_failure=("apigatewayv2", "get_apis")
        )
        self.assertEqual(code, 1)
        self.assertIn("NOT CHECKED:", text)
        self.assertIn("would delete: Entra application", text)
        self.assertFalse(any("DELETE" in c.args[0] for c in cli.call_args_list))

    def test_nested_policy_read_or_delete_error_does_not_abort_entra(self):
        for operation in (
            "list_role_policies",
            "list_attached_role_policies",
            "delete_role_policy",
            "detach_role_policy",
        ):
            with self.subTest(operation=operation):
                directory = Directory()
                code, text, _, _, _, _ = self.cleanup(
                    ["--execute", "--idp", "entra"],
                    directory=directory,
                    aws_failure=("iam", operation),
                    iam_roles=True,
                )
                self.assertEqual(code, 1)
                self.assertIn("NOT CHECKED:" if operation.startswith("list_") else "FAILED:", text)
                self.assertFalse(any(a["id"] == "app-id" for a in directory.active["applications"]))

    def test_dry_run_lists_and_execute_purges_existing_deleted_items(self):
        directory = Directory(active=False)
        directory.deleted["application"] = [
            {"id": "old-app", "appId": "old-guid", "displayName": "sample-oidc-noscope"},
            {"id": "foreign-app", "appId": "foreign-guid", "displayName": "sample-oidc-extra-app"},
        ]
        directory.deleted["user"] = [
            {"id": "old-user", "userPrincipalName": "sample-oidc-user-a@example.com"},
            {"id": "foreign-user", "userPrincipalName": "sample-oidc-extra-user-a@example.com"},
        ]
        directory.deleted["servicePrincipal"] = [
            {"id": "old-sp", "appId": "old-guid", "displayName": "renamed"},
            {"id": "foreign-sp", "appId": "foreign-guid", "displayName": "sample-oidc-noscope"},
        ]
        code, text, cli, _, _, _ = self.cleanup(["--idp", "entra"], directory=directory)
        self.assertEqual(code, 0)
        for oid in ("old-app", "old-user", "old-sp"):
            self.assertIn(oid, text)
        self.assertFalse(any("DELETE" in c.args[0] for c in cli.call_args_list))
        code, _, _, _, _, _ = self.cleanup(["--execute", "--idp", "entra"], directory=directory)
        self.assertEqual(code, 0)
        self.assertEqual([a["id"] for a in directory.deleted["application"]], ["foreign-app"])
        self.assertEqual([a["id"] for a in directory.deleted["user"]], ["foreign-user"])
        self.assertEqual([a["id"] for a in directory.deleted["servicePrincipal"]], ["foreign-sp"])

    def test_purge_failure_is_reported_and_remaining_objects_are_attempted(self):
        directory = Directory()
        directory.failed_purges.add("sp-id")
        code, text, _, _, _, _ = self.cleanup(["--execute", "--idp", "entra"], directory=directory)
        self.assertEqual(code, 1)
        self.assertIn("FAILED:", text)
        self.assertEqual([obj["id"] for obj in directory.deleted["application"]], ["app-id"])
        self.assertEqual([obj["id"] for obj in directory.deleted["servicePrincipal"]], ["sp-id"])
        directory.failed_purges.clear()
        code, _, _, _, _, _ = self.cleanup(["--execute", "--idp", "entra"], directory=directory)
        self.assertEqual(code, 0)
        self.assertEqual(directory.deleted["application"], [])
        self.assertEqual(directory.deleted["servicePrincipal"], [])

    def test_aws_client_creation_failure_still_runs_entra(self):
        for service in ("bedrock-agentcore-control", "iam", "lambda", "apigatewayv2", "logs", "secretsmanager"):
            with self.subTest(service=service):
                directory = Directory()
                code, text, _, _, _, _ = self.cleanup(
                    ["--execute", "--idp", "entra"],
                    directory=directory,
                    client_failure=service,
                )
                self.assertEqual(code, 1)
                self.assertIn("NOT CHECKED:", text)
                self.assertFalse(any(a["id"] == "app-id" for a in directory.active["applications"]))

    def test_gateway_target_read_error_and_keycloak_read_errors_are_recorded(self):
        failures = [
            ("bedrock-agentcore-control", "list_gateway_targets"),
            ("ec2", "describe_instances"),
            ("ec2", "describe_addresses"),
            ("ec2", "describe_security_groups"),
            ("route53", "list_resource_record_sets"),
        ]
        for failure in failures:
            with self.subTest(failure=failure):
                directory = Directory()
                code, text, _, _, _, _ = self.cleanup(
                    ["--execute", "--idp", "entra", "--idp", "keycloak"],
                    directory=directory,
                    aws_failure=failure,
                    gateways=True,
                )
                self.assertEqual(code, 1)
                self.assertIn("NOT CHECKED:", text)
                self.assertFalse(any(a["id"] == "app-id" for a in directory.active["applications"]))

    def test_duplicate_name_in_deleted_items_stops_before_any_write(self):
        directory = Directory()
        directory.deleted["application"] = [
            {"id": "older-app", "appId": "older-guid", "displayName": "sample-oidc-app"}
        ]
        code, text, cli, api, sm, _ = self.cleanup(["--execute", "--idp", "entra"], directory=directory)
        self.assertEqual(code, 1)
        self.assertIn("NOT CHECKED:", text)
        self.assertFalse(any("DELETE" in c.args[0] for c in cli.call_args_list))
        api.delete_api.assert_not_called()
        sm.delete_secret.assert_not_called()

    def test_skip_flag_keeps_soft_deleted_objects_without_any_az_call(self):
        directory = Directory(active=False)
        directory.deleted["application"] = [{"id": "old", "appId": "old-guid", "displayName": "sample-oidc-noscope"}]
        code, _, cli, _, _, _ = self.cleanup(
            ["--execute", "--idp", "entra", "--skip-entra-objects"], directory=directory
        )
        self.assertEqual(code, 0)
        cli.assert_not_called()
        self.assertEqual(len(directory.deleted["application"]), 1)

    def test_paged_deleted_items_are_checked_and_external_next_links_are_refused(self):
        class PagedDirectory(Directory):
            external = False

            def __call__(self, argv, **kwargs):
                url = argv[argv.index("--url") + 1]
                if "/deletedItems/microsoft.graph.application?" in url and "page=2" not in url:
                    next_link = "https://outside.example.com/" if self.external else url + "&page=2"
                    return SimpleNamespace(
                        returncode=0, stderr="", stdout=json.dumps({"value": [], "@odata.nextLink": next_link})
                    )
                return super().__call__(argv, **kwargs)

        for external in (False, True):
            with self.subTest(external=external):
                directory = PagedDirectory(active=False)
                directory.external = external
                directory.deleted["application"] = [
                    {"id": "old", "appId": "old-guid", "displayName": "sample-oidc-noscope"}
                ]
                code, _, cli, _, _, _ = self.cleanup(["--execute", "--idp", "entra"], directory=directory)
                self.assertEqual(code, 1 if external else 0)
                self.assertFalse(any("https://outside.example.com/" in c.args[0] for c in cli.call_args_list))
                self.assertEqual(len(directory.deleted["application"]), 1 if external else 0)

    def test_repeated_cleanup_never_purges_foreign_sp_after_matching_name_app_is_gone(self):
        directory = Directory(active=False)
        directory.deleted["application"] = [
            {"id": "own-app", "appId": "own-guid", "displayName": "sample-oidc-noscope"}
        ]
        directory.deleted["servicePrincipal"] = [
            {"id": "own-sp", "appId": "own-guid", "displayName": "renamed"},
            {"id": "foreign-sp", "appId": "foreign-guid", "displayName": "sample-oidc-noscope"},
        ]
        for _ in range(2):
            self.cleanup(["--execute", "--idp", "entra"], directory=directory)
            self.assertEqual([obj["id"] for obj in directory.deleted["servicePrincipal"]], ["foreign-sp"])

    def test_orphan_sp_needs_validated_state_app_id_provenance(self):
        for state in (
            None,
            {
                "tenantId": TENANT,
                "prefix": "sample-oidc",
                "noscope": {"appId": "own-guid"},
            },
        ):
            with self.subTest(state=state):
                directory = Directory(active=False)
                directory.deleted["servicePrincipal"] = [
                    {"id": "orphan-sp", "appId": "own-guid", "displayName": "sample-oidc-noscope"},
                    {"id": "foreign-sp", "appId": "foreign-guid", "displayName": "sample-oidc-noscope"},
                ]
                code, text, _, _, _, _ = self.cleanup(
                    ["--execute", "--idp", "entra"], directory=directory, state_data=state
                )
                self.assertEqual(code, 0 if state else 1)
                if not state:
                    self.assertIn("NOT CHECKED:", text)
                self.assertEqual(
                    [obj["id"] for obj in directory.deleted["servicePrincipal"]],
                    ["foreign-sp"] if state else ["orphan-sp", "foreign-sp"],
                )

    def test_process_credential_os_and_json_errors_do_not_abort_entra_cleanup(self):
        for error in (FileNotFoundError("credential executable missing"), json.JSONDecodeError("invalid", "", 0)):
            with self.subTest(error=type(error).__name__):
                directory = Directory()
                code, text, _, _, _, _ = self.cleanup(
                    ["--execute", "--idp", "entra"],
                    directory=directory,
                    client_failure="bedrock-agentcore-control",
                    credential_error=error,
                )
                self.assertEqual(code, 1)
                self.assertIn("NOT CHECKED:", text)
                self.assertFalse(any(obj["id"] == "app-id" for obj in directory.active["applications"]))
                self.assertEqual(directory.deleted["application"], [])

    def test_mismatched_state_cannot_authorize_orphan_purge(self):
        for field, value in (("tenantId", "other-tenant"), ("prefix", "other-prefix")):
            with self.subTest(field=field):
                state = {"tenantId": TENANT, "prefix": "sample-oidc", "noscope": {"appId": "own-guid"}}
                state[field] = value
                directory = Directory(active=False)
                directory.deleted["servicePrincipal"] = [
                    {"id": "orphan", "appId": "own-guid", "displayName": "sample-oidc-noscope"}
                ]
                code, text, cli, api, sm, _ = self.cleanup(
                    ["--execute", "--idp", "entra"], directory=directory, state_data=state
                )
                self.assertEqual(code, 1)
                self.assertIn("NOT CHECKED:", text)
                self.assertFalse(any("DELETE" in call.args[0] for call in cli.call_args_list))
                api.delete_api.assert_not_called()
                sm.delete_secret.assert_not_called()
