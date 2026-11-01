"""Exercise gateway provisioning with local state and mocked AWS clients."""

import contextlib
import io
import json
import pathlib
import runpy
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from entra_fixtures import APP, GATEWAY, RESOURCE, TENANT
from entra_fixtures import adapter as entra_adapter

from lib import idp

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "gateway" / "provision.py"
ACCOUNT = "123456" + "789012"


class MissingRoleError(Exception):
    """The fake IAM client's missing-role response."""


class GatewayPermissionsTest(unittest.TestCase):
    def provision(self, partition, region, name, existing, selected=None):
        gateway = f"sample-oidc-{name}-gw"
        base = f"arn:{partition}:bedrock-agentcore:{region}:{ACCOUNT}"
        provider = f"{base}:token-vault/default/oauth2credentialprovider/sample-oidc-{name}"
        secret = f"arn:{partition}:secretsmanager:{region}:{ACCOUNT}:secret:bedrock-agentcore-identity!sample-abcdef"
        role = f"arn:{partition}:iam::{ACCOUNT}:role/sample-oidc-{name}-gateway-role"
        provider_response = {
            "name": f"sample-oidc-{name}",
            "credentialProviderArn": provider,
            "clientSecretArn": {"secretArn": secret},
        }
        ctl = mock.Mock()
        ctl.list_oauth2_credential_providers.return_value = {
            "credentialProviders": [provider_response] if existing else []
        }
        ctl.create_oauth2_credential_provider.return_value = provider_response
        ctl.get_oauth2_credential_provider.return_value = provider_response
        ctl.list_gateways.return_value = {"items": []}
        ctl.create_gateway.return_value = {"gatewayId": f"{gateway}-abc123"}
        ctl.get_gateway.return_value = {"status": "READY", "gatewayUrl": "https://gateway.example.com"}
        ctl.list_gateway_targets.return_value = {"items": []}
        ctl.create_gateway_target.return_value = {"targetId": "resource"}
        ctl.get_gateway_target.return_value = {"status": "READY"}
        iam = mock.Mock()
        iam.exceptions.NoSuchEntityException = MissingRoleError
        if existing:
            iam.get_role.return_value = {"Role": {"Arn": role}}
        else:
            iam.get_role.side_effect = MissingRoleError
        iam.create_role.return_value = {"Role": {"Arn": role}}
        sts = mock.Mock()
        sts.get_caller_identity.return_value = {"Account": ACCOUNT}
        session = mock.Mock()
        session.client.side_effect = {
            "bedrock-agentcore-control": ctl,
            "iam": iam,
            "sts": sts,
        }.__getitem__
        adapter = SimpleNamespace(
            NAME=name,
            PROVIDER=f"sample-oidc-{name}",
            provider_input=lambda: ("CustomOauth2", {}),
            door=lambda: {
                "discovery_url": "https://idp.example.com/.well-known/openid-configuration",
                "audiences": ["gateway"],
                "client_claim": "azp",
                "client_value": "app",
            },
            exchange_params=lambda: {"scopes": ["resource"], "custom": {}},
        )
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            state = pathlib.Path(directory)
            (state / f"{name}-resource-api.json").write_text('{"url": "https://api.example.com"}')
            stack.enter_context(
                mock.patch.multiple(idp, STATE=state, PREFIX="sample-oidc", PARTITION=partition, REGION=region)
            )
            stack.enter_context(mock.patch.object(idp, "load", return_value=selected or adapter))
            stack.enter_context(mock.patch.object(idp, "session", return_value=session))
            stack.enter_context(mock.patch.object(sys, "argv", [str(SCRIPT)]))
            stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            runpy.run_path(str(SCRIPT), run_name="__main__")
        return iam, ctl, gateway, base, secret

    def test_new_and_existing_roles_have_scoped_trust_and_exact_secret(self):
        for partition, region in (("aws", "us-west-2"), ("aws-cn", "cn-north-1")):
            for name in ("keycloak", "entra"):
                for existing in (False, True):
                    with self.subTest(partition=partition, idp=name, existing=existing):
                        iam, ctl, gateway, base, secret = self.provision(partition, region, name, existing)
                        if existing:
                            iam.update_assume_role_policy.assert_called_once()
                            trust_json = iam.update_assume_role_policy.call_args.kwargs["PolicyDocument"]
                        else:
                            trust_json = iam.create_role.call_args.kwargs["AssumeRolePolicyDocument"]
                        condition = json.loads(trust_json)["Statement"][0]["Condition"]
                        self.assertEqual(condition["StringEquals"], {"aws:SourceAccount": ACCOUNT})
                        self.assertEqual(condition.get("ArnLike"), {"aws:SourceArn": f"{base}:gateway/{gateway}-*"})
                        policy = json.loads(iam.put_role_policy.call_args.kwargs["PolicyDocument"])
                        grants = [
                            item for item in policy["Statement"] if item["Action"] == "secretsmanager:GetSecretValue"
                        ]
                        self.assertEqual(
                            grants,
                            [
                                {
                                    "Effect": "Allow",
                                    "Action": "secretsmanager:GetSecretValue",
                                    "Resource": secret,
                                }
                            ],
                        )
                        if existing:
                            ctl.get_oauth2_credential_provider.assert_called_once_with(name=f"sample-oidc-{name}")

    def test_entra_wires_microsoft_provider_and_token_exchange_without_custom_parameters(self):
        selected = entra_adapter(self)
        _, ctl, _, _, _ = self.provision("aws", "us-west-2", "entra", False, selected=selected)
        provider = ctl.create_oauth2_credential_provider.call_args.kwargs
        self.assertEqual(provider["credentialProviderVendor"], "MicrosoftOauth2")
        self.assertEqual(provider["oauth2ProviderConfigInput"]["microsoftOauth2ProviderConfig"]["tenantId"], TENANT)
        self.assertEqual(provider["oauth2ProviderConfigInput"]["microsoftOauth2ProviderConfig"]["clientId"], GATEWAY)
        gate = ctl.create_gateway.call_args.kwargs["authorizerConfiguration"]["customJWTAuthorizer"]
        self.assertEqual(gate["allowedAudience"], [GATEWAY])
        self.assertEqual(
            gate["customClaims"][0]["authorizingClaimMatchValue"]["claimMatchValue"]["matchValueString"], APP
        )
        target = ctl.create_gateway_target.call_args.kwargs
        oauth = target["credentialProviderConfigurations"][0]["credentialProvider"]["oauthCredentialProvider"]
        self.assertEqual(oauth["grantType"], "TOKEN_EXCHANGE")
        self.assertEqual(oauth["scopes"], [f"api://{RESOURCE}/resource.read"])
        self.assertNotIn("customParameters", oauth)
        self.assertEqual(
            list(json.loads(target["targetConfiguration"]["mcp"]["openApiSchema"]["inlinePayload"])["paths"]),
            ["/v1/me"],
        )


if __name__ == "__main__":
    unittest.main()
