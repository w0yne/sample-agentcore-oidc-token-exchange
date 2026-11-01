"""Test live-check script contracts offline with pairwise sub and stable oid."""

import contextlib
import io
import json
import pathlib
import runpy
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

from entra_fixtures import GATEWAY, RESOURCE, adapter, enter_context

from lib import idp, mcp, net

ROOT = pathlib.Path(__file__).resolve().parents[1]


def claims(user):
    return {"oid": f"{user}-oid", "sub": f"pairwise-{user}", "azp": GATEWAY, "aud": RESOURCE, "scp": "resource.read"}


class EntraLiveScriptTest(unittest.TestCase):
    def setUp(self):
        self.a = adapter(self)
        self.a.token = lambda user, resource: f"{user}:{resource}"
        self.a.id_token = lambda user: "id-token"
        self.a.token_without_resource_scope = lambda user: "no-scope"
        self.a.other_resource_token = lambda user: "other-resource"
        self.a.other_client_token = lambda user: "other-client"
        enter_context(self, mock.patch.object(idp, "load", return_value=self.a))
        directory = pathlib.Path(enter_context(self, tempfile.TemporaryDirectory()))
        enter_context(self, mock.patch.multiple(idp, STATE=directory, PREFIX="sample-oidc", REGION="us-west-2"))
        enter_context(self, mock.patch.object(idp, "evidence_path", side_effect=lambda name: directory / name))
        (directory / "entra-resource-api.json").write_text('{"url":"https://api.example.com"}')
        (directory / "entra-gateway-us-west-2.json").write_text('{"gatewayUrl":"https://gateway.example.com"}')

        def open_https(request, **kwargs):
            token = request.headers.get("Authorization", "").removeprefix("Bearer ")
            if not token.endswith(":resource"):
                raise urllib.error.HTTPError(request.full_url, 403, "denied", {}, None)
            body = io.BytesIO(json.dumps(claims(token.split(":")[0])).encode())
            body.status = 200
            return body

        enter_context(self, mock.patch.object(net, "open_https", side_effect=open_https))
        self.output = enter_context(self, contextlib.redirect_stdout(io.StringIO()))

    def run_script(self, name):
        with mock.patch.object(sys, "path", list(sys.path)), self.assertRaises(SystemExit) as stopped:
            runpy.run_path(str(ROOT / "tests/e2e" / name), run_name="__main__")
        self.assertEqual(stopped.exception.code, 0, self.output.getvalue())

    def test_resource_check_uses_oid_not_pairwise_sub(self):
        self.run_script("test_resource_api.py")

    def test_gateway_check_uses_oid_and_gateway_app_guid(self):
        def tool(url, token, name, args):
            if token and token.endswith(":gateway"):
                return 200, {"result": {"content": [{"type": "text", "text": json.dumps(claims(token.split(":")[0]))}]}}
            return 403, {}

        with mock.patch.object(mcp, "tool", side_effect=tool):
            self.run_script("test_gateway.py")

    def test_identity_check_uses_idp_specific_workload_and_claims(self):
        ctl, dp, session = mock.Mock(), mock.Mock(), mock.Mock()
        ctl.list_workload_identities.return_value = {"workloadIdentities": []}
        dp.get_workload_access_token_for_jwt.side_effect = lambda **kw: {
            "workloadAccessToken": kw["userToken"].split(":")[0]
        }
        dp.get_resource_oauth2_token.side_effect = lambda **kw: {
            "accessToken": kw["workloadIdentityToken"] + ":resource"
        }
        session.client.side_effect = {"bedrock-agentcore-control": ctl, "bedrock-agentcore": dp}.__getitem__
        with mock.patch.object(idp, "session", return_value=session):
            self.run_script("test_identity_direct.py")
        self.assertEqual(ctl.create_workload_identity.call_args.kwargs["name"], "sample-oidc-entra-workload")
        self.assertEqual(dp.get_resource_oauth2_token.call_args.kwargs["oauth2Flow"], "ON_BEHALF_OF_TOKEN_EXCHANGE")
