"""Synthetic Entra state shared by offline provisioning tests."""

import contextlib
from unittest import mock

from lib import idp

TENANT = "11111111-1111-4111-8111-11111111111a"
RESOURCE = "22222222-2222-4222-8222-22222222222b"
GATEWAY = "33333333-3333-4333-8333-33333333333c"
APP = "44444444-4444-4444-8444-44444444444d"
STATE = {
    "tenantId": TENANT,
    "resource": {"appId": RESOURCE, "audience": f"api://{RESOURCE}"},
    "gateway": {"appId": GATEWAY, "audience": f"api://{GATEWAY}"},
    "app": {"appId": APP},
    "users": {"sample-oidc-user-a": "user-a-oid", "sample-oidc-user-b": "user-b-oid"},
}


def enter_context(test, context):
    stack = contextlib.ExitStack()
    test.addCleanup(stack.close)
    return stack.enter_context(context)


def adapter(test):
    a = idp.load("entra")
    enter_context(test, mock.patch.object(a, "state", return_value=STATE))
    enter_context(
        test,
        mock.patch.object(
            idp,
            "secret",
            return_value={"tenant_id": TENANT, "client_id": GATEWAY, "client_secret": "synthetic-client-secret"},
        ),
    )
    return a
