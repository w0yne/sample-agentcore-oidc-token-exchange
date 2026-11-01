#!/usr/bin/env python3
"""Deploy an identity echo Lambda behind an API Gateway HTTP API JWT authorizer.

Only GET /v1/me is exposed. AWS validates issuer, audience and the route scope.
The dedicated -jwt API is disabled during updates. An API using the function's base
name is deleted while Lambda invocation permission is suspended. Maintenance can
change the URL; rerun gateway/provision.py after deployment.
Usage: python resource-api/deploy.py <resource-api.zip>
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from lib import idp, wait

A = idp.load()
sess = idp.session()
NAME, TAGS = f"{idp.PREFIX}-{A.NAME}-resource-api", {"project": idp.PREFIX}
API_NAME = f"{NAME}-jwt"
iam, lam, api, sts = sess.client("iam"), sess.client("lambda"), sess.client("apigatewayv2"), sess.client("sts")
acct = sts.get_caller_identity()["Account"]
zipfile = pathlib.Path(sys.argv[1]).read_bytes()
settings = A.resource_api_config()

apis = api.get_apis()["Items"]
base_api = next((x for x in apis if x["Name"] == NAME), None)
found = next((x for x in apis if x["Name"] == API_NAME), None)
if found:
    api.update_api(ApiId=found["ApiId"], DisableExecuteApiEndpoint=True)
else:
    found = api.create_api(Name=API_NAME, ProtocolType="HTTP", DisableExecuteApiEndpoint=True, Tags=TAGS)
api_id = found["ApiId"]
authorizer_args = {
    "ApiId": api_id,
    "Name": f"{A.NAME}-jwt",
    "AuthorizerType": "JWT",
    "IdentitySource": ["$request.header.Authorization"],
    "JwtConfiguration": {"Issuer": settings["issuer"], "Audience": settings["audiences"]},
}
existing_auth = next((a for a in api.get_authorizers(ApiId=api_id)["Items"] if a["Name"] == f"{A.NAME}-jwt"), None)
if existing_auth:
    authorizer_id = existing_auth["AuthorizerId"]
    api.update_authorizer(AuthorizerId=authorizer_id, **authorizer_args)
else:
    authorizer_id = api.create_authorizer(**authorizer_args)["AuthorizerId"]
gate = {"AuthorizationType": "JWT", "AuthorizerId": authorizer_id, "AuthorizationScopes": [settings["required_scope"]]}
routes = api.get_routes(ApiId=api_id)["Items"]
for route in routes:
    api.update_route(ApiId=api_id, RouteId=route["RouteId"], **gate)

# Suspend API invocation while synchronizing the function and its dedicated endpoint.
try:
    lam.remove_permission(FunctionName=NAME, StatementId="http-api")
except lam.exceptions.ResourceNotFoundException:
    pass
if base_api:
    api.delete_api(ApiId=base_api["ApiId"])

try:
    role = iam.get_role(RoleName=NAME)["Role"]["Arn"]
except iam.exceptions.NoSuchEntityException:
    role = iam.create_role(
        RoleName=NAME,
        Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
    )["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=NAME, PolicyArn=f"arn:{idp.PARTITION}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    iam.get_waiter("role_exists").wait(RoleName=NAME)
cfg = dict(
    FunctionName=NAME,
    Runtime="python3.12",
    Role=role,
    Handler="handler.handler",
    Timeout=15,
    MemorySize=256,
    Environment={"Variables": {}},
)
try:
    lam.get_function(FunctionName=NAME)
    lam.update_function_code(FunctionName=NAME, ZipFile=zipfile)
    lam.get_waiter("function_updated").wait(FunctionName=NAME)
    lam.update_function_configuration(**cfg)
except lam.exceptions.ResourceNotFoundException:
    wait.retry(
        lambda: lam.create_function(Code={"ZipFile": zipfile}, Tags=TAGS, **cfg),
        lambda e: isinstance(e, lam.exceptions.InvalidParameterValueException) and "cannot be assumed" in str(e),
        "the new IAM role to become usable by Lambda",
    )
lam.get_waiter("function_active_v2").wait(FunctionName=NAME)
lam.get_waiter("function_updated_v2").wait(FunctionName=NAME)
fn_arn = lam.get_function(FunctionName=NAME)["Configuration"]["FunctionArn"]
integration_args = dict(
    ApiId=api_id,
    IntegrationType="AWS_PROXY",
    IntegrationUri=fn_arn,
    PayloadFormatVersion="2.0",
    IntegrationMethod="POST",
)
existing_integration = next(
    (i for i in api.get_integrations(ApiId=api_id)["Items"] if i.get("IntegrationUri") == fn_arn), None
)
if existing_integration:
    integration = existing_integration["IntegrationId"]
    api.update_integration(IntegrationId=integration, **integration_args)
else:
    integration = api.create_integration(**integration_args)["IntegrationId"]
target = {"Target": f"integrations/{integration}", **gate}
me = next((r for r in routes if r["RouteKey"] == "GET /v1/me"), None)
if me:
    api.update_route(ApiId=api_id, RouteId=me["RouteId"], **target)
else:
    api.create_route(ApiId=api_id, RouteKey="GET /v1/me", **target)
for route in routes:
    if route["RouteKey"] != "GET /v1/me":
        api.delete_route(ApiId=api_id, RouteId=route["RouteId"])
lam.add_permission(
    FunctionName=NAME,
    StatementId="http-api",
    Action="lambda:InvokeFunction",
    Principal="apigateway.amazonaws.com",
    SourceAccount=acct,
    SourceArn=f"arn:{idp.PARTITION}:execute-api:{idp.REGION}:{acct}:{api_id}/*/GET/v1/me",
)
if any(s["StageName"] == "$default" for s in api.get_stages(ApiId=api_id)["Items"]):
    api.update_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
else:
    api.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
api.update_api(ApiId=api_id, DisableExecuteApiEndpoint=False)
with open(idp.state_file(A.NAME, "resource-api"), "w", encoding="utf-8") as state:
    json.dump({"url": found["ApiEndpoint"], "apiId": api_id}, state)
print(found["ApiEndpoint"])
