# Security

Report suspected vulnerabilities using the
[AWS security reporting page](https://aws.amazon.com/security/vulnerability-reporting/),
not a public issue. This is a non-production identity-echo sample.

## Managed Identity Boundary

- AgentCore Gateway uses its managed inbound JWT configuration for T1.
- API Gateway uses its native JWT authorizer for T2: issuer and audience are configured
  on the authorizer, and `resource.read` is required on the `GET /v1/me` route.
- Lambda returns the claims supplied in the API Gateway authorizer context, without logging.
- The function requires the managed authorizer event shape; missing context causes a function error.
- The Lambda resource permission names API Gateway, the source account and this API's GET route.
  Same-account IAM principals with direct `lambda:InvokeFunction` can fabricate an event,
  including its authorizer context. Restrict that permission and function-configuration access.
  A direct invocation is not an authenticated end-user request.
- Control qualifying token issuance at the selected IdP. The identity response may include personal claims
  and must be handled as sensitive data.
- Tokens and cached exchange results can remain usable until expiry. Do not interpret a successful
  call as a fresh account-status or membership check.

## Deployment and Network

The default API endpoint is public HTTPS, protected by managed JWT authorization.
Deployment disables it during updates and gates existing routes before uploading echo code.
Deployment maintains the dedicated `-jwt` endpoint. An API using the function's base
name is deleted while invocation permission is suspended. This maintenance may change
the endpoint URL and interrupt service until clients and the Gateway target are updated.
Only the dedicated sample API and default stage are supported; do not add custom domains
or other invocation paths. Configuration propagation and denial behavior need live verification.
Never point a public unprotected integration directly at this function.

Keycloak is self-hosted on AWS, not a hosted identity service. Its public discovery/JWKS
endpoints are required by managed authorizers. Caddy publishes 443 and port 80 for certificate
issuance/HTTPS redirection; Keycloak and PostgreSQL have no published container ports.
Admin, master-realm, metrics and health paths are CIDR-restricted. Limit the admin CIDR to trusted hosts.
EC2 requires IMDSv2, uses encrypted EBS, and has no SSH ingress; use Systems Manager.
Patching, image integrity, public certificate issuance and availability remain customer responsibilities.

## Secrets and Permissions

Generated test-user and admin passwords and Keycloak client secrets are stored in Secrets Manager.
Identity maintains its own copy of the exchange client's secret. Local state files contain IDs,
not credentials. The instance stores admin/database passwords in a root-only mode-600 file;
container environments and the database command line still expose them to privileged host users.
Rotate credentials deliberately; updating a source secret does not automatically refresh an
existing Identity credential provider or a running container.

The Gateway role trusts the AgentCore service only with matching SourceAccount and a
prefixed Gateway SourceArn. Its API grants are scoped to the workload directory, prefixed
workload identities, token vault and provider; secret read permission names the provider's exact secret.
The host role reads only its admin secret and uses the AWS-managed Systems Manager policy.
The Lambda role uses the AWS-managed basic logging policy.
Review effective IAM/SCPs, role passing and existing roles separately.

HTTP helpers require HTTPS and reject redirects; AWS SDK calls use their own transport.
Test sign-in uses password grants only for disposable synthetic users. Real clients should
use the IdP's supported authorization-code/PKCE flow. Leave detailed Gateway errors disabled.
Use a dedicated realm and explicitly maintain its configuration alongside the setup script.

For Entra, use only a dedicated disposable tenant and an MFA-authenticated tenant-admin
Azure CLI login. Keep tenant security controls enabled; if they block password grants,
stop the unattended tests rather than weaken policy. Setup grants delegated consent
tenant-wide for the sample apps; it creates no user directory roles or group-based access
rules. Client secrets expire after 90 days and are not automatically rotated.
Graph setup sends sensitive request bodies through mode-600 temporary files, removed
after the CLI call; it does not print CLI diagnostics or credentials. Cleanup checks the
explicit tenant and exact names. Never reuse another deployment's prefix or object names.

## Region and Assurance Limits

HTTP API JWT authorizers are available in cn-north-1 and cn-northwest-1.
Authorizer creation fetches issuer discovery; the discovery endpoint and advertised
JWKS URI must be publicly reachable from the Region's API Gateway over trusted HTTPS.
Feature availability does not prove a particular issuer or the complete exchange path works.
Managed service configuration provides the JWT access gate. Confirm connectivity before use.
Offline unit tests and policy validation do not establish deployment success or production security.
Third-party software is listed in [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES).
