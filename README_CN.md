# sample-agentcore-oidc-token-exchange

[English](README.md)

演示用户身份经过 Amazon Bedrock AgentCore Gateway 和 AgentCore Identity 的 OIDC token exchange，
再由下游 API 回显。IdP 可选**部署在 Amazon EC2 上的自托管 Keycloak**（默认）
或 **Microsoft Entra ID**（`IDP=entra`）。
下游 JWT 校验由 **Amazon API Gateway HTTP API 原生 JWT authorizer** 执行，
Lambda 函数展示托管 authorizer 已验证的身份 claims。

> **免责声明：本仓库仅为示例，不用于生产。**
> 请使用隔离的测试账号和虚构身份，自行完成适用的安全、性能及可靠性验证。部署会产生 AWS 费用。

## 架构

![架构图](docs/architecture.png)

图展示通过 `IDP` 二选一的 Keycloak 或 Microsoft Entra ID，以及共同的托管边界。
下面的编号示例使用 Keycloak；Entra 的标识符及交换协议差异见后文。

1. 测试用户登录 Keycloak，获得 audience 为 `gateway` 的 T1。
2. 客户端携带 T1 调用 Gateway 的 MCP 工具 `resource___whoami`。
3. Gateway 托管 `CUSTOM_JWT` authorizer 根据配置检查签名、audience 和 `azp=app`。
4. Gateway 向 AgentCore Identity 请求下游 token。
5. Identity 使用 Keycloak 的 `gateway` 机密客户端完成 RFC 8693 token exchange，
   得到 audience 为 `resource-api`、scope 为 `resource.read` 的 T2。
6. Gateway 携带 T2 请求 `GET /v1/me`。
7. API Gateway 原生 JWT authorizer 校验 T2 及路由 scope；
   Lambda 将 `requestContext.authorizer.jwt.claims` 原样序列化返回。

此示例展示 token exchange 后的身份。
符合托管校验条件的身份可以看到自己的 claims；所选 IdP 的 token 签发策略决定哪些身份能获得相应 token。
引入敏感业务数据之前需要单独设计访问控制。

## 前提

- Python 3.10+、AWS CLI v2、具备所需资源创建权限的 AWS 凭证。
- 应用区域支持 AgentCore Gateway/Identity、HTTP API JWT authorizer、Lambda、
  IAM、Secrets Manager 和 CloudWatch Logs。
- Keycloak 专用：Route 53 托管域及未使用的公共 DNS 名；`KC_REGION` 中有默认 VPC、EC2、EBS、Elastic IP 和 SSM。
- Keycloak 专用：独立 realm；setup 添加示例所需配置，管理员负责维护 realm 中的其他用户和客户端。
- Entra 专用：Azure CLI，以及**没有真实用户和数据的专用、可丢弃测试 tenant**。
  使用 tenant 管理员交互式 `az login` 并完成 MFA；保持 Security defaults、Conditional Access 和 MFA 开启。
  测试用户的 password grant（ROPC）不能完成 MFA；若被策略阻止，停止无人值守测试，
  改用隔离的 Keycloak 或另行适配 authorization code + PKCE。不能为了测试关闭安全控制或豁免用户。

Keycloak discovery、JWKS 和 token 端点必须能通过可信公共 HTTPS 被托管服务访问。
管理路径仅允许 `KC_ADMIN_CIDR`。测试使用 password grant；真实用户应用应采用 IdP 支持的
authorization-code/PKCE 流程。

## 部署

```sh
git clone https://github.com/aws-samples/sample-agentcore-oidc-token-exchange.git
cd sample-agentcore-oidc-token-exchange
pip install -r requirements.txt
export KC_HOSTNAME=keycloak.example.com
export KC_HOSTED_ZONE_ID=<your-hosted-zone-id>
export KC_ADMIN_CIDR=<your-admin-public-ip>/32
export KC_REALM=sample
export SAMPLE_REGION=us-west-2
export IDP=keycloak
resource-api/build.sh .build
python idp/keycloak/infra.py
python idp/keycloak/setup.py
python resource-api/deploy.py .build/resource-api.zip
python gateway/provision.py
```

先等待 Keycloak 证书就绪，从允许的管理 CIDR 运行 setup。Lambda ZIP 仅含标准库代码。
API 更新期间禁用默认端点，先配置 authorizer 并保护现有路由，再上传回显函数，
移除 `GET /v1/me` 以外的路由，最后启用端点。失败时端点可能保持禁用，修复后重跑。
脚本不支持自定义域名及手工添加的 stage/integration。

HTTP API 名为 `<prefix>-<idp>-resource-api-jwt`。部署为函数维护专用端点；
如有名为 `<prefix>-<idp>-resource-api` 的 API，会在暂停 Lambda 调用权限期间删除它。
维护过程可能中断服务并改变 URL，部署后必须重跑 `gateway/provision.py` 并更新直接客户端。

| 环境变量 | 默认值 | 作用 |
|---|---|---|
| `IDP` | `keycloak` | `keycloak` 或 `entra` |
| `ENTRA_TENANT_ID` | Entra setup/cleanup 必填 | 可丢弃测试 tenant 的 GUID，必须与 Azure CLI 登录一致 |
| `SAMPLE_PREFIX` | `sample-oidc` | AWS 应用资源前缀 |
| `SAMPLE_REGION` / `SAMPLE_PROFILE` | `us-west-2` / 默认凭证链 | API、Gateway、Identity 的区域与凭证 |
| `SECRETS_REGION` | `us-west-2` | 全球账号中 IdP 源凭证的 Secrets Manager 区域 |
| `SAMPLE_STATE` | `.state` | 非秘密资源 ID；其他部署使用 `.state-<suffix>` |
| `KC_HOSTNAME` / `KC_HOSTED_ZONE_ID` | 必填 | 公共域名与 Route 53 zone |
| `KC_REGION` / `KC_REALM` | `us-west-2` / `sample` | 全球 AWS 区域及独立 realm |
| `KC_INSTANCE_TYPE` / `KC_VERSION` | `t3.medium` / `26.8.1` | 实例创建时生效 |
| `KC_ADMIN_CIDR` | 自动发现的公网 IP `/32` | 创建时设置的管理访问范围 |
| `SAMPLE_GATEWAY_DEBUG` | 未设置 | `1` 返回详细错误，只用于调试 |

issuer、audience、scope 由所选 adapter 的 `resource_api_config()` 提供给托管 API。
Lambda 不保存身份配置；Gateway 入口只允许自身 audience，不接受 resource API 的 audience。
`KC_ADMIN_CIDR`、版本和实例类型不会通过重跑 infra 更新已有实例。

### Microsoft Entra ID

使用包含 `idp/entra/` 的当前 fork checkout；此选项在原 Keycloak 示例上扩展。
无需部署 Keycloak、EC2 或 Route 53。选一个未使用的前缀：3-40 个小写字母、数字或连字符，
首字符为字母。不要复用已有应用、用户名称或其他 tenant 的前缀。

```sh
export IDP=entra
export ENTRA_TENANT_ID='YOUR-DISPOSABLE-TENANT-GUID'
export AWS_PROFILE='YOUR-GLOBAL-AWS-SANDBOX-PROFILE'
export SAMPLE_PROFILE="$AWS_PROFILE"
export SAMPLE_REGION=us-west-2
export SECRETS_REGION=us-west-2
export SAMPLE_PREFIX=oidc-entra-lab
export SAMPLE_STATE="$PWD/.state-entra-lab"

az login --tenant "$ENTRA_TENANT_ID" --allow-no-subscriptions
aws sts get-caller-identity
python idp/entra/setup.py
resource-api/build.sh .build
python resource-api/deploy.py .build/resource-api.zip
python gateway/provision.py
```

Setup 在修改前核对 tenant 及已有客户端凭证，创建四个 single-tenant app registration：
`<prefix>-app`、`<prefix>-gateway`、`<prefix>-resource-api`、`<prefix>-noscope`，对应的 service principal、
delegated admin consent，以及两个 cloud-only 合成测试用户。
不创建组、不授予测试用户目录管理员角色、不修改 tenant 安全策略。
Admin consent 在这个可丢弃 tenant 内对所有用户生效，因此不能在组织生产 tenant 执行。
主客户端对 resource API 只获得 `resource.read` consent；独立的机密客户端 `noscope`
只获得 `resource.other`，供“相同 audience、缺少必需 scope”的拒绝测试使用。
Entra 可能返回同一客户端对资源的全部已同意 scope，而不只是本次请求的 scope，因此两者不能合并授权。

应用使用 `api://<appId>` 标识符。客户端密钥及生成的用户密码仅写入 Secrets Manager，
名称为 `<prefix>/entra/app-client`、`gateway-client`、`noscope-client` 和 `users`，使用 AWS 默认凭证链。
`<SAMPLE_STATE>/entra-state.json` 只保存 ID。客户端密钥有效期 90 天，重跑 setup 会复用，
不会自动续期；已存在的 Identity provider 也保留自己的密钥副本。
再次测试应先清理再使用新前缀，不能假设修改源 secret 就同步完成 provider 轮换。

| 边界 / claim | Keycloak | Entra v2 |
|---|---|---|
| Identity provider | `CustomOauth2`，RFC 8693 | `MicrosoftOauth2`，内置 on-behalf-of（OBO） |
| Gateway outbound grant | `TOKEN_EXCHANGE` | `TOKEN_EXCHANGE`，Identity 内部执行 Microsoft OBO 协议 |
| Gateway T1 `aud` / `azp` | `gateway` / `app` | Gateway app GUID / 客户端 app GUID |
| Resource issuer | realm URL | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| Resource T2 `aud` | `resource-api` | Resource app GUID，**不是** `api://` URI |
| Resource scope | `scope` 中的 `resource.read` | `scp` 中的 `resource.read`；请求时使用 `api://<resource-appId>/resource.read` |
| 测试比较的稳定用户标识 | `sub` | 所配置 tenant 内的 `oid`；`sub` 随 app 不同 |
| T2 `azp` | `gateway` | Gateway app GUID |

Gateway 保留托管的 `azp EQUALS <client-appId>` 检查，不提供关闭认证或 token passthrough 模式。
Discovery、密钥和 token 校验由 API Gateway 执行；Lambda 保持原样回显 claims。
Entra 测试比较已验证的 `oid`，不在应用代码中增加身份校验或业务授权。

### AWS 中国区域

保留通过 `SAMPLE_REGION=cn-north-1` 和对应 `SAMPLE_PROFILE` 构建 `aws-cn` ARN 的路径。
使用单独的 `SAMPLE_STATE`。Keycloak 与 IdP 源凭证仍在全球 AWS 账号，使用默认凭证链，
需要评估跨境 HTTPS 连通性及数据政策。

**HTTP API 原生 JWT authorizer 在 `cn-north-1` 和 `cn-northwest-1` 可用。**
API Gateway 创建 authorizer 时会获取 issuer 的 `/.well-known/openid-configuration`。
Keycloak 的 discovery 端点及其声明的 JWKS URI 必须能被中国区 API Gateway 通过公网和可信 HTTPS 访问。
中国区无法访问 discovery 端点的 issuer，例如不可达的 Google 端点，不能使用；
仅从操作者的机器访问成功并不足够。
服务可用不等于特定 Keycloak 部署或完整 AgentCore token-exchange 链路已经验证通过。
请在目标环境检查链路及区域依赖，再使用这一托管访问控制边界。

Entra adapter 使用全球 Microsoft Entra ID 的 `login.microsoftonline.com` 和 `graph.microsoft.com`，
不是世纪互联运营的云；选择 AWS 中国区域不会改变 Microsoft 端点。
需单独确认托管 AWS 服务到 discovery/token 端点的连通性、Identity vendor 支持及跨境政策。
本次 fork 的 Entra 变更只有离线测试覆盖，不声明任何区域的 live e2e 已通过。

## 使用与检查

本地 HTTPS 测试需要 PATH 中可用的 OpenSSL，用于生成临时测试证书。

```python
import json
from lib import idp, mcp
adapter = idp.load()
with open(idp.state_file(adapter.NAME, f"gateway-{idp.REGION}")) as state:
    gateway = json.load(state)["gatewayUrl"]
status, reply = mcp.tool(gateway, adapter.token("user-a", "gateway"), "resource___whoami", {})
```

响应是 authorizer 提供的 claims，可能包含个人信息，请勿不必要地记录。

```sh
python -m unittest discover -s tests -v
pip install ruff==0.17.1 bandit==1.9.4 pre-commit==4.5.1
ruff check .
ruff format --check .
bandit -c pyproject.toml -r .
```

离线测试检查身份回显和 AWS 配置调用；部署后的检查验证托管服务行为。
pre-commit 还需安装 git-secrets 并注册 AWS 规则。
获得部署测试授权后，可分别运行 `tests/e2e/test_resource_api.py`、
`tests/e2e/test_gateway.py`、`tests/e2e/test_identity_direct.py`。
最后一个脚本会创建测试 workload identity；使用端点前必须通过拒绝访问测试。
三个 live 脚本必须使用同一组 `IDP`、前缀、state 和账号变量。
Entra 的 ROPC 若被策略阻止，应记为测试受阻，不能削弱 MFA。
证据分别写入 `evidence/keycloak/`、`evidence/entra/`；同一 IdP 换部署前先归档旧证据。

## 清理

```sh
python scripts/cleanup.py
python scripts/cleanup.py --execute --idp keycloak
```

`--region R` 可重复；不加 `--idp` 时仅清理环境变量 `IDP`（默认 Keycloak）在所选区域的应用资源。
`--idp` 可重复，应用与 IdP 清理都只针对选中的栈。
`--idp keycloak` 还删除 Keycloak 实例及 realm 数据、EIP、安全组、实例角色和凭证。
DNS 清理需要原来的 `KC_HOSTNAME`、`KC_HOSTED_ZONE_ID` 和 `KC_REGION`。
Secrets Manager 无恢复窗口删除；失败后没有自动回滚。
按精确资源名与项目标签选择，不要复用它们。AWS 列表只读第一页，适用于小型 sandbox。
Gateway 管理的 workload identity 和 provider secret 预计由所属服务清理，
必须通过最终 dry run 和服务资源清单确认。其他日志和手工添加的资源不在清理范围。
AWS 读取失败记录为 `NOT CHECKED`，删除失败记录为 `FAILED`，然后继续其他独立资源，
包括 AWS 失败后的 Entra 清理；存在任意失败则最终非零退出，dry run 的读取失败也一样。

Entra 保持原部署环境变量和 tenant 管理员登录：

```sh
python scripts/cleanup.py --idp entra
python scripts/cleanup.py --execute --idp entra
python scripts/cleanup.py --idp entra
```

先审阅 dry run，执行后再次 dry run，必须不再列出残留。
脚本在 AWS 删除前核对 `ENTRA_TENANT_ID`，按 tenant 内唯一的精确 app display name 及完整测试用户 UPN 查找，
不是宽泛的前缀匹配；active/deleted 对象重名则在任何删除前停止，并在计划中展示 object ID。
Graph 列表会遍历所有页。Setup 到 cleanup 期间应保持 tenant 默认域名不变。
Azure CLI 缺失、未登录、tenant 错误或 Entra 列表不完整时，在任何删除前输出 `NOT CHECKED` 并非零退出。
`--skip-entra-objects` 不调用 `az`，只保留 Entra apps/users；**仍会删除**所选 AWS 资源和源 secret，
不能据此声称 tenant 已清理。Dry run 也会列出 `directory/deletedItems` 中属于样例的对象。
执行模式会按 object ID 永久清除样例 applications、users 及级联删除的 service principals；
SP 通过所选应用的 `appId` 关联，支持已重命名的 SP。历史孤立 deleted SP 必须通过原
`entra-state.json` 中的 `appId` 确认归属，且 state 的 tenant/prefix 必须匹配，不能只按名字 purge。
清理完成前保留 `SAMPLE_STATE`；无法确认归属的同前缀孤立 SP 保留并报告 `NOT CHECKED`。
若 SP purge 失败，会保留应用的软删除记录，以便下次仍通过 `appId` 重试。
目录传播延迟或 purge 权限错误仍视为失败，必须重跑并检查最终 dry run。永久清除不可恢复。
脚本不删除 tenant；不再需要时手工删除测试 tenant，并核对安全策略保持情况。
AWS 资源标签为 `project=<SAMPLE_PREFIX>`，名称也带 IdP，因此 `--idp entra` 不选择 Keycloak 资源。

## 安全、费用和许可证

见 [SECURITY.md](SECURITY.md)：直接 Lambda 调用、token 缓存、公共端点及凭证的风险。
托管 authorizer 和 IAM 权限共同构成示例的访问控制边界。
按量服务、持续运行的 EC2、EBS 和公共 IPv4 均会产生费用，见 [AWS Pricing](https://aws.amazon.com/pricing/)。
采用 [MIT-0](LICENSE)，第三方软件见 [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES)。
