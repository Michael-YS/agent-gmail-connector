# 未完成测试与测试方法

本文件只记录当前还没有通过的测试与外部验收。已通过的本地结果：194 项 library（含邀请与账号管理、Connection revoke/恢复、Access Key、持久化限流、发送额度返还、机器端及控制面/OAuth 无内容审计、并发撤销压力测试和保留期清理、Gmail thread/attachment/draft read、reply-all、HTTP multipart 与 MCP base64 草稿附件、持久化 REST/MCP 创建幂等性、MCP JSON-RPC 错误审计分类、rmcp Streamable HTTP 草稿幂等性、内容协商、Host rebinding 及无状态协议负向测试、Gmail 401/invalid_grant → `reauth_required` 持久化与 REST/MCP 独立错误码、JSON reauthorize 入口、Gmail 读取 429/5xx 有界重试）、4 项 HTTP 安全与 managed-draft 契约测试、21 项 REST/MCP 契约测试，共 219 项；并已运行 `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --all-targets --all-features --locked`。未执行部署、真实 Google 或浏览器 smoke。

## A. 尚未实现，因此目前无法执行的测试

### A1. Google OIDC 登录与邀请制 control plane

- 已实现：真实 RS256/JWKS verifier、flow-scoped 单次 callback、Owner/Member session、邀请 API/HTML、Member Connection/Access Key HTML、账号自删与 Owner revoke、JSON reauthorize 入口（`POST /control/api/connections/{id}/reauthorize`）。管理 JSON API 使用 `/control/api/...`，HTML 使用 `/control/...`。剩余外部缺口：真实 Google 浏览器登录、连接/重新授权和账号撤销 smoke。
- 实现后测试：用 fake OIDC server 覆盖成功、错误 state/nonce、错误 issuer/audience、过期 token、未验证 email、邀请 email 不一致、邀请重放、session idle/absolute expiry 和 CSRF；再用 Dev Project 浏览器登录。
- 命令目标：`cargo test --test oidc_contract --all-features`。
- 通过标准：所有失败在创建用户/session 前被拒绝；数据库和日志不出现 authorization code、state、nonce、access token 或 ID token。

### A2. Gmail OAuth Connection 与真实 Google adapter

- 已实现：offline consent、完整 scope 校验、Connection callback、加密 refresh token、single-flight access-token cache、`invalid_grant` reauth、production Gmail adapter、Connection revoke JSON/HTML 与 Google token revoke。Member 账号和独立 Connection 撤销都会在启动时恢复中断状态。Gmail 401/refresh `invalid_grant` 现在都会持久化 `reauth_required` 并以独立错误码暴露（REST 403 `reauth_required`、JSON-RPC -32005、rmcp 透传类别），JSON reauthorize 入口已接入。剩余缺口：真实 Gmail smoke（入口脚本 `scripts/smoke-gmail.sh` 已存在，见 B6）。
- 实现后测试：fake Google server 覆盖部分授权、refresh、invalid_grant、429/5xx/Retry-After、timeout、revoke；Dev 账号完成连接、搜索、读取、线程和附件流。
- 命令目标：`cargo test --test gmail_adapter --all-features`，以及人工 `scripts/smoke-gmail.sh --prepare-only`。
- 通过标准：缺少 `gmail.readonly` 或 `gmail.compose` 不创建 Connection；refresh token 仅以 XChaCha20-Poly1305 envelope 入库；查询和邮件内容不进日志。

### A3. 数据库 repository 与 control plane CRUD

- 已实现：SQLite repository 已覆盖 users/invitations/sessions/connections/access keys/grants/managed drafts/audit/首次授权 ledger；Owner/Member 各自的 Access Key 与 Connection 管理使用 session+CSRF，Member 自删与 Owner revoke 原子失效本地权限，启动恢复中断撤销。剩余缺口转入真实浏览器/Google 外部验收。
- 实现后测试：临时 SQLite 覆盖 Owner/Member、邀请、Connection、key create/rotate/revoke、grant 变更、账号删除与跨重启恢复。
- 命令目标：`cargo test --test repository_roundtrip --all-features`。
- 通过标准：重启后状态不丢失；key/confirmation/session 只存 hash；唯一 Owner、唯一 Gmail sub 与 first-authorization ledger 约束生效。

### A4. MIME、附件与完整 managed draft

- 已实现：mail-builder MIME、稳定 Message-ID、reply References、reply-all 排除当前主地址、非 ASCII header 编码、header/filename/content-type 注入防护、原始附件与最终编码消息的 25 MiB 双重限制、Gmail draft create/update/delete/send、hash-only confirmation、原子 outcome 持久化、重启恢复和 Sent Message-ID 对账，以及 REST new/reply/reply-all/forward、同 Connection 源附件转发/下载、HTTP multipart 上传、MCP `drafts.create` 的 4 MiB base64 小附件和持久化 HTTP create idempotency。
- 实现后测试：非 ASCII headers、header injection、reply references、reply-all 排除当前地址、forward 内嵌图、恶意文件名、MCP 4 MiB、HTTP 25 MiB、超限和响应丢失。
- 命令目标：`cargo test --test mime_and_drafts --all-features`。
- 通过标准：非 managed draft 只能读取；版本变化返回 `409 draft_changed`；超时不自动重发，无法对账进入 `send_state_unknown`。

### A5. MCP Streamable HTTP 与 rmcp schema

- OpenAPI 已覆盖全部现有 REST 路由、参数、JSON/multipart 请求体、二进制附件响应、统一错误响应和 bearer 安全；OpenAPI 与 MCP tools schema 均有稳定 SHA-256 snapshot 契约。兼容 JSON-RPC 已迁移到 `/mcp-compat` 并实现当前全部草稿读写工具；计划约定的 `/mcp` 已接入官方 rmcp 无状态 Streamable HTTP，`/mcp-streamable` 为临时别名，并暴露同一工具 schema，当前所有工具通过受控兼容 bridge，草稿创建按 JSON-RPC 调用生成稳定的持久化幂等键。审计包装已覆盖已知 `tools/call` 操作且不读取邮件内容；内容协商、Host rebinding、未知协议版本、stateless session 边界和 rmcp 授权错误分类已有负向契约。原生 handler 迁移不是 v1 硬要求；剩余是运行真实 MCP client。
- 实现后测试：导出 OpenAPI/MCP schema，运行 snapshot 与真实 MCP client；比较 HTTP/MCP 的领域字段和错误码。
- 命令目标：`cargo test --test transport_contract --all-features`，`cargo test --test mcp_schema --all-features`。
- 通过标准：tools 标明邮件内容不可信和发送需用户许可；MCP 与 REST 共享认证、grant、状态机和审计逻辑。

### A6. 限流、审计、账号撤销与清理

- 已实现：4 路读取并发、20 收件人限制、跨重启 SQLite 固定窗口、REST/MCP 120/key/min、30 prepare/key/hour、10 send/Connection/hour、50 send/Connection/day、原子小时/日预占、重放/无效/明确失败返还、unknown 保留占用、429 header/body retry 秒数、机器端及 control-plane mutation/OAuth transition 无内容审计，以及可配置保留期的启动/每小时清理。
- 本地实现与并发撤销压力测试已完成；剩余外部中断/Google 验收见 B0 与 B6。
- 命令目标：`cargo test --test security_flows --all-features`。
- 通过标准：429 含 retry seconds；日志/审计不包含地址、主题、正文、snippet、附件名、查询或任何 token。

## B. 代码已具备，但当前机器未完成的测试

### B0. Connection 撤销的外部与中断验收

- 本地已验证：Google 200/4xx/429/5xx/timeout 分类、错误正文有界、Owner/Member 同用户 session+CSRF、撤销前失效、grants/confirmation/OAuth transaction 清理、历史授权计数保留、损坏凭证仍清理、refresh 进行中撤销拒绝返回 token。
- 待验证：真实垃圾邮箱 token revoke；HTTP 客户端断开后清理完成；进程在本地失效后终止，重启扫描自动完成清理。
- Google 失败时 `local_revoked=true` 不代表 Google 已确认撤销；`remote_revocation=unconfirmed` 需要用户在 Google 账号授权页检查。已经发出的上游请求不能追溯取消。

### B1. cargo-audit 与 cargo-deny

- 前置条件：安装 `cargo-audit 0.22.2`、`cargo-deny 0.20.2` 并允许访问 advisory/index。
- 命令：先运行 `cargo tree --locked --target all --all-features -i rsa`，确认 SQLite-only 构建不解析 rsa；再运行 `cargo audit --ignore RUSTSEC-2023-0071`; `cargo deny check`（`cargo audit` 不提供 `--locked` 选项；构建检查仍使用 `--locked`）。
- 期望：无未处理 advisory、许可证或来源违规。
- 当前结果：已将 `jsonwebtoken 11` 的密码学后端切到 `aws_lc_rs`，运行时依赖图不再包含 rsa；Cargo.lock 仍记录 sqlx-mysql 的未启用可选依赖，因此 CI/release 对 `RUSTSEC-2023-0071` 使用带原因的窄例外，并用 `cargo tree` 守卫确保 rsa 不可达。`cargo-audit 0.22.2 --ignore RUSTSEC-2023-0071` 通过；`cargo-deny 0.20.2` 的 advisory/license/source 检查通过，保留 duplicate-version warnings。该例外必须在启用 MySQL 或更换 JWT 后端时重新审查。

### B2. Docker/Compose 与容器安全

- 前置条件：amd64 Docker Engine、Compose v2、`.env` 和四个 0400 secret 文件。
- 命令：`docker compose --env-file .env -f compose.yaml config --quiet`; `docker build --platform linux/amd64 -t agentmail:test .`; `docker run --rm --entrypoint /usr/bin/id agentmail:test --user`。
- 期望：构建成功、架构 amd64、UID/GID 10001；只监听 `127.0.0.1:18080`，rootfs 只读、无 capabilities、no-new-privileges。
- 当前原因：本机没有 Docker 可执行文件。

### B3. 备份与迁移脚本

- 前置条件：Linux、Docker/Compose、`flock`、可恢复测试数据。
- 成功路径：`bash -n scripts/backup.sh scripts/migrate.sh`; `./scripts/backup.sh`; `./scripts/migrate.sh`。
- 失败路径：加入一条受控失败迁移或使用损坏测试镜像后执行 migrate。
- 并发路径：并行运行两次 backup，再并行运行两次 migrate。
- 期望：在线 backup 是可打开的 SQLite DB；迁移先备份，成功恢复 ready；失败保持主服务 stopped；每组仅一个进程拿到锁；不删除 volume/旧备份。
- 当前结果：`bash -n` 已通过；真实 Docker 路径未运行。

### B4. Nginx/TLS 公网入口

- 前置条件：VPS、DNS、有效证书、Nginx 和只在 loopback 运行的容器。
- 命令：`nginx -t`; reload；从外网分别访问 `/`、`/api`、`/mcp`、`/health/live`、`/health/ready`。
- 期望：HTTP 固定跳转 canonical HTTPS；证书主机名正确；MCP buffering 关闭；不能绕过 Nginx 直连 Docker port。

### B5. GHCR release 供应链

- 前置条件：GitHub Actions/GHCR 权限和版本 tag。
- 方法：发布 `vX.Y.Z`，核对 `X.Y.Z`、`X.Y`、`latest`、commit SHA 标签；下载 SBOM，验证 provenance/attestation 和 keyless signature；在干净 amd64 主机按 digest 拉取。
- 期望：产物与 commit/digest 一致，镜像不含 `.env`、OAuth secret、keyring 或测试凭据。
- 当前结果：已新增 tag-triggered GHCR workflow（先执行 locked fmt/check/clippy/test、cargo-audit/deny 和 amd64 镜像漏洞扫描，再进行固定 action SHA 的构建、SPDX SBOM、provenance/SBOM attestations、cosign keyless sign/verify）；尚未在真实 GitHub tag 上执行，因此下载产物、签名身份和干净主机 digest 拉取仍待外部验收。

### B6. Google Dev/Prod 与真实 Gmail smoke

- 前置条件：Dev/Prod Cloud Projects、测试 Gmail、正确 OAuth clients/scopes/callbacks、明确的测试收件 allowlist。
- 方法：完成 A1-A6 后登录、连接 Gmail，运行 `scripts/smoke-gmail.sh`（默认 prepare-only，创建带 `[AgentMail E2E <run-id>]` 的单个 managed draft）；人工核对 preview 后用 `--send` 交互确认发送到测试账号自身。
- 期望：只产生一个预期草稿/邮件，不改既有标签或已读状态；token 加密入库；所有 revoke 立即切断本地权限。
