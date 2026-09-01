# 未完成测试与测试方法

本文件只记录当前还没有通过的测试与外部验收。已通过的本地结果见提交记录：Rust 严格 Clippy、103 项领域/配置/数据库/OAuth/JWKS/control-plane/repository/治理测试、3 项 HTTP 安全契约测试、5 项 REST/MCP 契约测试，以及隔离 SQLite 的 migrate/status/backup CLI smoke。

## A. 尚未实现，因此目前无法执行的测试

### A1. Google OIDC 登录与邀请制 control plane

- 已实现：真实 RS256/JWKS verifier（固定 discovery、no-redirect、响应上限、缓存与 unknown-kid 冷却）、flow-scoped 单次 callback、固定双 client token exchange、Owner+session、session cookie/CSRF 和 Login/Gmail HTTP 路由均已接入 `serve`。剩余缺口：邀请接受、Member 登录及邀请/成员/Access Key 的 control plane 页面与 CRUD 尚未接入 HTTP，真实 Google 浏览器登录尚未执行。
- 实现后测试：用 fake OIDC server 覆盖成功、错误 state/nonce、错误 issuer/audience、过期 token、未验证 email、邀请 email 不一致、邀请重放、session idle/absolute expiry 和 CSRF；再用 Dev Project 浏览器登录。
- 命令目标：`cargo test --test oidc_contract --all-features`。
- 通过标准：所有失败在创建用户/session 前被拒绝；数据库和日志不出现 authorization code、state、nonce、access token 或 ID token。

### A2. Gmail OAuth Connection 与真实 Google adapter

- 已实现：offline consent、完整 scope 校验、Connection callback、加密 refresh token、single-flight access-token cache、`invalid_grant` reauth、原 connection 的 owner/sub 绑定 reauthorize，以及带 8 MiB 响应上限的 Gmail 只读 client。剩余缺口：真实 `GmailAdapter` 尚未装配，Google token revoke 与完整 Connection revoke 编排尚未实现；REST 邮件路径当前仍使用 `FakeGmailAdapter`。
- 实现后测试：fake Google server 覆盖部分授权、refresh、invalid_grant、429/5xx/Retry-After、timeout、revoke；Dev 账号完成连接、搜索、读取、线程和附件流。
- 命令目标：`cargo test --test gmail_adapter --all-features`，以及人工 `scripts/smoke-gmail.sh --prepare-only`。
- 通过标准：缺少 `gmail.readonly` 或 `gmail.compose` 不创建 Connection；refresh token 仅以 XChaCha20-Poly1305 envelope 入库；查询和邮件内容不进日志。

### A3. 数据库 repository 与 control plane CRUD

- 缺口：SQLite repository 已覆盖 users/invitations/sessions/connections/access keys/grants/managed drafts/audit/首次授权 ledger；HTTP 已从 repository 认证持久化 key、校验 grant 并列出获授权 Connections，但 control plane CRUD 与完整 transport 持久化装配尚未完成，当前 production `serve` 没有可用 Access Key 管理入口。
- 实现后测试：临时 SQLite 覆盖 Owner/Member、邀请、Connection、key create/rotate/revoke、grant 变更、账号删除与跨重启恢复。
- 命令目标：`cargo test --test repository_roundtrip --all-features`。
- 通过标准：重启后状态不丢失；key/confirmation/session 只存 hash；唯一 Owner、唯一 Gmail sub 与 first-authorization ledger 约束生效。

### A4. MIME、附件与完整 managed draft

- 缺口：mail-builder MIME、reply/reply-all/forward、multipart 流式上传、附件转发/下载、25 MiB 编码后限制和 Sent Message-ID 对账尚未完成。
- 实现后测试：非 ASCII headers、header injection、reply references、reply-all 排除当前地址、forward 内嵌图、恶意文件名、MCP 4 MiB、HTTP 25 MiB、超限和响应丢失。
- 命令目标：`cargo test --test mime_and_drafts --all-features`。
- 通过标准：非 managed draft 只能读取；版本变化返回 `409 draft_changed`；超时不自动重发，无法对账进入 `send_state_unknown`。

### A5. 完整 REST OpenAPI 与 rmcp schema

- 缺口：OpenAPI 已描述消息搜索且 REST/MCP 复用认证、grant 与 `MailboxReadService`，最小 JSON-RPC 已实现 `messages.search`；其余 REST paths/tools、rmcp Streamable HTTP、session lifecycle 与 schema snapshot 尚未实现。
- 实现后测试：导出 OpenAPI/MCP schema，运行 snapshot 与真实 MCP client；比较 HTTP/MCP 的领域字段和错误码。
- 命令目标：`cargo test --test transport_contract --all-features`，`cargo test --test mcp_schema --all-features`。
- 通过标准：tools 标明邮件内容不可信和发送需用户许可；MCP 与 REST 共享认证、grant、状态机和审计逻辑。

### A6. 限流、审计、账号撤销与清理

- 缺口：限流窗口、4 路读取并发、send-unknown refund、无内容 AuditEvent 与 repository 写入已实现；rate bucket 数据库读写、transport 接入、30 天清理和完整账号撤销编排尚未完成。
- 实现后测试：冻结时间并跨重启验证 120/min、30 prepare/hour、10/hour、50/day、20 recipients；账号/key/grant/Connection revoke 的并发请求立即失败；审计字段白名单快照。
- 命令目标：`cargo test --test security_flows --all-features`。
- 通过标准：429 含 retry seconds；日志/审计不包含地址、主题、正文、snippet、附件名、查询或任何 token。

## B. 代码已具备，但当前机器未完成的测试

### B1. cargo-audit 与 cargo-deny

- 前置条件：安装 `cargo-audit`、`cargo-deny` 并允许访问 advisory/index。
- 命令：`cargo audit --locked`; `cargo deny check`。
- 期望：无未处理 advisory、许可证或来源违规。
- 当前原因：本机未安装这两个 cargo 子命令；CI 已配置执行。

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
- 当前原因：仓库 CI 只做验证/构建/扫描，release workflow 尚未实现。

### B6. Google Dev/Prod 与真实 Gmail smoke

- 前置条件：Dev/Prod Cloud Projects、测试 Gmail、正确 OAuth clients/scopes/callbacks、明确的测试收件 allowlist。
- 方法：完成 A1-A6 后登录、连接 Gmail、创建带 `[AgentMail E2E <run-id>]` 的 managed draft，默认只执行 prepare；人工核对 preview 后才确认发送到测试账号自身。
- 期望：只产生一个预期草稿/邮件，不改既有标签或已读状态；token 加密入库；所有 revoke 立即切断本地权限。