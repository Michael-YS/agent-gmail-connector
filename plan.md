# AgentMail v1 实施计划

## 1. 目标与已确认边界

AgentMail 是部署在 `https://agentmail.michaelsun.top` 的 Gmail 访问转发层。它集中处理 Google OIDC、Gmail OAuth、refresh token、安全审计和 Gmail API 调用，并向 agent 提供 REST 与 MCP 两种机器接口。

对外路径：

- `/`：人类使用的 control plane；未登录时同时作为公开产品说明页。
- `/api`：API 版本信息与 OpenAPI 入口。
- `/api/v1`：稳定 REST API。
- `/mcp`：MCP Streamable HTTP。
- `/health/live`、`/health/ready`：最小化健康状态。

v1 包含：

- Google OIDC 登录、唯一 Owner、管理员邀请和多个 Member。
- 一个 Member 连接多个 Gmail；同一个 Gmail 账号在整个实例中只能归属一个 Member。
- Access Key 与 Gmail Connection 解耦；一把 key 可授权一个或多个 Connections。
- Gmail 搜索、邮件读取、线程读取和附件下载。
- 新邮件、回复、回复全部和转发草稿。
- 读取全部 Gmail 草稿，但只能修改、删除和发送 AgentMail 在该 Connection 下创建的草稿。
- 两阶段、版本绑定、单次使用的发送确认流程。
- 无邮件内容的元数据审计。

v1 明确不包含：

- Gmail watch、Google Pub/Sub、后台收信或定时轮询。
- 邮件已读状态、标签、归档、垃圾邮件或邮件删除操作。
- send-as aliases。
- 批量发信。
- 原始 MIME 下载接口。
- MCP 大型本地附件上传。
- 多实例、横向扩容或 PostgreSQL。
- Access Key 的细粒度操作权限。
- Sentry、外部日志或公网 Prometheus metrics。

v2 计划增加 Access Key 能力范围，例如 `read`、`draft.write` 和 `draft.send`；v1 中 key 对获授权 Connection 拥有全部 AgentMail v1 能力。

## 2. Google 项目与合规模式

维护两个 Google Cloud Projects：

1. `AgentMail Dev`
   - Publishing status 为 Testing。
   - junk-mail 测试邮箱是 test user。
   - 允许 localhost redirect URI。
   - 7 天 refresh token 有效期可接受。
2. `AgentMail Prod`
   - Audience 为 External。
   - Publishing status 为 In Production。
   - 仅配置 `agentmail.michaelsun.top` 的 HTTPS redirect URI。
   - 采用 Personal Use 豁免，不申请 OAuth verification 或 CASA。
   - 用户接受 unverified app 警告。

官方 Personal Use 说明：<https://support.google.com/cloud/answer/13464323>。

生产实例实施以下护栏：

- 管理员邀请制。
- `PERSONAL_USE_USER_LIMIT` 默认 90，配置上限不得超过 99。
- 保存只增不减的历史 Gmail 首次授权计数；账号删除不降低计数，上游 reauthorize/rotate 不重复计数。
- control plane 展示当前成员数、历史授权计数和剩余额度，并注明 Google Cloud Console 是最终权威数据。
- 所有环境继续遵守 Google API Services User Data Policy。

每个 Google Cloud Project 创建两个 Web OAuth Clients：

- Login Client：只请求 `openid email profile`，用于 control plane 登录，不保存 refresh token。
- Gmail Client：请求 `openid email profile gmail.readonly gmail.compose`，用于 Gmail Connection，要求 offline access。

两个流程使用独立 callback、client secret、OAuth state 和错误处理。Authorization code flow 使用 PKCE；OIDC 验证 `state`、`nonce`、issuer、audience、签名、过期时间和 `email_verified=true`。Gmail callback 必须确认实际 granted scopes 完整，否则不创建 Connection。

## 3. 技术栈与模块结构

使用单一 Rust 应用：

- Axum + Tokio：HTTP server。
- Askama：服务端 HTML 模板。
- rmcp：MCP Streamable HTTP。
- SQLx + SQLite WAL：持久化与迁移。
- oauth2 + reqwest：Google OAuth/OIDC 和固定 Gmail REST 调用。
- mail-builder：RFC 合规 MIME、HTML、附件、回复与转发。
- tower/tower-http：中间件、限流、request ID、超时和安全头。
- XChaCha20-Poly1305：Google refresh token 信封加密。

不包装或执行 `gws` CLI，也不向 agent 暴露动态 Google Discovery 表面。可以参考其错误处理和 MIME 行为，但 AgentMail 只维护自己的窄接口。

核心深模块：

- **Identity**：Owner/Member、邀请、Google OIDC、sessions、账号删除。
- **Connections**：Gmail OAuth、refresh、reauthorize、revoke 和状态转换。
- **Access**：Access Keys、grants、Bearer 认证和 key rotation。
- **Mailbox**：搜索、规范化邮件、线程、附件和草稿操作。
- **Delivery**：草稿版本、prepare/send、幂等和不确定发送恢复。
- **Audit**：脱敏审计、last activity 和限流计数。
- **Google adapter**：真实 Gmail 实现；测试使用 fake adapter。

HTTP、MCP 和 control plane 通过相同领域模块工作，不能各自实现 OAuth、Gmail 或授权逻辑。

## 4. 数据模型

SQLite 至少包含以下表：

- `users`：稳定 Google `sub`、登录 email、角色、状态、last activity、时间戳。
- `invitations`：规范化目标 email、一次性 token hash、邀请者、过期和接受状态。
- `web_sessions`：随机 session token hash、用户、CSRF 状态、空闲和绝对过期时间。
- `oauth_transactions`：流程类型、state/PKCE/nonce、发起用户、目标 Connection 和短期过期时间。
- `gmail_connections`：owner、Google `sub`、主 email、状态、granted scopes、加密 refresh token 信封、时间戳。
- `access_keys`：owner、名称、公开 prefix、secret hash、generation、状态、last used。
- `access_key_grants`：Access Key 到 Connection 的授权关系。
- `managed_drafts`：Connection、Gmail draft/message ID、稳定 RFC Message-ID、当前版本指纹和状态。
- `send_confirmations`：token hash、Access Key/generation、Connection、draft/version、过期、消费状态和结果。
- `idempotency_records`：调用方、操作、请求摘要、状态和缓存结果。
- `audit_events`：无内容元数据审计。
- `rate_limit_buckets`：需要跨重启保留的发信计数。
- `instance_counters`：Personal Use 历史授权计数等单调状态。

约束：

- `gmail_connections.google_sub` 全局唯一；email 只用于展示。
- Access Key、session、邀请、OAuth state 和确认 token 均只保存哈希。
- Access Key 格式为 `amk_<public-id>.<256-bit-secret>`；比较使用常量时间算法。
- refresh token 使用随机 nonce、key version 和 AAD 加密；AAD 绑定 user、Connection 和凭据类型。
- keyring secret 支持多个解密版本和一个 active version，便于先重加密再移除旧密钥。
- managed draft 所有权属于 Connection；key rotation 不改变草稿所有权。

主要状态：

- User：`active`、`revoking`。
- Connection：`active`、`reauth_required`、`revoking`。
- Access Key：`active`、`revoked`。
- Managed Draft：`active`、`sending`、`sent`、`deleted`、`send_state_unknown`。

## 5. Control plane

Askama 服务端渲染，少量原生 JavaScript；不引入 React、Vite 或生产 Node runtime。所有修改操作使用 POST、CSRF token 和 Post/Redirect/Get。

公共页面：

- 产品用途与数据处理说明。
- Google 登录入口。
- Privacy Policy、Terms of Service 和 Data Deletion 页面。

Member 页面：

- 自己的 Gmail Connections：email、状态、scope、last used、reauthorize、revoke。
- 自己的 Access Keys：名称、prefix、grants、last used、rotate、revoke。
- 创建 key 并选择 Connections。
- 只在创建或 rotate 成功页显示一次完整 key；离开后无法再次读取。
- 自己的 30 天无内容审计。
- 删除自己的 AgentMail 账号。

Owner 额外页面：

- 创建、查看、撤销和重新生成邀请链接。
- 查看成员登录 email、状态、Connection/Key 数量和 last activity。
- revoke 某个 AgentMail 账号。
- 查看 Personal Use 当前成员、历史授权计数和剩余额度。

Owner 不能读取成员邮件或草稿，不能查看 Google token、Access Key 明文、查询字符串、收件人、主题、正文或附件名。

Owner 通过 `OWNER_EMAIL` 引导首次登录，成功后以 Google `sub` 作为稳定身份。Owner 不能在 UI 中被删除或降级；转移 Owner 必须由服务器 owner 修改配置并运行专门管理命令。

邀请：

- 绑定精确、已验证的 Google email。
- 一次性链接，默认 7 天过期。
- 由 Owner 手动复制给用户，不集成邮件投递服务。

账号 revoke：

1. 立即使 sessions、Access Keys、grants 和发送确认失效。
2. 标记账号 `revoking`，阻止新调用。
3. 对各 Connection 调用 Google token revoke。
4. 短期重试瞬时失败；无论 Google 结果如何，本地权限始终立即失效。
5. 删除 refresh token、Connection、key hash、grant、managed draft 记录和用户资料。
6. 不删除 Gmail 中的邮件或草稿。
7. 只保留不含 Google 用户数据的最小安全审计事件。

## 6. 机器认证与公共接口

REST 与 MCP 使用同一个 Bearer Access Key：

```http
Authorization: Bearer amk_<public-id>.<secret>
```

规则：

- 禁止 query-string token。
- control plane cookie 不能调用 REST/MCP。
- 每个机器调用必须显式传 `connection_id`，即使 key 只拥有一个 grant。
- 服务器先解析 key，再验证 key owner、状态、generation 和 Connection grant。
- API/MCP 不能创建 OAuth Connection 或管理 Access Key；这些操作只存在于 control plane。
- 每个响应包含 request ID 和实际 Connection ID；不得根据 email 路由。

REST 路径：

```text
GET    /api/v1/connections

GET    /api/v1/connections/{connection_id}/messages
GET    /api/v1/connections/{connection_id}/messages/{message_id}
GET    /api/v1/connections/{connection_id}/threads/{thread_id}
GET    /api/v1/connections/{connection_id}/messages/{message_id}/attachments/{attachment_id}

GET    /api/v1/connections/{connection_id}/drafts
GET    /api/v1/connections/{connection_id}/drafts/{draft_id}
POST   /api/v1/connections/{connection_id}/drafts
PATCH  /api/v1/connections/{connection_id}/drafts/{draft_id}
DELETE /api/v1/connections/{connection_id}/drafts/{draft_id}

POST   /api/v1/connections/{connection_id}/drafts/{draft_id}/prepare-send
POST   /api/v1/connections/{connection_id}/drafts/{draft_id}/send
```

`/api` 提供版本信息和 OpenAPI 文档链接；成功响应返回领域 JSON，错误使用稳定机器码、request ID、可重试标志和 `retry_after_seconds`，不透传含敏感数据的 Google 原始错误正文。

搜索：

- 接受 Gmail `q` 查询字符串，但审计和应用日志不记录其值。
- 默认 page size 20，最大 100。
- Gmail page token 包装为 AgentMail 不透明 cursor，不作为长期稳定标识。
- 搜索结果只返回安全元数据、snippet 和附件清单，不默认返回正文。

邮件读取：

- 默认规范化纯文本。
- HTML 仅显式请求，删除 script、form、事件处理器、远程图片和主动内容。
- 不自动访问链接或加载远程图片。
- 正文置于 `untrusted_email_content`，明确禁止 agent 把内容当成系统指令。
- 超长正文分块并返回 `truncated` 与不透明后续 cursor。
- 不开放原始 MIME。

附件：

- HTTP draft create/update 使用 JSON（无附件）或 `multipart/form-data`（`metadata` JSON + `attachments[]`）。
- HTTP 原始附件合计上限 25 MiB，并在 MIME 编码后再次检查 Gmail 总大小限制。
- 下载附件流式转发，不落盘；文件名与 Content-Disposition 必须清理。
- MCP 小附件使用 base64，默认原始数据合计上限 4 MiB。
- MCP 可以引用当前获授权 Gmail 中已有附件用于回复/转发。
- 大型本地附件必须通过 HTTP 创建或更新草稿。
- 禁止服务器从任意 URL 抓取附件，避免 SSRF。

MCP 使用无状态 Streamable HTTP。MCP tools 与 HTTP 复用领域类型，但为 agent 清晰度将以下草稿操作拆开：

- create new draft
- create reply draft
- create reply-all draft
- create forward draft
- list/get/update/delete managed draft
- prepare send
- send prepared draft

MCP tool annotations 和描述必须标明外部副作用、邮件内容不可信，以及发送前必须取得用户许可。

## 7. 草稿与发送状态机

草稿规则：

- new、reply、reply-all、forward 都创建真实 Gmail Draft。
- reply/reply-all 自动生成线程、`In-Reply-To` 和 `References`。
- reply-all 排除当前 Gmail 主地址；v1 不解析 send-as aliases。
- forward 默认包含原附件与内嵌图片；超限时返回结构化错误，允许调用方选择移除附件。
- 每个 draft 生成唯一稳定 RFC Message-ID。
- list/get 可以读取全部 Gmail 草稿，并返回 `managed_by_agentmail`。
- update/delete/send 只允许 `managed_by_agentmail=true` 且属于当前 Connection 的草稿。
- 人类在 Gmail UI 修改 AgentMail 草稿后，它仍是 managed draft，但版本会改变。

并发规则：

- `get_draft` 返回内容指纹 `version`。
- update/delete 必须传 `expected_version`；不匹配返回 `409 draft_changed`。
- 同一 draft 的写入、prepare 和 send 串行化。

发送流程：

1. `prepare_send(draft_id)` 重新读取草稿，返回 Connection、From、To/Cc/Bcc、主题、正文摘要、附件清单、version、安全提示和 5 分钟确认 token。
2. Agent 把该摘要展示给用户并征求发送许可。
3. `send` 只接受 `draft_id` 与 confirmation token，不接受任何收件人、主题、正文或附件字段。
4. 服务端验证 key/generation、Connection、draft/version、过期和单次状态后调用 Gmail。
5. 草稿变化、key rotate/revoke、grant 移除或 Connection revoke 会使确认 token 失效。
6. 相同 confirmation token 的重复请求返回首次结果，不重复发送。

发送成功响应丢失时：

- 不直接重试 `drafts.send`。
- 使用稳定 RFC Message-ID 查询 Sent Mail 并对账。
- 能确认则返回幂等成功；无法确认则进入 `send_state_unknown`，阻止自动再次发送并给出人工检查提示。

HTTP 创建草稿支持 `Idempotency-Key`；同一 key 与相同请求摘要返回原结果，不创建重复草稿。MCP transport 为一次工具调用建立对应幂等记录。

## 8. 限流、重试与审计

默认限制：

- 每把 Access Key 120 次 API/MCP 调用每分钟，允许有限 burst。
- 每个 Connection 最多 4 个并发 Gmail 读取请求。
- 每把 key 最多 30 次 `prepare_send`/小时。
- 每个 Connection 最多 10 封成功发送/小时、50 封/天。
- 单封邮件最多 20 个 `To + Cc + Bcc` 收件人。
- `send_state_unknown` 暂计入额度，确认未发送后返还。
- 超限返回 `429` 和 `retry_after_seconds`。

读取类 Google `429/5xx` 按有限次数指数退避并加入 jitter，尊重 Retry-After。写入依赖幂等记录；发送使用专门状态机，不执行通用自动重试。

审计默认保留 30 天，可由 owner 配置调整。审计只保存：

- 用户 ID、Access Key ID、Connection ID。
- 操作类型、结果类别、延迟、request ID、时间。

禁止保存：

- Gmail 查询字符串。
- 邮箱地址、收件人、主题、正文、snippet 和附件名。
- Authorization、Cookie、OAuth code/state、refresh/access token、Access Key secret 和 confirmation token。

用户与 Connection 的 `last_activity_at` 单独保存，不因审计清理而丢失。

## 9. Secrets 与容器安全

VPS 推荐布局：

```text
/opt/agentmail/                 # compose、版本配置、宿主机脚本
/etc/agentmail/secrets/         # root-owned 0400 secrets
/var/lib/agentmail/             # SQLite 与持久状态
/var/backups/agentmail/         # 迁移备份
```

Compose secrets 只读挂载：

- Google login client secret。
- Google Gmail client secret。
- credential encryption keyring。
- session/CSRF secret。

非秘密 client ID、public base URL、限流和保留期使用普通配置。应用必须在启动时拒绝弱密钥、缺失配置、非 HTTPS production URL 和未知 schema version。

容器：

- 仅构建 `linux/amd64`。
- 两阶段 Rust build，运行层使用 Debian slim 和 CA certificates。
- 非 root 用户。
- root filesystem 只读；仅数据目录和 tmpfs 可写。
- `cap_drop: ALL`、`no-new-privileges`。
- 端口只发布到 `127.0.0.1`，例如 `127.0.0.1:18080:8080`。
- 优雅处理 SIGTERM，并在停止前完成或终止在途请求。

应用仅信任显式配置的反向代理。`PUBLIC_BASE_URL=https://agentmail.michaelsun.top` 是 OAuth URL 的唯一来源，不根据传入 Host/X-Forwarded-* 动态构造 redirect URI。

Nginx：

- 负责 TLS 和公网入口。
- `/mcp` 关闭 proxy buffering，并设置适合 Streamable HTTP 的 read timeout。
- 附件上传路径关闭 request buffering，使应用能够流式读取。
- `client_max_body_size` 与应用限制一致并略留 MIME/form 开销。
- 不记录 Authorization 或 Cookie。
- 只传递必要的 Host、X-Forwarded-Proto、X-Request-ID 和客户端地址信息。

## 10. 数据库迁移与备份

应用二进制提供：

```text
agentmail migrate status
agentmail migrate
agentmail database backup <target>
agentmail serve
```

`agentmail serve` 永不自动迁移；发现 pending migration 时拒绝启动并提示运行宿主机脚本。

仓库提供 `scripts/migrate.sh`，Dockerfile 不复制 `scripts/`，因此脚本不进入镜像。脚本：

1. `set -euo pipefail` 并解析真实部署目录。
2. 使用 `flock` 防止并行迁移。
3. 检查 Compose 配置、目标镜像、数据目录、权限和可用空间。
4. 查询当前 schema 和 pending migrations；无变化时安全退出。
5. 优雅停止 AgentMail。
6. 调用一次性容器与 SQLite backup API 创建带 UTC 时间、旧 schema 和应用版本的备份。
7. 执行 `docker compose run --rm --no-deps agentmail migrate`。
8. 成功后启动服务并等待 `/health/ready`。
9. 输出旧/新版本、schema、备份路径和健康结果。
10. 失败时保持服务停止，不自动覆盖数据库，并输出明确恢复命令。

脚本不使用 `docker compose down`，不删除 volume、数据库或旧备份。迁移备份不自动清理。

## 11. 日志与健康检查

- 仅输出脱敏结构化 JSON 到 stdout/stderr，由 Docker logging driver 接管。
- 日志包含 request ID、路由模板、操作类别、状态、延迟和 Google 错误类别。
- 日志不得包含正文、地址、主题、查询、附件名或任何秘密。
- `/health/live` 只表示进程事件循环可用。
- `/health/ready` 检查配置、SQLite、schema 和关键内部状态，但不调用 Google。
- 不接入 Sentry、外部日志、analytics 或公网 metrics。

## 12. 开发、测试与 CI

真实 Gmail smoke test 使用专门收 junk mail 的账号：

- 主题带 `[AgentMail E2E <run-id>]`。
- 只发送到测试账号自身或显式测试 allowlist。
- 只修改/删除当前测试创建的 managed drafts。
- 不修改既有邮件状态、标签或位置。
- 使用仓库内无敏感信息的小附件。
- 默认执行到 `prepare_send`；实际发送要求运行者再次确认。
- refresh token 只进入本地测试实例或 VPS 加密数据库，不进入 GitHub Secrets。

自动测试：

- 领域状态机、grants、加密、token hash、OAuth state 和限流单元测试。
- MIME、非 ASCII header、reply/reply-all/forward、附件大小测试。
- 临时 SQLite、迁移升级、约束和备份恢复测试。
- fake OAuth/Gmail adapter 的成功、部分授权、token revoke、429、5xx、超时和响应丢失测试。
- HTTP OpenAPI contract 和 MCP tool schema 快照测试。
- 跨用户、跨 key、跨 Connection、IDOR、CSRF、重放和日志脱敏安全测试。
- 超长正文、恶意 HTML、header injection、路径/文件名清理和 SSRF 拒绝测试。

GitHub Actions：

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo audit
cargo deny check
迁移与 schema 测试
OpenAPI/MCP schema 快照测试
Docker build
容器漏洞扫描
```

PR 和普通 push 不使用真实 Google 凭据。Actions 固定到完整 commit SHA，并验证 Rust lockfile。

## 13. 镜像发布与 VPS 更新

镜像公开发布到 GHCR。VPS 不需要 `docker login`。

- PR/普通分支：验证，不推 production image。
- `main`：可发布 `edge`，不供生产使用。
- `vX.Y.Z` tag：发布 `X.Y.Z`、`X.Y`、`latest` 和不可变 commit SHA 标签。
- 生成 SBOM、build provenance、GitHub artifact attestation 和 keyless signature。
- GHCR 推送仅使用 Actions 的短期 `GITHUB_TOKEN`。
- 镜像中不包含 `.env`、OAuth secrets、加密密钥或测试凭据。

生产 Compose 固定明确版本或 image digest，不跟随 `latest`。服务器 owner 通过 SSH 更新版本；需要 schema 变化时运行 `scripts/migrate.sh`。GitHub Actions 不 SSH 到 VPS，也不自动部署或自动回滚。

## 14. 实施顺序与完成标准

1. 初始化 Rust 项目、配置、错误模型、tracing、SQLite migrations、Docker 与 CI。
2. 实现 Identity、公开说明页、Google OIDC、Owner bootstrap、邀请与 sessions。
3. 实现 Gmail OAuth Connection、加密 keyring、refresh、reauthorize 和 revoke。
4. 实现 Access Keys、grants、Bearer middleware、Personal Use 计数和 control plane 页面。
5. 实现 Mailbox 读取接口、正文规范化、HTML 清理、分页和附件流。
6. 实现 managed drafts、MIME、reply/reply-all/forward、版本冲突与附件限制。
7. 实现 prepare/send 状态机、确认 token、幂等、Sent 对账和发送限流。
8. 实现 REST OpenAPI 和 MCP tools，完成跨 transport contract 测试。
9. 完成账号删除、Owner revoke、审计清理、健康检查和宿主机迁移脚本。
10. 使用 Dev Project 与 junk-mail 账号完成真实 OAuth/Gmail smoke test。
11. 构建并验证公开 GHCR release image；在 VPS 使用固定版本部署并通过 Nginx 验证三个公共入口。

v1 验收必须证明：

- 未获 grant 的 key 无法通过修改 ID 访问其他 Connection。
- Gmail refresh token、Access Key secret 和 session secret 从未以明文进入数据库、日志、镜像或 GitHub Actions。
- 邮件正文与附件不持久化，HTML/远程内容按约定处理。
- 非 managed draft 只能读取，不能修改、删除或发送。
- 未 prepare、过期、已消费、跨 key、跨 Connection 或版本变化的确认 token 均不能发送。
- 网络超时和客户端重试不会造成重复草稿或重复发送。
- account/Connection/key revoke 立即切断本地访问。
- pending migration 时应用拒绝启动；宿主机脚本能备份、迁移、重启并验证 readiness。
- 发布镜像可在 Debian/Ubuntu amd64 VPS 上由 Compose 拉取运行，且只通过宿主机 Nginx 暴露公网。
