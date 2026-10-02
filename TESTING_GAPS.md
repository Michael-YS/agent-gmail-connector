# 未完成测试与测试方法

## 前端样式部署验收（2026-10-02）

- `agentmail:3d85c3f` 已部署 S1，来源为已合并并推送的 `main` 提交 `3d85c3f`；13 项控制台、5 项 HTTP、24 项 REST/MCP 契约、格式及严格 Clippy 通过，七页的桌面/窄屏/深色浏览器检查通过。服务 healthy/零 restart，源站 HTTPS live/ready、首页样式/CSP、匿名 MCP 401 和匿名控制台 303 已验证。备份 `agentmail-20261002T185031Z.db` 的只读 integrity/foreign key 检查通过，旧镜像 `b38f8c2` 保留。
- Cloudflare 公网路径仍返回 525，旧镜像也复现；s1 的有效证书、TLS 1.2/1.3、本机源站及从本机直连 `149.28.206.57` 的 HTTPS 均通过。尚需核对 Cloudflare 的 A/AAAA origin、Origin Rule/端口等设置；当前证据只能定位到 Cloudflare 到源站路径，不能断言具体 DNS 配置错误。未关闭 TLS 验证或修改 Nginx。真实登录后页面与真实 MCP client 尚未重新验收。
- 全量单测在当前沙箱中为 187 通过/22 失败；mock listener 被网络沙箱拒绝，默认 umask 导致空 secret 文件先被权限规则拒绝，隔离的 connection revoke 压力测试仍触发 SQLite `PoolTimedOut`。私有 `umask 077` 权限测试及允许 loopback 的 UI/HTTP/REST/MCP 契约复跑通过。本轮保留后端安全校验与原有测试超时，不能据此声明全量门禁通过。

## S1 beta 修复验收（2026-09-27）

- 本轮 MCP `connections.list` 已部署 `agentmail:b38f8c2`：回归覆盖 REST/MCP 结果一致、三个 MCP 入口、空列表、跨所有者与未授权/非 active 连接隔离、无效参数、鉴权、单次计费与元数据审计，并更新工具 schema snapshot。格式与 diff 检查通过，用户运行全量测试与严格 Clippy 后报告 all pass；用户完成 S1 amd64 构建，部署前备份 `agentmail-20260928T083917Z.db` 只读 `quick_check=ok`、外键问题 0，新容器 healthy/零 restart、内外网 live/ready 与首页 200、匿名 MCP initialize 401，旧镜像 `c08553a` 保留。仍需真实 MCP 客户端刷新工具列表，用 `{}` 调用并核对只出现当前 Key 的可用连接，不发送邮件。相关提交已于 2026-10-02 随 `main` 推送至 origin。
- Hermes 首次真实 MCP 连接被 rmcp 默认 Host 白名单拒绝（403），非 SSE transport 选错：线上 Nginx 的固定公网 Host 未包含在默认 loopback 名单中。修复 `c08553a` 已部署，生产 `PUBLIC_BASE_URL` authority 接线与公网域名正向/未知 Host 负向回归已补，保留 loopback 默认、Bearer 鉴权及非默认端口/IPv6 语义。格式与 diff 检查通过，用户运行全量测试与严格 Clippy 后报告全过；新容器 healthy/零 restart、内外网 live/ready 与首页 200，匿名 MCP initialize 为 401。备份 `agentmail-20260928T071146Z.db` 的只读 `quick_check=ok`，旧镜像 `353d67d` 保留。真实 Hermes 重连 initialize/tools/list 仍待用户验收；不要关闭 Host 校验或让客户端伪造 Host。

- 已补首次注册 token 页面并部署 `agentmail:353d67d`：任意未登记但已验证的 Google 身份可以进入该页面，没有有效同邮箱邀请不得创建用户/session；已有账号直接登录。待注册状态五分钟过期、单次提交且重启失效。格式与 diff 检查通过，用户运行全量测试及严格 Clippy 后报告 all pass。新容器健康、内外网 live/ready 与公网首页 200，匿名 GET `/auth/register` 为 303 `/auth/google/login`；备份 `agentmail-20260928T043442Z.db` 的只读 `quick_check=ok`，旧镜像 `44193e1` 保留。用户完成真实浏览器邀请注册，数据库确认 Active Member、Google 绑定和有效 session。
- Owner 更换与旧账号本地退出已完成：操作前备份 `agentmail-20260928T054101Z.db` 的只读 `quick_check=ok`；内存副本演练和停服事务保留目标身份/session，原 Owner 的一条已消费邀请需先清理以免 `invited_by` 外键阻塞账号删除。启动恢复走现有 token revoke/本地清理流程；核对仅一个目标 Active Owner，旧账号、两个 Connection、Key 与旧邀请均移除，目标 session 保留、外键零问题，容器 healthy/零 restart、内外网健康 200。`OWNER_EMAIL` 已同步新 Owner。仍待新 Owner 页面刷新验收、Google 端撤销结果独立核验；没有删除 Gmail 邮件或草稿，本地备份不能回滚 Google 端 revoke。

- 此前部署 `agentmail:44193e1` 时容器健康、容器内及公网 live/ready 均通过；备份 `agentmail-20260928T005333Z.db` 的 SQLite `quick_check=ok`。此前真实浏览器 Owner 登录与账户页正常。Google Gmail consent 曾创建一个属于 Owner 的 Active Connection，账户页显示 `gmail.readonly` 与 `gmail.compose`，随后已将其撤销；scope URL 兼容修复已通过真实授权验证。
- 成功 Gmail callback 曾返回 JSON；`45bd227` 将它改为 303 跳转 `/control/account`，本地测试断言跳转和 `no-store`。新版本尚未再次通过真实 Google callback 验证跳转；不可刷新已消费的旧 callback。
- 待执行：真实 refresh、Google 端 revoke 状态核对、撤销后重新授权 callback，以及真实 MCP client。单封垃圾邮箱自发自收、Sent/Inbox 只读核对、临时 Key 与 Connection 的本地撤销已完成；不要再次发送，也不要复制 callback URL、authorization code 或 token 到日志/文档。
- 撤销后点击 Connect Gmail 暴露 POST→Google 307 重定向：Nginx 收到表单请求并返回 307，浏览器未到授权页。`0c5780e` 已改成 303 并补测试；用户报告全量测试和严格 Clippy 均通过，S1 构建与健康部署已完成，真实 Google callback 尚未验证。
- 非 Owner 且尚未受邀的另一 Google 账号尝试 Panel 登录，Login callback 返回了误导性的 HTTP 503；只读核对表明 S1 仅有一个有效 Owner，没有该账号的 Member。`88fbe8a` 已将此情况改为 HTTP 403 `authentication_failed`，不创建账号或 session；用户报告全量测试和严格 Clippy 均通过，S1 已健康部署，真实浏览器回归仍待执行。已消费的旧 callback 不可刷新重放。
- 本机测试环境注意：默认 `umask 022` 会使 `config::tests::google_client_secret_files_use_size_permission_and_exclusivity_rules` 的空文件先触发权限错误；默认测试并发叠加编译负载时，Connection revoke 压力测试曾触发 SQLite `PoolTimedOut`。复跑使用 `umask 077` 和 `--test-threads=2`；测试夹具对权限/负载的敏感性仍未在代码中修正，本轮没有放宽生产权限校验或测试超时。
- `mcp_draft_writes_validate_arguments_and_charge_per_request` 曾固定要求两次请求后的分钟桶计数为 2，跨分钟时会误失败。当前测试先断言 REST create 计费一次，再按 MCP update 前后窗口是否相同断言计数为 2 或 1，仍能发现第二次请求未计费；生产限流逻辑未改。用户复跑全量测试与严格 Clippy 后报告全 pass。
- 登录前公开首页此前没有任何 CSS；`44193e1` 补内联响应式明暗样式，并断言首页样式、CSP 和原有登录/法律链接。用户报告全量测试与严格 Clippy 全 pass，S1 已健康部署；公网首页含新样式，真实浏览器窄屏深色视图的标题、登录按钮和法律链接已核对，无明显溢出，未点击登录。本轮未单独截图验证宽屏和浅色视图。

本文件聚焦剩余测试与外部验收。最新本地门禁结果统一记录在 `IMPLEMENTATION_PROGRESS.md`。历史上 WSL Docker 与 S1 amd64 的构建、迁移、loopback-only 运行、安全边界、备份和重启恢复，以及 S1 Nginx/TLS/Cloudflare 入口均已通过验收；这些结果不代表本轮代码已部署。arm64 真实主机、GitHub tag release 和真实 Google/browser smoke 仍未完成。

## A. 已实现功能的验收覆盖与剩余缺口

### A1. Google OIDC 登录与邀请制 control plane

- 已实现：真实 RS256/JWKS verifier、flow-scoped 单次 callback、Owner/Member session、邀请 API/HTML、Member Connection/Access Key HTML、账号自删与 Owner revoke、JSON reauthorize 入口（`POST /control/api/connections/{id}/reauthorize`）。管理 JSON API 使用 `/control/api/...`，HTML 使用 `/control/...`。Owner 真实 Google 浏览器登录已通过；邀请制 Member 登录和账号撤销仍待外部 smoke。
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

### B5. GHCR release 供应链

- 前置条件：GitHub Actions/GHCR 权限和版本 tag。
- 方法：发布 `vX.Y.Z`，核对 `X.Y.Z`、`X.Y`、`latest`、commit SHA 标签和 amd64/arm64 manifest；下载 SBOM，验证 provenance/attestation 和 keyless signature；分别在干净 amd64、arm64 主机按 digest 拉取。
- 期望：产物与 commit/digest 一致，镜像不含 `.env`、OAuth secret、keyring 或测试凭据。
- 当前结果：已新增 tag-triggered GHCR workflow（先执行 locked fmt/check/clippy/test、cargo-audit/deny 和 amd64/arm64 镜像漏洞扫描，再使用固定基础镜像 digest 和固定 action SHA 进行多架构构建、per-platform SBOM attestations、provenance attestation、cosign keyless sign/verify）；尚未在真实 GitHub tag 上执行，因此下载产物、签名身份和干净主机 digest 拉取仍待外部验收。

### B6. Google Dev/Prod 与真实 Gmail smoke

- 前置条件：Dev/Prod Cloud Projects、测试 Gmail、正确 OAuth clients/scopes/callbacks、明确的测试收件 allowlist。
- 方法：完成 A1-A6 后登录、连接 Gmail，运行 `scripts/smoke-gmail.sh`（默认 prepare-only，创建带 `[AgentMail E2E <run-id>]` 的单个 managed draft）；人工核对 preview 后用 `--send` 交互确认发送到测试账号自身。
- 期望：只产生一个预期草稿/邮件，不改既有标签或已读状态；token 加密入库；所有 revoke 立即切断本地权限。
- 当前结果（2026-09-27）：Prod project 的两个 Web client、固定 HTTPS callbacks 和所需 scope 已配置；S1 `0c5780e` 生产部署健康。真实 Owner 浏览器 Login 与 Gmail offline consent 已成功。首次垃圾邮箱草稿因 Message-ID 不一致在 `prepare-send` 返回 `409 draft_changed`，没有发送；旧失配草稿不自动认领或删除。修正 Gmail 身份持久化和重启后的 sender preview 后，新的单封自发自收 smoke 的 search/create/prepare/send 全部返回 HTTP 200；发送结果为 `Sent`、`replayed=false`，且已持久化。同一 Gmail message ID 在 Sent 与 Inbox 的只读搜索均返回 HTTP 200、`message_present=true`。控制台随后显示临时 Access Key 为 `Revoked`、Connection 列表为空、本地凭证已移除；HTML 入口没有显示 Google 端 token revoke 的结果，因此不能宣称远端已确认。refresh、撤销后重新授权的真实 callback 跳转仍待验收。Gmail 更新成功但回读失败时仍会安全拒绝后续发送，恢复该草稿需单独处理。旧 Google client secret 在这些验收完成前不得停用或删除。
