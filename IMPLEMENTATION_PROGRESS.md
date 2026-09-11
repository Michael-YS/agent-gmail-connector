# AgentMail v1 实现进度

更新时间：2026-09-11

## 当前状态

- 工作分支：`feat/agentmail-v1`
- 当前实现尚未全部完成。
- Windows sandbox helper 仍会间歇返回 `helper_unknown_error: setup refresh had errors`；本轮通过用户批准的只读/构建命令和 Codex 标准 `apply_patch` 模式完成工作。

## 已提交里程碑

1. `b0b67d2 docs: define AgentMail v1 plan`
2. `080d519 fund AgentMail secure core and API`
3. `527f501 ops: add hardened deployment and test guide`
4. `c2d2356 feat: persist auth and governance state`
5. `a841153 feat: add identity sessions and Google token client`
6. `9bb0ff9 feat: add control plane and mailbox transports`
7. `c19ccab feat: add secure invites and OAuth configuration`
8. `a277988 feat(auth): wire Google OIDC control plane`
9. `20560ec feat(gmail): wire production read adapter`
10. `59bfc44 feat(mime): build bounded managed messages`
11. `06b77b6 feat(gmail): manage production drafts`
12. `dd44402 feat(gmail): persist safe send outcomes`
13. `e501f0d feat(control): manage Access Keys`
14. `0f8b8ff feat(control-ui): owner HTML dashboard and invitations`
15. `3f45d95 feat(connections): revoke Gmail access safely`
16. `11d78f2 feat(control): manage members and accounts`
17. `646f91e feat(governance): persist limits and audits`
18. `7b86676 feat(mail): add live reads`
19. `3cc5516 feat(draft): add reply intents`
20. 工作区：multipart 草稿附件入口。
21. `dd77595 feat(audit): record control outcomes`
22. `bf1e459 feat(mcp): add draft attachments`
23. `e661498 docs: sync implementation progress`
24. `8b1a20c feat: extend mcp transport and release checks`
25. `ec7546b fix: harden mcp idempotency and audit`
26. `df0ab81 test: cover rmcp draft idempotency`
27. `24b2e24 test: cover rmcp protocol boundaries`
28. `a303a2d test(mcp): lock transport contract snapshots`
29. 当前工作区干净；剩余为 `/mcp` 端点迁移决策及外部验收门槛。

## 当前实现断点

- 新增 `POST /control/api/connections/{connection_id}/revoke`：Owner/Member 的有效 session + `x-csrf-token`，只能撤销自己的 Connection。SQLite 事务先标记 `revoking` 并移除 grants、发送确认和绑定该 Connection 的 OAuth transactions，再尝试 Google token revoke；无论远端结果如何，随后清理本地 Connection、加密凭证与 managed draft 记录，不调用 Gmail 邮件/草稿删除。
- Member `/control/account` 已实现 Connection list/connect/reauthorize/revoke、Access Key create/rotate/revoke/grants 和 delete-own-account；Owner `/control/members` 已接账号 revoke。账号撤销先事务性使所有 session/key/grant/confirmation/OAuth transaction 与 Connection 失效，再逐个撤销 Google token 并删除本地用户数据；启动时自动恢复 `revoking` Member 和独立 `revoking` Connection。Owner 无法从控制面删除。撤销保留 Personal Use 历史授权账本，缺失或损坏的凭证不阻止本地清理。

- Gmail read、MIME、managed draft、安全发送、Access Key 与邀请/Member control-plane 管理已实现。
- HTML control plane 已接入 `serve`：Askama 模板（base + owner/{dashboard,invitations,members,capacity}.html + member/account.html），严格 CSP、`HttpOnly; Secure; SameSite=Lax` session + csrf cookie、双重 cookie session/csrf 绑定、PRG + flash 一次性 cookie 携带邀请 token 或 Access Key credential。Owner 管理邀请、成员和容量；Owner/Member 在 `/control/account` 管理自己的 Connection 与 Access Key，Member 可删除自身账号。未登录请求 302 `/auth/google/login`，所有 mutation 强制 CSRF 和资源所有权。
- 登录 OAuth callback 现在除 session cookie 外另发 `__Host-agentmail_csrf` cookie，作为 HTML 表单 CSRF 明文载体，HttpOnly 仍由服务端读取；JSON 客户端不受影响（依旧从 response body 取 csrf 并以 `x-csrf-token` 头提交）。
- 新增仓库函数 `list_member_summaries` 与 `personal_use_summary`，仅返回 active Member 聚合元数据与单调历史计数，供 `/control/members` 和 `/control/capacity` 渲染；`list_member_summaries` 查询已修正为 SQLite 兼容的 `MAX(u.last_activity_at, subqueries...)` 形式。
- production Gmail adapter 已完成 Gmail 搜索分页、消息、线程、草稿列表/详情与附件读取，并完成 managed draft create/update/delete/send，不再回退到 fake adapter。草稿列表连续读取 Gmail 的所有 page token，并拒绝循环 token。消息默认返回规范化文本；HTML 必须显式请求且会删除主动内容。附件不会落盘，响应采用 `no-store`、强制下载及 `nosniff`。
- 安全 MIME 构建层已使用 `mail-builder 0.5` 完成：稳定 Message-ID、reply References、reply-all 排除当前主地址、非 ASCII header、安全附件 filename/content-type、inline CID、原始附件与最终编码消息的 25 MiB 双重限制，以及有界 writer。
- managed draft 已接入真实 Gmail create/update/delete：使用稳定 Message-ID 和安全 MIME，按草稿独立串行化，从 SQLite 恢复重启后的 managed record，保持 expected-version 乐观锁，并对 create 持久化失败做补偿删除、对 delete 404 做幂等成功。prepare/send/update/delete 会重读 Gmail 当前草稿并以完整结构化内容重算 version，网页端编辑会使旧确认失效；prepare 也返回真实收件人、主题、正文摘要和附件名。
- `POST /api/v1/connections/{connection_id}/drafts` 已支持持久化 `Idempotency-Key`：只保存 key 与请求摘要的 SHA-256 和内部 managed draft ID；相同 key/摘要返回原草稿，不会再创建 Gmail draft，摘要不同时返回冲突。managed draft 与完成记录在同一 SQLite 事务写入。
- MCP 兼容 JSON-RPC 已增加 `messages.get`、`threads.get`、`messages.get_attachment`、`drafts.list`、`drafts.get`、`drafts.create`、`drafts.update`、`drafts.delete`、`drafts.prepare_send` 与 `drafts.send`，与 REST 共用 Access Key/Connection grant、草稿状态机、确认 token 和审计边界；邮件和附件明确标为不可信。`drafts.create/update` 的 base64 附件总原始数据上限为 4 MiB，任何附件均不落盘。MCP 草稿创建会按 JSON-RPC 调用生成稳定的持久化幂等键，重试不会重复创建。新增 `/mcp-streamable` 使用官方 rmcp 的无状态 Streamable HTTP、Bearer 认证和当前全部工具 schema；当前所有工具通过受控兼容 bridge 复用认证、限流、领域状态机和元数据审计。MCP/OpenAPI schema 摘要、Host rebinding、内容协商、无状态协议边界及 rmcp 授权错误分类均有契约测试；原生 handler 迁移不是 v1 硬要求，仍待真实 MCP client 验收及 `/mcp` 兼容端点迁移决策。
- REST create draft 已支持 `new`、`reply`、`reply_all`、`forward` 意图。reply/reply_all 使用源邮件 thread、`In-Reply-To` 和 `References`；reply_all 排除当前主地址。forward 默认复制同一已授权源邮件的附件与内嵌 CID 数据，并经过 MIME 原始/编码双重大小限制。
- confirmation token 只以 SHA-256 hash 入库；prepare 先持久化再返回明文一次；claim/outcome 与 managed draft 状态分别在 SQLite 事务中原子更新。相同 token 重放首次结果，不再次发送。
- production send 已启用单次 Gmail `drafts.send`。Timeout、5xx/Unavailable、429 和 claim 后进程重启均只按系统生成的 `@agentmail.invalid` Message-ID 查询 Sent；要求精确 Message-ID header 与 `SENT` 标签，无法确认则持久化 `send_state_unknown`，绝不盲目重发。
- 限流已接入 REST/MCP 共用认证和发送链路：每把 Access Key 120 次 API/MCP 调用/分钟、30 次 prepare/小时；每个 Connection 10 次发送/小时、50 次/天。小时/日额度在同一 SQLite 事务内预占，确认重放、无效确认和明确失败会原子返还，`send_state_unknown` 保留占用；429 返回 header/body retry 秒数。机器端 search、message/thread/attachment/draft read、prepare/send，以及 control-plane mutation/OAuth transition 的审计只写 ID、操作、结果、延迟、request ID 和时间；审计中间件不读取请求体、查询参数或响应体。
- `AUDIT_RETENTION_DAYS` 默认 30（范围 1–3650）；`serve` 启动时及每小时清理到期审计和已越过最长窗口的限流桶。
- Access Key 管理 JSON API 位于 `/control/api/access-keys...`，Owner/Member 都只能管理自己的 key；所有 mutation 要求 session+CSRF，跨用户 IDOR 被拒绝。HTML 管理位于 `/control/account`。初始及替换 grants 在 repository 事务内验证 active same-owner Connection；create/rotate credential 只显示一次并 `Cache-Control: no-store`，SQLite 只存 Argon2 hash。
- 邀请接受以 POST body 中的一次性 token 启动 Login OAuth；token 仅以 SHA-256 hash 绑定到 OAuth transaction，callback 仅以已验证、规范化 email 和精确 Google `sub` 原子接受邀请、创建 Member 与 session。重放、错误 email、过期或撤销邀请均不创建 session。
- 常规 Google Login 会以精确 Google `sub` 与规范化 verified email 登录既有 active Owner 或 Member；没有既有用户时才保留首次 Owner bootstrap 规则。
- Owner JSON API 已接入：`GET/POST /control/api/invitations`、`POST /control/api/invitations/{id}/revoke`、`POST /control/api/invitations/{id}/regenerate`；HTML 保留 `/control/invitations...`。mutation 要求 Owner session+CSRF，列表不返回 hash，create/regenerate token 只返回一次并 `Cache-Control: no-store`。
- 最新本地完整验证：188 个 library tests、4 个 HTTP tests、15 个 REST/MCP tests，共 207 项；`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings` 与 `cargo test --all-targets --all-features --locked` 已通过。未执行部署、真实 Google 或浏览器 smoke。

## 剩余实现里程碑

### 1. MIME 与附件入口

- MIME 构建层已完成并提交；后续不得回退为手写 MIME。
- new/reply/reply-all/forward 已接入；HTTP JSON 和 `multipart/form-data`（`metadata` + `attachments[]`）创建/更新草稿均已接入。附件字段分块读取，原始总量限制 25 MiB，metadata 限制 1 MiB，任何附件均不落盘。MCP `drafts.create` 已接受总计不超过 4 MiB 原始数据的 base64 小附件。
- 已有 Gmail 附件/内嵌图片转发与下载已接入；附件下载受 Gmail JSON/base64url API 限制，在内存中有界解码后转发，不会落盘。
- 已有稳定 Message-ID、In-Reply-To/References、header injection 防护、非 ASCII header、filename/content type 校验、双重 25 MiB 限制和有界 writer 测试。

### 2. Gmail 写入与发送链路（已完成本地实现）

- 已接入真实 Gmail draft create/update/delete/send；真实环境 smoke 仍待垃圾邮箱账户验证。
- 已将受管 MIME 输出编码为 Gmail raw message。
- confirmation/outcome、重放、响应丢失和进程重启后的 Sent Mail 对账均已实现并通过本地测试。
- 保持 access-key scope、owner、connection status 和 CSRF/幂等性约束。
- 不记录 token、邮件正文或附件内容。

### 3. Control plane 剩余入口

- Owner Access Key 与邀请 JSON 管理 API 已完成；Owner 控制面 HTML 已完成（dashboard / invitations / members / capacity）。
- Member 管理与账号删除编排、控制面/OAuth 无内容审计及并发撤销压力测试已完成本地实现；真实 Google revoke 与浏览器流程待 smoke。

### 4. 连接生命周期

- 已完成 Connection revoke JSON/HTML 入口、Google token revoke、本地凭证清除和启动恢复；真实 Google 撤销仍待 smoke。
- 凭证失效后的重新授权恢复流程。
- reconciliation、连接状态刷新和异常恢复。

### 5. 文档与发布验证

- 保持 `README.md` 与真实代码一致，并包含完整部署步骤。
- `TESTING_GAPS.md` 专门记录尚未完成的测试、前置条件和执行方法。
- 使用垃圾邮箱账户做真实 Google OAuth/Gmail smoke test，避免批量发送。
- 完成全量 fmt、Clippy、tests、Docker/部署配置检查。
- 按逻辑 milestone 分别提交。

## 既定产品边界

- v1 不实现细粒度 Access Key permissions，留给 v2。
- 不实现 Gmail watch、Pub/O 或后台同步。
- Gmail 用户身份以 Google `sub` 为准。
- 真实测试使用垃圾邮箱账户，不做批量发送。
- 敏感凭证不得写入仓库、日志或本文档。
