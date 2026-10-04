# AgentMail v1 实现进度

更新时间：2026-10-04

## 当前状态

- 2026-10-04 最终 GitHub CI #35（`0b98f8a`，[运行记录](https://github.com/Michael-YS/agent-gmail-connector/actions/runs/37203076186)）通过格式/check/严格 Clippy、238 项测试、依赖审计、amd64 镜像构建和 UID/GID smoke；完整 CI 仍因 Trivy 漏洞门禁失败。运行时包升级消除了 #34 的 `libpcre2-8-0` 与 `tzdata` 两项可修复记录；Debian 12.15 镜像剩余 256 项（1 Unknown、80 Low、115 Medium、56 High、4 Critical），扫描报告全部未列出修复版本。Critical 涉及 `perl-base` 的 CVE-2026-13221、CVE-2026-42496、CVE-2026-8376，以及 `zlib1g` 的 CVE-2023-45853。仍保留所有严重级别及未修复漏洞的失败门禁；零漏洞验收未完成，下一步需评估运行时镜像及漏洞适用性，未新增忽略、未合并或部署。
- 2026-10-04 镜像扫描配置补齐：Docker Scout 官方 action 文档要求 Docker Hub 登录，而当前 CI 未配置此凭证；CI 改用固定 SHA 的 Trivy action 与固定 `v0.75.0` 工具版本，只扫描漏洞，覆盖 OS/library、所有严重级别及未修复漏洞，发现漏洞仍返回非零。未创建凭证、未新增漏洞忽略；最终完整 CI 待验收，release workflow 未改。
- 2026-10-04 GitHub CI #31（`d001c0e`）通过测试、依赖审计与 amd64 镜像构建，随后容器 smoke 失败：`id --user` 输出数字 UID，旧脚本错误比较完整 `id` 文本。CI 现分别断言 UID/GID 都为 10001；漏洞扫描复用 release workflow 固定 SHA 的 Docker Scout action，保持 `exit-code: true`。已整合远端 `main`（`26ab695`），整合后本地 238 项测试、格式和严格 Clippy 通过；最终 CI 验收仍待完成，README 原有未提交修改保留，本轮未部署。
- 2026-10-04 GitHub CI #30（`cd83896`）已通过 fmt/check/clippy/test，随后 `cargo audit` 发现 `rustls 0.23.43` 的 `RUSTSEC-2026-0285`，阻止镜像构建。已定向更新锁文件至修复版本 `0.23.45`，未新增审计例外；本地 locked 全目标/全特性测试（238 项）、`cargo audit --ignore RUSTSEC-2023-0071` 和 `cargo deny check` 通过。升级后的 GitHub CI 完整验收待完成，本轮未部署。
- 2026-10-04 CI 测试夹具修复：`google_client_secret_files_use_size_permission_and_exclusivity_rules` 的空文件在 Unix 上显式设为 `0600`，避免默认 `umask 022` 先触发权限错误；生产 secret 文件校验未改。分支 `codex/fix-secret-file-test-permissions` 本地 `cargo fmt --check`、严格全目标/全特性 Clippy 和 locked 全目标/全特性测试均通过（238 项）；WSL Ubuntu 24.04 在 `umask 022` 下的原失败精确测试通过。GitHub Actions 验收待完成，本轮未部署。

- 前端样式 `3d85c3f` 已合并并推送至 `origin/main`，并部署 S1：统一登录、邀请注册与控制台的蓝色邮件视觉、响应式导航/表格、明暗主题及键盘焦点；排除本地 agent 日志、提示文件、Node 工具目录和临时 pnpm manifests。13 项控制台测试、5 项 HTTP 契约、24 项 REST/MCP 契约、格式及严格 Clippy 通过；浏览器检查覆盖七页的桌面、390px、320px 和深色模式。全量单测本机结果为 187 通过/22 失败，包含沙箱禁止本地 mock listener、默认 umask 权限夹具及既有 SQLite revoke 压力测试超时；私有 umask 可解决权限夹具，隔离 revoke 压力测试仍出现 `PoolTimedOut`，未调整后端实现或测试超时。

- 本轮只读 MCP `connections.list` 已提交并部署 `b38f8c2`：与 REST `GET /api/v1/connections` 共用当前 Key 的 active、same-owner grant 过滤，不请求 Gmail、不返回凭证；空对象参数（或省略 arguments）返回 Connection 元数据，非空对象、null 和数组被拒绝。新增无 Connection target 的元数据审计、三个 MCP 入口的契约回归与更新后的工具 schema snapshot，Agent 使用说明已同步。独立源码复核未发现实现问题，格式与 diff 检查通过；用户运行全量测试与严格 Clippy 后报告 all pass。用户完成 S1 amd64 构建后已健康切换，真实 Hermes 刷新工具列表并调用 `{}` 尚待验收；此前 Git push 曾被安全审核拦截；本轮用户明确授权后，相关历史提交已随 `main` 推送至 origin。
- 工作分支：`fix/nginx-tls-consistency`（Nginx TLS 一致性修复与部署记录合并到 `main`）
- 本轮 Hermes 公网 MCP 连接的 `403 Host header is not allowed` 修复 `c08553a` 已部署：线上 rmcp 原先使用默认 loopback 白名单，而 Nginx 正确转发公网域名。生产启动显式传入已验证 `PUBLIC_BASE_URL` 的 authority（保留 IPv6 括号和非默认端口），保留本机白名单、Bearer 鉴权与未知 Host 拒绝，不从请求 Host/Forwarded 推导信任配置。原路由构造入口仍保留 loopback 默认行为；无 schema 变更。公网域名 initialize/tools/list、别名、本机、缺失鉴权、Forwarded 伪造和非默认端口已有回归；格式与 diff 检查通过，用户运行全量测试与严格 Clippy 后报告全过。新容器健康、内外网 live/ready 和首页 200，匿名 MCP initialize 仍为 401；真实 Hermes 重连与 tools/list 尚待用户验收。
- 本轮已补首次注册的浏览器入口并部署 `353d67d`：未登记 Google 身份认证后只进入邀请 token 页面；有效同邮箱、单次使用邀请才创建 Member 和 session，已有账号仍直接登录。待注册状态仅在服务端内存保存，五分钟过期、单次提交且重启失效；无新 schema。格式与 diff 检查通过，用户运行全量测试及严格 Clippy 后报告 all pass。用户随后完成真实浏览器邀请注册，只读核对目标成为 Google-bound Active Member 且有有效 session；新 Owner 权限页面仍待用户刷新验收。
- Owner 更换及旧账号退出已完成：先在数据库内存副本演练，确认目标身份/session 与外键不受损；操作前在线备份 `/var/backups/agentmail/agentmail-20260928T054101Z.db` 的只读 `quick_check=ok`。短暂停服后原子将原 Owner 改为 revoking Member、将已验证目标提升为唯一 Active Owner，保留目标 ID/Google 绑定/session，并更新生产 `OWNER_EMAIL`。旧 Owner 的一条已消费邀请因 `invited_by` 限制外键需同步清理，未改写邀请发行者；恢复启动复用现有凭证撤销流程。只读验收：仅一个 Active Owner、目标 session 保留，旧账号及原有两个 Connection、本地凭证、一个已撤销 Key 和邀请均移除，外键零问题、容器 healthy 且零 restart，内外网 live/ready 与首页 200。没有删除 Gmail 邮件或草稿；Google 端 token revoke 的最终结果未独立核验，数据库备份也不能撤销已完成的 Google 端 revoke。
- 当前实现尚未全部完成。
- S1 现运行 `agentmail:3d85c3f`（linux/amd64，镜像 revision `3d85c3fcbca778df6131c819cb72c14e3b89b85c`）：部署前在线 SQLite 备份 `/var/backups/agentmail/agentmail-20261002T185031Z.db`，只读 `quick_check=ok`、外键问题 0、权限 0600/UID:GID 10001:10001。无 pending migration；容器 healthy/零 restart、只读 root filesystem，端口仍为 `127.0.0.1:18080`。本机 HTTP 与证书校验通过的源站 HTTPS live/ready 均为 200，源站首页新样式及 CSP 已核对，匿名 MCP initialize 为 401、匿名控制台为 303。生产源码已同步该提交，Compose 哈希未变，`.env` 仅修改镜像 tag，旧镜像 `agentmail:b38f8c2` 保留回退。首次 rollout 的 Cloudflare 525 在旧镜像也复现；后续已定位并修复 Nginx 默认站点与 AgentMail 的 cipher-preference 不一致，公网路径恢复，详见下条。构建和两次部署日志位于 `/opt/agentmail-builds/3d85c3f/`。真实登录后的浏览器页面与 Hermes `connections.list` 仍待用户核对。
- S1 Nginx TLS 修复（2026-10-02）：默认 HTTPS 站点使用 `ssl_prefer_server_ciphers off`，AgentMail 原继承全局 `on`；按 Cloudflare cipher 顺序构造的 TLS 1.3 key-exchange retry 在生产与隔离 Nginx 均复现 `bad cipher`，隔离实例统一 `off` 后通过。用户授权后全局与 AgentMail 统一为 `off`，其余六个站点原已为 `off`；AgentMail 改为独立 `http2 on` 语法，消除 deprecated/protocol-options warnings。完整 `nginx -t` 无警告通过，2026-10-02 20:42:09 UTC 完成 Nginx restart。七站点 TLS 1.2/1.3/retry 与证书/hostname 校验均通过，三个已配置 IPv6 TLS 的站点 retry、七站点 HTTP→HTTPS redirect 与 AgentMail HTTP/2 均通过；AgentMail 公网首页及 live/ready 为 200、匿名控制台 303、匿名 MCP initialize 401，其他六站点源站/公网状态与变更前一致（200/302/307/401/403）。容器仍为 `agentmail:3d85c3f`、healthy、零 restart；变更前配置备份 `/var/backups/nginx/agentmail-tls-20261002T204209Z/`。部署模板和 README 同步一致性要求；真实登录及 Hermes 验收仍待用户完成。
- 真实 Google Gmail consent 曾为 Owner 创建一个 Active Connection，账户页显示 `gmail.readonly` 和 `gmail.compose`，随后该测试 Connection 已撤销。`ea26723` 的 Google `userinfo.email/profile` scope URL 兼容修复因此获得线上验证。成功 Gmail callback 曾显示 JSON；`45bd227` 改为 303 跳转 `/control/account`，本地 callback 回归测试通过，但新版本尚未重新执行一次真实 Gmail callback。
- 本轮 Windows 本地验证：`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --all-targets` 已通过；最新 `654b49d` 的全量门禁由用户运行并报告全 pass。限流测试曾在固定分钟边界偶发失败，已改为有界重试并通过全量复跑。真实 refresh、revoke、真实 MCP client、arm64 实机和 GitHub tag release 仍待验收。
- 首次真实垃圾邮箱 smoke 在 `drafts.create` 后，`prepare-send` 安全地返回 `409 draft_changed`，未发送；旧失配草稿不自动认领或删除。`b68101d` 修正 Gmail 实际 Message-ID 持久化，`654b49d` 修正服务重启后 `prepare-send` 的 sender preview。随后只对新 managed draft 执行一次自发自收：`drafts.send` 返回 HTTP 200、`Sent`、`replayed=false`；只读 SQLite 核对其状态为 `sent` 且有一条持久化发送结果。`scripts/verify-self-send.sh` 用同一 Gmail message ID 只读搜索，Sent 与 Inbox 均返回 HTTP 200、`message_present=true`。控制台随后显示临时 Access Key 为 `Revoked`、Connection 列表为空，并提示本地凭证已移除；HTML 入口不呈现 Google 端 revoke 的确认状态。不要重复发送。
- 撤销后重新连接 Gmail 暴露出 OAuth start 的 POST→Google 307 重定向；Nginx 确认表单 POST 到达并返回 307，但浏览器未到授权页。`0c5780e` 已把该重定向改为 303，并收紧 POST 入口回归断言；用户运行 `cargo test --all-targets` 与严格 Clippy 后报告全部通过，S1 构建与健康部署已完成，真实 Gmail callback 仍待验收。
- 另一 Google 账号尝试普通 Panel 登录时，Login callback 错把“未获准的身份”映射为 HTTP 503。S1 只登记测试邮箱 Owner、没有该账号的 Member；失败的 Login 事务已消费，不能刷新重放。`88fbe8a` 让未登记身份得到通用 HTTP 403 `authentication_failed`，并断言不会新增用户或 session；用户报告全量测试和严格 Clippy 均通过，S1 已健康部署，真实浏览器回归仍待执行。是否邀请该账号需 Owner 单独决定。
- 登录前公开首页此前没有 CSS；`44193e1` 补内联响应式明暗样式，保留原有登录与法律链接及 CSP 安全边界。验证期间暴露的 MCP 计数测试分钟边界误失败已用窗口感知断言修正，生产限流不变。用户复跑全量测试与严格 Clippy 后报告全 pass，S1 已健康部署；公网首页含新样式，浏览器刷新后的窄屏深色视图已核对标题、登录按钮和法律链接，无明显溢出，未点击登录。

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
29. `425f760 docs: clarify mcp endpoint migration`
30. `d265b16 feat(mcp): align canonical streamable endpoint`
31. `a7b2abe build: adopt aws-lc jwt backend and audit guards`
32. `544bbc7 feat(connections): surface reauth_required across machine APIs`
33. `637dc3f feat(control): add json connection reauthorize endpoint`
34. `e10064d ops: add bounded gmail smoke script`

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
- MCP 兼容 JSON-RPC 已迁移到 `/mcp-compat`，增加 `messages.get`、`threads.get`、`messages.get_attachment`、`drafts.list`、`drafts.get`、`drafts.create`、`drafts.update`、`drafts.delete`、`drafts.prepare_send` 与 `drafts.send`，与 REST 共用 Access Key/Connection grant、草稿状态机、确认 token 和审计边界；邮件和附件明确标为不可信。`drafts.create/update` 的 base64 附件总原始数据上限为 4 MiB，任何附件均不落盘。MCP 草稿创建会按 JSON-RPC 调用生成稳定的持久化幂等键，重试不会重复创建。`/mcp` 现在使用官方 rmcp 的无状态 Streamable HTTP，`/mcp-streamable` 保留临时别名；当前所有工具通过受控兼容 bridge 复用认证、限流、领域状态机和元数据审计。MCP/OpenAPI schema 摘要、Host rebinding、内容协商、无状态协议边界及 rmcp 授权错误分类均有契约测试；原生 handler 迁移不是 v1 硬要求，仍待真实 MCP client 验收。
- REST create draft 已支持 `new`、`reply`、`reply_all`、`forward` 意图。reply/reply_all 使用源邮件 thread、`In-Reply-To` 和 `References`；reply_all 排除当前主地址。forward 默认复制同一已授权源邮件的附件与内嵌 CID 数据，并经过 MIME 原始/编码双重大小限制。
- confirmation token 只以 SHA-256 hash 入库；prepare 先持久化再返回明文一次；claim/outcome 与 managed draft 状态分别在 SQLite 事务中原子更新。相同 token 重放首次结果，不再次发送。
- production send 已启用单次 Gmail `drafts.send`。Timeout、5xx/Unavailable、429 和 claim 后进程重启均只按系统生成的 `@agentmail.invalid` Message-ID 查询 Sent；要求精确 Message-ID header 与 `SENT` 标签，无法确认则持久化 `send_state_unknown`，绝不盲目重发。
- 限流已接入 REST/MCP 共用认证和发送链路：每把 Access Key 120 次 API/MCP 调用/分钟、30 次 prepare/小时；每个 Connection 10 次发送/小时、50 次/天。小时/日额度在同一 SQLite 事务内预占，确认重放、无效确认和明确失败会原子返还，`send_state_unknown` 保留占用；429 返回 header/body retry 秒数。机器端 search、message/thread/attachment/draft read、prepare/send，以及 control-plane mutation/OAuth transition 的审计只写 ID、操作、结果、延迟、request ID 和时间；审计中间件不读取请求体、查询参数或响应体。
- `AUDIT_RETENTION_DAYS` 默认 30（范围 1–3650）；`serve` 启动时及每小时清理到期审计和已越过最长窗口的限流桶。
- Access Key 管理 JSON API 位于 `/control/api/access-keys...`，Owner/Member 都只能管理自己的 key；所有 mutation 要求 session+CSRF，跨用户 IDOR 被拒绝。HTML 管理位于 `/control/account`。初始及替换 grants 在 repository 事务内验证 active same-owner Connection；create/rotate credential 只显示一次并 `Cache-Control: no-store`，SQLite 只存 Argon2 hash。
- 邀请接受以 POST body 中的一次性 token 启动 Login OAuth；token 仅以 SHA-256 hash 绑定到 OAuth transaction，callback 仅以已验证、规范化 email 和精确 Google `sub` 原子接受邀请、创建 Member 与 session。重放、错误 email、过期或撤销邀请均不创建 session。
- 常规 Google Login 会以精确 Google `sub` 与规范化 verified email 登录既有 active Owner 或 Member；没有既有用户时才保留首次 Owner bootstrap 规则。
- Owner JSON API 已接入：`GET/POST /control/api/invitations`、`POST /control/api/invitations/{id}/revoke`、`POST /control/api/invitations/{id}/regenerate`；HTML 保留 `/control/invitations...`。mutation 要求 Owner session+CSRF，列表不返回 hash，create/regenerate token 只返回一次并 `Cache-Control: no-store`。
- Connection 生命周期新增机器端可感知的 reauth 分类：Gmail API 401 或 Google refresh `invalid_grant` 会把 Connection 原子标记为 `reauth_required`（`invalid_grant` 在凭证提供方内持久化；Gmail 401 由 adapter 经 `mark_reauth_required` 持久化并清除内存 token）。REST 对 grant 仍有效但状态为 `reauth_required` 的 Connection 返回 403 `reauth_required`（owner 不匹配或无 grant 仍是统一 403 `forbidden`，grant 检查改用与连接状态无关的 `access_key_grant_exists`）；MCP JSON-RPC 兼容面映射为 -32005，rmcp Streamable 桥按错误类别透传；发送失败 outcome 新增 `reauth_required`（401 不可能已投递，不做 Sent 对账）。
- 新增 JSON 控制面入口 `POST /control/api/connections/{connection_id}/reauthorize`：Owner/Member 的有效 session + CSRF，缺失或他人连接返回 404 `connection_not_found`，`revoking` 状态返回 409 `connection_revoking`，Active/`reauth_required` 均可发起；成功返回 `authorize_url` 与 Gmail transaction cookie（`Cache-Control: no-store`），并以 `connection.reauthorize` 记录无内容审计。HTML `/control/account` 流程不变。
- 新增 `scripts/smoke-gmail.sh`（垃圾邮箱 + 单收件人 allowlist 的真实 Gmail smoke 入口，默认 prepare-only，`--send` 需交互确认）。
- 历史验证记录（本轮本地门禁见「当前状态」）：194 个 library tests、4 个 HTTP tests、21 个 REST/MCP tests，共 219 项；`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings` 与 `cargo test --all-targets --all-features --locked` 已通过。Gmail 读取仅对 429/5xx 使用有界退避重试；写入和发送不重试。`cargo audit 0.22.2 --ignore RUSTSEC-2023-0071` 通过，且 `cargo tree --target all --all-features -i rsa` 证明 rsa 仅存在于未启用的 sqlx-mysql 可选分支；`cargo deny 0.20.2` 的 advisory/license/source 检查通过（仅 duplicate-version warnings）。WSL Docker 已通过 amd64 镜像构建、Compose 迁移与 live/ready、容器安全边界、SQLite backup integrity、迁移成功/受控失败及 backup/migrate 并发锁验收；2026-09-22 新 Prod OAuth 配置又通过独立 Compose 启动和 Login authorize URL/Google 接受性检查。发布定义已扩展为 amd64/arm64 多架构。S1 amd64 VPS 已完成原生镜像构建、迁移、loopback-only Compose 部署、容器安全检查、在线备份与重启恢复；Nginx/Let's Encrypt/Cloudflare 公网入口的 `/`、`/api`、live/ready 和 OAuth start 已通过，`/mcp` 未认证请求返回 401。GitHub tag release、浏览器 Login、Gmail offline consent/refresh 与真实 Gmail smoke 尚未完成。

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

- 已完成 Connection revoke JSON/HTML 入口、Google token revoke、本地凭证清除和启动恢复；`reauth_required` 已持久化并在 REST/MCP 以独立错误码暴露，JSON reauthorize 入口已接入；真实 Google 撤销仍待 smoke。
- reconciliation、周期性连接状态刷新仍未实现（v1 边界允许：只在请求路径按需检测 401/invalid_grant 并标记，无后台探测）。

### 5. 文档与发布验证

- 保持 `README.md` 与真实代码一致，并包含完整部署步骤。
- `TESTING_GAPS.md` 专门记录尚未完成的测试、前置条件和执行方法。
- 使用垃圾邮箱账户做真实 Google OAuth/Gmail smoke test，避免批量发送。
- 完成全量 fmt、Clippy、tests、本机 WSL Docker/Compose 和 S1 VPS/Nginx/TLS 验收；继续完成 GitHub tag release 与 Google/browser 外部验收。
- 按逻辑 milestone 分别提交。

## 既定产品边界

- v1 不实现细粒度 Access Key permissions，留给 v2。
- 不实现 Gmail watch、Pub/O 或后台同步。
- Gmail 用户身份以 Google `sub` 为准。
- 真实测试使用垃圾邮箱账户，不做批量发送。
- 敏感凭证不得写入仓库、日志或本文档。
