# AgentMail v1 代码审查

审查日期：2026-09-11

审查基线：`origin/feat/agentmail-v1...HEAD`（本地分支领先 35 个提交）

状态：审查后的本地修复已于 2026-09-12 完成并通过 219 项测试；WSL Docker 的 amd64 构建、Compose 运行态、安全边界和备份/迁移脚本验收已通过。2026-09-22 又完成 S1 VPS 的原生构建、迁移、loopback-only 部署、Nginx/TLS/Cloudflare、在线备份和重启恢复验收；GitHub tag release 和 Google/browser smoke 仍待外部验收，见 `TESTING_GAPS.md`。本文保留原始发现作为决策记录。

## 修复结果（2026-09-12）

- P1 #1、#2、#3、#4 与 P2 #5、#6、#7、#9 已修复并纳入契约测试。
- 读取重试只适用于 429/5xx 的 GET 路径；写入和发送保持单次尝试。测试服务器不再等待未发生的连接，避免非重试断言死等。
- Docker Scout 改为 `docker/scout-action` 的完整 commit SHA；smoke 脚本不再输出收件人、主题、正文摘要或附件名。
- P2 #8（附件下载真正流式转发）及 P3 #10、#11 仍是后续改进，不在本轮以未验证重构冒险处理。

## 权限模型决策

采用“资源所有者完整自助，Owner 只管成员资格和全局护栏”的模型。

- Member 可以查看、创建、重新授权和撤销自己的 Gmail Connections。
- Member 可以查看、创建、rotate 和 revoke 自己的 Access Keys，并且只能在自己的 active Keys 与 active Connections 之间管理 grants。
- Owner 管理邀请、成员资格、Personal Use 容量和整账号 revoke，但不能借助 Owner 角色访问或修改成员的 Connection、Access Key 或 grants。
- 所有 mutation 必须同时通过 session、CSRF 和资源所有权验证。一次性 credential 只在 create/rotate 成功时显示，数据库只保存 hash。

### 待对齐的规则文件

`AGENTS.md` 当前写着“Access Key mutation 只允许 Owner session+CSRF”，容易被理解为只允许 `Owner` 角色，与上述决策和当前 Member 自助实现冲突。应改为“Access Key mutation 只允许资源所有者 session+CSRF”，并保留 same-owner active Connection 的 grant 约束。

## P1：合并或发布前应修复

### 1. MCP draft create 的持久化幂等键不唯一

- 位置：`src/http.rs:3166-3175`
- 问题：非空 JSON-RPC `id` 被单独 hash 成持久化幂等键，但 JSON-RPC `id` 只用于关联请求与响应，不保证跨无状态调用全局唯一。客户端重用 `id=1` 时，不同创建会被误判为 conflict，相同创建会被误 replay。
- 建议：为 `drafts.create` 引入显式的调用级 `idempotency_key`，并增加“重用 JSON-RPC ID 但发起新操作”的契约测试。

### 2. update 会破坏 reply/forward 语义

- 位置：`src/http.rs:1799-1814`
- 问题：更新时重建整个草稿，固定设置 `reply_headers: None`，未重新上传时也把附件置空。普通 update 会移除 reply/reply-all 的 `In-Reply-To`/`References`，或删掉 forward 默认复制的原附件。
- 建议：在 managed draft 中保留或可重建回复语义和附件来源；部分更新默认继承已有信息。

### 3. `/mcp-compat` 的 `reauth_required` 错误形式不符合契约

- 位置：`src/http.rs:3434-3437`、`src/http.rs:4363-4385`
- 问题：授权检查失败时直接返回 REST HTTP 403 envelope，而不是已约定的 JSON-RPC `-32005`；现有测试还锁定了该行为。
- 建议：所有 MCP authorization error 都经统一 MCP error mapper 转换，修正契约测试。

### 4. tag release 缺少 Docker Scout 安装步骤

- 位置：`.github/workflows/release.yml:47-54`
- 问题：verify job 直接调用 `docker scout`，但 workflow 没有安装 Scout。GitHub Ubuntu 24.04 runner 的已安装软件清单不包含 Scout，Docker 官方也说明纯 Docker Engine 不附带 Scout。tag release 会在扫描步骤固定失败。
- 建议：使用固定 commit SHA 的官方 Scout action，或安装固定版本的 Scout CLI。
- 证据：<https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md>；<https://docs.docker.com/scout/install/>。

## P2：功能或安全契约缺口

### 5. Gmail 读取没有按计划有限重试

- 位置：`src/google_gmail.rs:538-558`
- 问题：读取请求只执行一次 `send()`，Google 429/5xx 直接返回，没有指数退避、jitter 或 `Retry-After` 处理。
- 建议：只为读取类请求增加有上限的 retry policy；不将通用重试应用于写入或发送。

### 6. REST draft write 未记录元数据审计

- 位置：`src/http.rs:1360-1375`、`src/http.rs:1707-1723`、`src/http.rs:1847-1863`
- 问题：REST create/update/delete 没有经过 `audit_response`，而 MCP 中的同类操作会记录，导致两个 transport 的审计边界不一致。
- 建议：在共享的 authorized domain boundary 记录操作结果，确保不读取或保存请求体、收件人、主题、正文或附件名。

### 7. MCP draft 契约缺少计划能力

- 位置：`src/http.rs:3256-3259`
- 问题：当前仅暴露带 `kind` 的统一 `drafts.create`，没有按计划拆分 new/reply/reply-all/forward；schema 也不能引用已授权 Gmail 中的现有附件。
- 建议：拆分为独立、对 agent 语义清晰的 tools，并增加同 Connection 已有附件引用类型。

### 8. HTTP 附件下载不是流式转发

- 位置：`src/google_gmail.rs:411-426`、`src/http.rs:2945-2960`
- 问题：附件被完整解码到 `Vec<u8>` 后再整体构造 HTTP 响应，与计划中的“流式转发”不符。
- 建议：在有界 base64url 解码与 Axum response body 之间使用有界流，同时保留大小校验和不落盘约束。

### 9. Gmail smoke 脚本输出邮件正文摘要

- 位置：`scripts/smoke-gmail.sh:97-104`
- 问题：脚本将 `preview.body_summary` 打印到测试终端或 CI 输出，违反项目对邮件正文不进入日志或测试输出的边界。
- 建议：仅输出固定的脱敏状态或长度，不输出摘要文本。

## P3：可维护性

### 10. control UI 的 flash view 字段与转换逻辑重复

- 位置：`src/control_ui.rs:172`、`src/control_ui.rs:816`
- 问题：六个 flash 展示字段及投影逻辑在多个页面重复。
- 建议：提取 `FlashView` 和单一转换 helper。

### 11. `src/http.rs` 承担过多变更理由

- 位置：`src/http.rs:2702`、`src/http.rs:3369`
- 问题：REST authorization、OpenAPI、MCP dispatcher、审计、限流和 draft state machinery 集中在同一大文件，任一 transport 变更都容易扩大回归面。
- 建议：按 REST/OpenAPI/MCP transport 拆分模块，保留共享授权、领域状态机和审计边界。

## 已执行的验证

- `git diff --check origin/feat/agentmail-v1...HEAD`：通过。
- `cargo fmt --all -- --check`：通过。
- `cargo clippy --all-targets --all-features --locked -- -D warnings`：通过。
- `cargo test --all-targets --all-features --locked`：通过，193 项 library、4 项 HTTP、16 项 REST/MCP，共 213 项。
- 上述通过项不覆盖本文记录的契约、故障路径、GitHub tag release 和真实 Google/Docker/browser 验收缺口。
