# AgentMail v1 实现进度

更新时间：2026-09-01

## 当前状态

- 工作分支：`feat/agentmail-v1`
- 当前实现尚未全部完成。
- Windows sandbox helper 仍会间歇返回 `helper_unknown_error: setup refresh had errors`；本轮通过用户批准的只读/构建命令和 Codex 标准 `apply_patch` 模式完成工作。
- 用户已经取消“完成后关闭计算机”的要求；后续不得关机。

## 已提交里程碑

1. `b0b67d2 docs: define AgentMail v1 plan`
2. `080d519 feat: build AgentMail secure core and API`
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

`a277988` 已包含真实 Google OIDC/JWKS 校验、统一 OAuth 回调、控制面 HTTP 路由、owner session、原子 OAuth transaction claim、加密 refresh token provider、连接所有权/状态保护，以及真实 Google token/Gmail HTTP client。该提交完成时通过 111 项测试、严格 Clippy 和格式检查。

## 当前实现断点

- Gmail read、MIME、managed draft 和安全发送四个后续代码里程碑均已提交；除本进度文档同步外没有未提交代码。
- production Gmail adapter 已完成读取及无附件 managed draft create/update/delete/send，不再回退到 fake adapter。
- 安全 MIME 构建层已使用 `mail-builder 0.5` 完成：稳定 Message-ID、reply References、reply-all 排除当前主地址、非 ASCII header、安全附件 filename/content-type、inline CID、原始附件与最终编码消息的 25 MiB 双重限制，以及有界 writer。
- 无附件 managed draft 已接入真实 Gmail create/update/delete：使用稳定 Message-ID 和安全 MIME，按草稿独立串行化，从 SQLite 恢复重启后的 managed record，保持 expected-version 乐观锁，并对 create 持久化失败做补偿删除、对 delete 404 做幂等成功。
- confirmation token 只以 SHA-256 hash 入库；prepare 先持久化再返回明文一次；claim/outcome 与 managed draft 状态分别在 SQLite 事务中原子更新。相同 token 重放首次结果，不再次发送。
- production send 已启用单次 Gmail `drafts.send`。Timeout、5xx/Unavailable、429 和 claim 后进程重启均只按系统生成的 `@agentmail.invalid` Message-ID 查询 Sent；要求精确 Message-ID header 与 `SENT` 标签，无法确认则持久化 `send_state_unknown`，绝不盲目重发。
- 最新完整验证：119 个 library tests、4 个 HTTP tests、5 个 REST/MCP tests，共 128 项；`git diff --check`、`cargo fmt --check` 和严格 Clippy 均通过。Terra 复审指出缺少可计数的超时/重启证据，已补测试证明 timeout 仅 send 一次且重放不 send、claim 后重启 send 次数为零。

## 剩余实现里程碑

### 1. MIME 与附件入口

- MIME 构建层已完成并提交；后续不得回退为手写 MIME。
- new draft 的无附件路径已接入；剩余：reply、reply-all、forward 的完整编排。
- 剩余：HTTP multipart 上传、已有 Gmail 附件/内嵌图片转发、附件下载流。
- 已有稳定 Message-ID、In-Reply-To/References、header injection 防护、非 ASCII header、filename/content type 校验、双重 25 MiB 限制和有界 writer 测试。

### 2. Gmail 写入与发送链路（已完成本地实现）

- 已接入真实 Gmail draft create/update/delete/send；真实环境 smoke 仍待垃圾邮箱账户验证。
- 已将受管 MIME 输出编码为 Gmail raw message。
- confirmation/outcome、重放、响应丢失和进程重启后的 Sent Mail 对账均已实现并通过本地测试。
- 保持 access-key scope、owner、connection status 和 CSRF/幂等性约束。
- 不记录 token、邮件正文或附件内容。

### 3. 连接生命周期

- OAuth/连接撤销与本地凭证清除。
- 凭证失效后的重新授权恢复流程。
- reconciliation、连接状态刷新和异常恢复。

### 4. 文档与发布验证

- 保持 `README.md` 与真实代码一致，并包含完整部署步骤。
- `TESTING_GAPS.md` 专门记录尚未完成的测试、前置条件和执行方法。
- 使用垃圾邮箱账户做真实 Google OAuth/Gmail smoke test，避免批量发送。
- 完成全量 fmt、Clippy、tests、Docker/部署配置检查。
- 按逻辑 milestone 分别提交。

## 既定产品边界

- v1 不实现细粒度 Access Key permissions，留给 v2。
- 不实现 Gmail watch、Pub/Sub 或后台同步。
- Gmail 用户身份以 Google `sub` 为准。
- 真实测试使用垃圾邮箱账户，不做批量发送。
- 敏感凭证不得写入仓库、日志或本文档。
