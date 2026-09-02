# AgentMail agent guide

AgentMail 是 Rust/Axum + SQLite 实现的 Gmail 安全访问层。当前权威断点见 `IMPLEMENTATION_PROGRESS.md`，未完成验收见 `TESTING_GAPS.md`。

## 常用命令

- 格式：`cargo fmt --check`
- 严格静态检查：`cargo clippy --all-targets --all-features -- -D warnings`
- 全量测试：`cargo test --all-targets`
- 开发应在专用 feature branch 上进行，不直接改 `main`。

## 目录

- `src/`：领域模型、SQLite repository、HTTP/control plane、Google/Gmail adapters
- `migrations/`：显式 SQLite schema
- `tests/`：HTTP 与 REST/MCP 契约测试
- `deploy/`、`scripts/`：部署、迁移与备份入口

## 安全边界

- 不在源码、日志、文档或测试输出中保存 token、OAuth secret、邮件正文或附件内容。
- 只能修改、删除或发送 AgentMail 创建并登记的 managed draft。
- 发送必须先持久化 confirmation，再原子 claim；任何可能已处理的写入错误只做稳定 Message-ID Sent 对账，绝不自动重发。
- v1 不实现细粒度 Access Key permissions、Gmail watch、Pub/Sub 或后台同步。
- 真实 Gmail smoke 只使用垃圾邮箱账户和明确 allowlist，不做批量发送。
