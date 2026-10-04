# AgentMail

AgentMail 是一个面向 agent 的 Gmail 安全访问层。当前仓库已经实现 Rust/Axum 服务骨架、SQLite schema 与显式迁移、secret 文件加载、refresh token 信封加密、Access Key/grant 领域模型、OAuth/OIDC 的 state/nonce/PKCE 与 claims 语义核心、固定 callback 的 Google token exchange/refresh client、原子 Owner bootstrap、既有 active Owner/Member 的精确 Google `sub`+规范化 verified email 登录、hash-only web session/control-plane 应用服务、一次性邀请制与 Google 双 client 安全配置、SQLite repository、跨重启固定窗口限流、机器端及控制面无内容审计与自动保留期清理、共享 mailbox 读取服务、带响应上限和 MIME 安全处理的 Gmail HTTP client、完整现有 REST 路由 OpenAPI、MCP JSON-RPC 读取与草稿全流程工具、managed draft、持久化两阶段发送状态机、稳定 Message-ID Sent 对账，以及带双重 25 MiB 限制的安全 MIME 构建层。

重要：当前版本仍不是可投入生产的完整 v1。真实 OIDC/OAuth、加密 refresh token、REST 邮件读取、managed draft 和安全发送、Owner 邀请/成员管理、Member 连接与 Access Key 管理及账号删除已接入 `serve`。HTML 页面使用 `/control/...`，JSON 管理 API 使用 `/control/api/...`，避免路由冲突。邀请、session、Access Key 和发送确认明文均不进入数据库；create/rotate 只显示一次并 `no-store`。`/mcp` 现在是计划约定的官方 rmcp 无状态 Streamable HTTP，全工具通过受控兼容 bridge 复用认证、限流、领域状态机和元数据审计；旧手写 JSON-RPC 兼容面迁移到 `/mcp-compat`，`/mcp-streamable` 保留为临时别名。原生 rmcp handler 迁移不是 v1 硬要求。发布供应链 workflow 已加入，并在推送前置验证 job 中执行 locked fmt/check/clippy/test、cargo-audit/deny 和 amd64/arm64 镜像漏洞扫描，但真实 GitHub tag、Google/浏览器 smoke 仍未完成；HTTP JSON/multipart 草稿附件入口与 MCP 4 MiB Base64 小附件已实现，详见 [TESTING_GAPS.md](TESTING_GAPS.md)。在剩余安全验收完成前，不要把本仓库部署为真实邮件服务。

## 本地验证

需要 Rust 1.90+：

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

CLI 不会自动迁移。首次启动前必须显式执行：

```sh
agentmail migrate status
agentmail migrate
agentmail database backup /safe/path/agentmail-backup.db
agentmail serve
```

`serve` 遇到 pending migration 会拒绝启动。`database backup` 使用 SQLite `VACUUM INTO`，不会覆盖已有目标文件。

## Google Cloud 准备

Panel 首次注册流程：未登记账号先完成 Google 身份认证，再在 `/auth/register` 输入 Owner 为该邮箱生成的邀请 token；只有有效、未过期且未使用的同邮箱邀请才创建 Member 和 session。Owner 创建邀请后需安全转交 token，系统不自动发送邀请邮件。待注册页面不是 Panel 登录成功，不赋予 Gmail 权限；短时状态过期或服务重启后需重新 Google 登录。已有 Owner/Member 登录不再要求邀请 token，首次 Owner bootstrap 仍由 `OWNER_EMAIL` 限定。

最终 v1 需要两个 Google Cloud Project（Dev Testing、Prod In Production），每个项目建立两个 Web OAuth Client：

- Login Client：`openid email profile`，回调 `https://agentmail.michaelsun.top/auth/google/callback`。
- Gmail Client：`openid email profile gmail.readonly gmail.compose`，回调 `https://agentmail.michaelsun.top/connections/google/callback`，offline access。

Dev 可另加 localhost 回调并把 junk-mail 账号加入 test users。Prod 只保留 HTTPS 生产回调，`PERSONAL_USE_USER_LIMIT` 不得超过 99。`serve` 只从 `PUBLIC_BASE_URL` 与上述固定路径构造 redirect URI，不读取请求的 `Host`/`Forwarded`；Gmail 授权启动是需要有效 session 与 `X-CSRF-Token` 的 POST。真实浏览器/Google Cloud 验收方法列在 `TESTING_GAPS.md`。

Gmail callback 将 Google 返回的 `https://www.googleapis.com/auth/userinfo.email` 和 `https://www.googleapis.com/auth/userinfo.profile` 分别规范化为 `email`、`profile` 并去重；仍要求同时具备 `gmail.readonly` 与 `gmail.compose`，并拒绝其他未允许的 scope。Owner 可以将登录所用的 Google 账号连接为自己的 Gmail Connection。

`AUDIT_RETENTION_DAYS` 默认为 30，可配置为 1–3650。`serve` 启动时清理过期的无内容审计和失效限流桶，之后每小时重复执行。机器接口按 Access Key 限制 120 次/分钟、30 次 prepare/小时；发送按 Connection 限制 10 次/小时和 50 次/天。`429` 同时返回 `Retry-After` 与 `retry_after_seconds`。

## VPS 目录与 secrets

推荐目录：

```text
/opt/agentmail/                 compose.yaml、.env、scripts/
/etc/agentmail/secrets/         root:10001、0440 secrets
/var/lib/docker/volumes/...     Compose 管理的 agentmail-data
/var/backups/agentmail/         宿主机备份
```

在 `/opt/agentmail`：

```sh
cp config/example.env .env
sudo install -d -o root -g 10001 -m 0750 /etc/agentmail/secrets
sudo install -d -o 10001 -g 10001 -m 0700 /var/backups/agentmail
```

本地 Linux/WSL 隔离测试若保留 `.env` 的默认相对路径，则改为：

```sh
sudo install -d -o root -g 10001 -m 0750 ./secrets
sudo install -d -o 10001 -g 10001 -m 0700 ./backups
```

当前 Compose 从 `AGENTMAIL_SECRETS_DIR`（默认 `./secrets`）以只读 bind mount 读取四个文件。Compose 的本地 file secrets 不可靠地支持 `uid`/`gid`/`mode`，因此生产部署约定把宿主机文件设为 `root:10001`、`0440`；应用校验权限位，允许 group 只读，但拒绝 group 写/执行和任何 other 权限。`migrate.sh` 预检精确 owner/GID/mode，而应用配置解析器只强制安全权限位。

- `login_client_secret`：Google Login Client secret，单行。
- `gmail_client_secret`：Google Gmail Client secret，单行。
- `credential_encryption_keyring`：例如 `active=1;v1=<32-byte-key 的 base64url 或 hex>`。
- `session_csrf_secret`：严格两行；第一行 session secret，第二行 CSRF secret，每行至少 32 字节。

先在 `.env` 中设置生产目录：

```sh
AGENTMAIL_SECRETS_DIR=/etc/agentmail/secrets
AGENTMAIL_BACKUP_DIR=/var/backups/agentmail
```

安全生成生产 secret（输出只落文件）：

```sh
secret_dir=/etc/agentmail/secrets # 本地测试改为 "$(pwd)/secrets"
sudo sh -c 'umask 027; printf "active=1;v1=%s\n" "$(openssl rand -hex 32)" > "$1/credential_encryption_keyring"' sh "$secret_dir"
sudo sh -c 'umask 027; { openssl rand -base64 48; openssl rand -base64 48; } > "$1/session_csrf_secret"' sh "$secret_dir"
sudo chown root:10001 "$secret_dir"/*
sudo chmod 0440 "$secret_dir"/*
```

Google 两个 client secret 请从 Cloud Console 下载后手工写入同一目录的对应文件，不要放进 shell history、`.env`、GitHub Secrets 或镜像层，并保持上述 owner/mode。本地隔离测试也必须让容器 UID/GID 10001 拥有 backup 目录写权限。

## Compose 部署步骤

1. 编辑 `.env`，至少设置 `OWNER_EMAIL`、两个非秘密 client ID、`PUBLIC_BASE_URL`、`PERSONAL_USE_USER_LIMIT` 和固定镜像：

   ```sh
   AGENTMAIL_IMAGE=ghcr.io/<owner>/agentmail@sha256:<digest>
   AGENTMAIL_BACKUP_DIR=/var/backups/agentmail
   ```

2. 预检配置和真实挂载：

   ```sh
   docker compose --env-file .env -f compose.yaml config --quiet
   docker compose --env-file .env -f compose.yaml run --rm --no-deps agentmail migrate status
   ```

3. 首次迁移并启动：

   ```sh
   docker compose --env-file .env -f compose.yaml run --rm --no-deps agentmail migrate
   docker compose --env-file .env -f compose.yaml up -d agentmail
   docker compose --env-file .env -f compose.yaml ps
   curl --fail http://127.0.0.1:18080/health/live
   curl --fail http://127.0.0.1:18080/health/ready
   ```

发布镜像支持 `linux/amd64` 和 `linux/arm64`，Compose 默认使用宿主机原生架构。容器 UID/GID 为 10001，root filesystem 只读，`cap_drop: ALL`、`no-new-privileges`，只发布 `127.0.0.1:18080`。SQLite 位于 named volume 的 `/var/lib/agentmail/agentmail.db`；备份目录单独 bind mount 到 `/var/backups/agentmail`。

## Nginx

模板使用 Nginx 1.25.1+ 的 `http2 on` 语法。共享 HTTPS listener 的默认站点、各虚拟主机与 `http` 全局配置应统一使用 `ssl_prefer_server_ciphers off;`；S1 曾因默认站点为 `off`、AgentMail 继承 `on`，在 TLS 1.3 key-exchange retry 时出现 `bad cipher`，导致 Cloudflare 525。新增站点时检查这一配置的一致性。

```sh
sudo install -m 0644 deploy/nginx-agentmail.conf /etc/nginx/sites-available/agentmail.conf
sudo ln -s /etc/nginx/sites-available/agentmail.conf /etc/nginx/sites-enabled/agentmail.conf
sudo nginx -t
sudo systemctl reload nginx
```

模板固定 canonical host，`location /mcp` 覆盖 `/mcp`、`/mcp-compat` 与 `/mcp-streamable`，并关闭它们的响应和请求 buffering；draft 上传路径关闭 request buffering；HTTP 附件上限为 30 MiB 的代理预算。TLS 证书路径按实际 Certbot 布局调整。验证：

```sh
curl -I http://agentmail.michaelsun.top/
curl --fail https://agentmail.michaelsun.top/health/live
curl --fail https://agentmail.michaelsun.top/health/ready
curl --fail https://agentmail.michaelsun.top/api
```

## 备份与升级迁移

脚本必须在 Linux 上可执行：

```sh
chmod 0755 scripts/backup.sh scripts/migrate.sh
./scripts/backup.sh
./scripts/migrate.sh
```

`backup.sh` 从 Compose 环境解析 `AGENTMAIL_BACKUP_DIR`，先确认 bind mount 对容器 UID 10001 可写，再通过一次性容器调用应用的 SQLite 在线 backup API；不会 tar 一个与真实 volume 无关的目录。`migrate.sh` 从同一 Compose 环境解析 `AGENTMAIL_SECRETS_DIR`，使用 `flock`，先记录 schema、创建并验证备份，再停止主服务、运行一次性迁移容器、重启并等待 readiness。迁移失败时主服务保持停止，脚本不会执行 `docker compose down`、删除 volume、数据库或旧备份。

升级生产镜像时只修改明确版本或 digest，先拉取并运行 `scripts/migrate.sh`；不要跟随 `latest`。恢复时保持服务停止，将选定 `.db` 备份复制回 SQLite 路径，并由 owner 核对权限、schema 与 readiness 后再启动。

## 已实现的公共入口

- `/`、`/privacy`、`/terms`、`/data-deletion`
- `/api`、`/api/openapi.json`
- `/api/v1/...` REST 路由与 `/api/openapi.json`
- `/mcp` rmcp 无状态 Streamable HTTP（当前工具通过兼容 bridge）
- `/mcp-compat` 手写 JSON-RPC 兼容面（消息/线程/附件读取与草稿全流程）
- `/mcp-streamable` rmcp Streamable HTTP 临时别名
- `/health/live`、`/health/ready`

机器接口只接受 `Authorization: Bearer amk_<public-id>.<secret>`，显式拒绝 query-string token；每次 Connection 操作都检查 owner、状态与 grant。Connection 的 Google 凭证失效（Gmail 401 或 refresh `invalid_grant`）会被持久化为 `reauth_required`，机器接口对 grant 仍有效但需要重新授权的 Connection 返回 REST 403 `reauth_required` / JSON-RPC -32005，与统一拒绝的 403 `forbidden` 可区分。所有响应生成 request ID，并设置 CSP、`nosniff`、`no-referrer`、`no-store` 等安全头。

控制面 CSP 的 HTTP header 与模板 meta 策略保持一致：允许同源脚本、同源及内联样式、同源及 data 图片，禁止内联脚本、eval 和第三方资源。部署后应核对公网响应和 Firefox 页面样式；本地测试通过不代表 S1 已更新。

连接撤销：HTML 使用 `/control/account`，JSON 使用 `POST /control/api/connections/{connection_id}/revoke`；Owner 或 Member 只能操作自己的连接。先原子切断本地 grants、发送确认与待处理重授权，再尝试撤销 Google token；最后删除本地连接、加密凭证及受管草稿记录，保留 Gmail 中的邮件和草稿。远端未确认时需在 Google 账号授权页检查。

Member 可在 `/control/account` 连接或重新授权 Gmail（JSON 入口为 `POST /control/api/connections/{connection_id}/reauthorize`，返回 authorize URL 与 transaction cookie）、撤销连接、创建/轮换/撤销 Access Key、原子更新 grants，并删除自己的 AgentMail 账号。Owner 可从 `/control/members` 撤销 Member。账号撤销会立即失效 session、Access Key、grant、发送确认与 OAuth transaction，然后逐个尝试撤销 Google token 并删除本地用户数据；不会删除 Gmail 数据。启动时会恢复中断的 `revoking` Member，历史 Gmail 授权计数保持单调。Owner 账号不能通过控制面删除或降级。
