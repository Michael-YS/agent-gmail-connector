# AgentMail

AgentMail 是一个面向 agent 的 Gmail 安全访问层。当前仓库已经实现 Rust/Axum 服务骨架、SQLite schema 与显式迁移、secret 文件加载、refresh token 信封加密、Access Key/grant 领域模型、OAuth/OIDC 的 state/nonce/PKCE 与 claims 语义核心、固定 callback 的 Google token exchange/refresh client、原子 Owner bootstrap、hash-only web session/control-plane 应用服务、一次性邀请制与 Google 双 client 安全配置、SQLite repository、限流/无内容审计数据模型、共享 mailbox 读取服务、带响应上限和 MIME 安全处理的 Gmail 只读 HTTP client、REST 消息搜索 OpenAPI、最小 MCP JSON-RPC 搜索工具、managed draft 与两阶段发送状态机、production 只读 Gmail adapter，以及带双重 25 MiB 限制的安全 MIME 构建层。

重要：当前版本仍不是可投入生产的完整 v1。真实 RS256/JWKS 验签、Login/Gmail callback、session/CSRF、加密 refresh token、凭据刷新和 REST 邮件搜索/读取已经接入 `serve`；安全 MIME 构建层已实现，但真实 Gmail draft/send transport 仍会 fail-closed，control plane 页面与邀请/Access Key CRUD、完整 MCP Streamable HTTP/rmcp、HTTP multipart 附件入口和发布供应链尚未完成或尚未经过真实环境验证，详见 [TESTING_GAPS.md](TESTING_GAPS.md)。在真实 Gmail 写入 adapter 和剩余安全验收完成前，不要把本仓库部署为真实邮件服务。

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

最终 v1 需要两个 Google Cloud Project（Dev Testing、Prod In Production），每个项目建立两个 Web OAuth Client：

- Login Client：`openid email profile`，回调 `https://agentmail.michaelsun.top/auth/google/callback`。
- Gmail Client：`openid email profile gmail.readonly gmail.compose`，回调 `https://agentmail.michaelsun.top/connections/google/callback`，offline access。

Dev 可另加 localhost 回调并把 junk-mail 账号加入 test users。Prod 只保留 HTTPS 生产回调，`PERSONAL_USE_USER_LIMIT` 不得超过 99。`serve` 只从 `PUBLIC_BASE_URL` 与上述固定路径构造 redirect URI，不读取请求的 `Host`/`Forwarded`；Gmail 授权启动是需要有效 session 与 `X-CSRF-Token` 的 POST。真实浏览器/Google Cloud 验收方法列在 `TESTING_GAPS.md`。

## VPS 目录与 secrets

推荐目录：

```text
/opt/agentmail/                 compose.yaml、.env、scripts/
/etc/agentmail/secrets/         root-owned 0400 secrets
/var/lib/docker/volumes/...     Compose 管理的 agentmail-data
/var/backups/agentmail/         宿主机备份
```

在 `/opt/agentmail`：

```sh
cp config/example.env .env
mkdir -p secrets backups
chmod 700 secrets backups
```

当前 Compose 从 `./secrets` 读取四个只读文件：

- `login_client_secret`：Google Login Client secret，单行。
- `gmail_client_secret`：Google Gmail Client secret，单行。
- `credential_encryption_keyring`：例如 `active=1;v1=<32-byte-key 的 base64url 或 hex>`。
- `session_csrf_secret`：严格两行；第一行 session secret，第二行 CSRF secret，每行至少 32 字节。

安全生成本地 secret（输出只落文件）：

```sh
umask 077
printf 'active=1;v1=%s\n' "$(openssl rand -hex 32)" > secrets/credential_encryption_keyring
{ openssl rand -base64 48; openssl rand -base64 48; } > secrets/session_csrf_secret
chmod 400 secrets/*
```

Google 两个 client secret 请从 Cloud Console 下载后手工写入对应文件，不要放进 shell history、`.env`、GitHub Secrets 或镜像层。把 production secrets 放到 `/etc/agentmail/secrets` 时，应相应修改 Compose 的 secret `file:` 路径。

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

容器固定 `linux/amd64`，UID/GID 10001，root filesystem 只读，`cap_drop: ALL`、`no-new-privileges`，只发布 `127.0.0.1:18080`。SQLite 位于 named volume 的 `/var/lib/agentmail/agentmail.db`；备份目录单独 bind mount 到 `/var/backups/agentmail`。

## Nginx

```sh
sudo install -m 0644 deploy/nginx-agentmail.conf /etc/nginx/sites-available/agentmail.conf
sudo ln -s /etc/nginx/sites-available/agentmail.conf /etc/nginx/sites-enabled/agentmail.conf
sudo nginx -t
sudo systemctl reload nginx
```

模板固定 canonical host，`/mcp` 关闭响应和请求 buffering；draft 上传路径关闭 request buffering；HTTP 附件上限为 30 MiB 的代理预算。TLS 证书路径按实际 Certbot 布局调整。验证：

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

`backup.sh` 通过一次性容器调用应用的 SQLite 在线 backup API，目标是宿主机 backup bind mount；不会 tar 一个与真实 volume 无关的目录。`migrate.sh` 使用 `flock`，先记录 schema、创建并验证备份，再停止主服务、运行一次性迁移容器、重启并等待 readiness。迁移失败时主服务保持停止，脚本不会执行 `docker compose down`、删除 volume、数据库或旧备份。

升级生产镜像时只修改明确版本或 digest，先拉取并运行 `scripts/migrate.sh`；不要跟随 `latest`。恢复时保持服务停止，将选定 `.db` 备份复制回 SQLite 路径，并由 owner 核对权限、schema 与 readiness 后再启动。

## 已实现的公共入口

- `/`、`/privacy`、`/terms`、`/data-deletion`
- `/api`、`/api/openapi.json`
- `/api/v1/...` REST 路由骨架
- `/mcp` JSON-RPC 骨架
- `/health/live`、`/health/ready`

机器接口只接受 `Authorization: Bearer amk_<public-id>.<secret>`，显式拒绝 query-string token；每次 Connection 操作都检查 owner、状态与 grant。所有响应生成 request ID，并设置 CSP、`nosniff`、`no-referrer`、`no-store` 等安全头。
