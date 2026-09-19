#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
COMPOSE_FILE=${COMPOSE_FILE:-"$ROOT_DIR/compose.yaml"}
ENV_FILE=${ENV_FILE:-"$ROOT_DIR/.env"}
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-agentmail}
SERVICE=${SERVICE:-agentmail}
LOCK_FILE=${BACKUP_LOCK_FILE:-"$ROOT_DIR/.backup.lock"}

die() { printf 'backup: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || die 'docker is required'
command -v flock >/dev/null 2>&1 || die 'flock (util-linux) is required'
[[ -f "$COMPOSE_FILE" ]] || die "compose file not found: $COMPOSE_FILE"
[[ -f "$ENV_FILE" ]] || die "environment file not found: $ENV_FILE"
COMPOSE_DIR=$(cd -- "$(dirname -- "$COMPOSE_FILE")" && pwd -P)
exec 9>"$LOCK_FILE"
flock -n 9 || die 'another backup is already running'
compose=(docker compose --env-file "$ENV_FILE" --project-name "$PROJECT_NAME" --file "$COMPOSE_FILE")
"${compose[@]}" config --quiet || die 'compose preflight failed'
"${compose[@]}" config --services | grep -Fxq -- "$SERVICE" || die "service is not defined: $SERVICE"
compose_environment=$("${compose[@]}" config --environment) || die 'could not resolve compose environment'
BACKUP_DIR=${AGENTMAIL_BACKUP_DIR:-$(sed -n 's/^AGENTMAIL_BACKUP_DIR=//p' <<<"$compose_environment" | tail -n 1)}
BACKUP_DIR=${BACKUP_DIR:-./backups}
if [[ "$BACKUP_DIR" != /* ]]; then
  BACKUP_DIR="$COMPOSE_DIR/$BACKUP_DIR"
fi
[[ -d "$BACKUP_DIR" ]] || die "backup directory does not exist: $BACKUP_DIR"
export AGENTMAIL_BACKUP_DIR="$BACKUP_DIR"
"${compose[@]}" run --rm --no-deps --entrypoint /usr/bin/test "$SERVICE" -w /var/backups/agentmail \
  || die 'backup directory is not writable by container UID 10001'
stamp=$(date -u +%Y%m%dT%H%M%SZ)
name="agentmail-${stamp}.db"
"${compose[@]}" run --rm --no-deps "$SERVICE" database backup "/var/backups/agentmail/$name"
target="$BACKUP_DIR/$name"
[[ -s "$target" ]] || die "backup was not created or is empty: $target"
printf 'backup: created %s\n' "$target"
