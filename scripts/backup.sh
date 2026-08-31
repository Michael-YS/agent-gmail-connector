#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
COMPOSE_FILE=${COMPOSE_FILE:-"$ROOT_DIR/compose.yaml"}
ENV_FILE=${ENV_FILE:-"$ROOT_DIR/.env"}
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-agentmail}
SERVICE=${SERVICE:-agentmail}
BACKUP_DIR=${AGENTMAIL_BACKUP_DIR:-"$ROOT_DIR/backups"}
LOCK_FILE=${BACKUP_LOCK_FILE:-"$ROOT_DIR/.backup.lock"}

die() { printf 'backup: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || die 'docker is required'
command -v flock >/dev/null 2>&1 || die 'flock (util-linux) is required'
[[ -f "$COMPOSE_FILE" ]] || die "compose file not found: $COMPOSE_FILE"
[[ -f "$ENV_FILE" ]] || die "environment file not found: $ENV_FILE"
exec 9>"$LOCK_FILE"
flock -n 9 || die 'another backup is already running'
mkdir -p -- "$BACKUP_DIR"
chmod 700 -- "$BACKUP_DIR"
export AGENTMAIL_BACKUP_DIR="$BACKUP_DIR"
compose=(docker compose --env-file "$ENV_FILE" --project-name "$PROJECT_NAME" --file "$COMPOSE_FILE")
"${compose[@]}" config --quiet || die 'compose preflight failed'
"${compose[@]}" config --services | grep -Fxq -- "$SERVICE" || die "service is not defined: $SERVICE"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
name="agentmail-${stamp}.db"
"${compose[@]}" run --rm --no-deps "$SERVICE" database backup "/var/backups/agentmail/$name"
target="$BACKUP_DIR/$name"
[[ -s "$target" ]] || die "backup was not created or is empty: $target"
printf 'backup: created %s\n' "$target"