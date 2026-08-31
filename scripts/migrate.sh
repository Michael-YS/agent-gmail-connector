#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
COMPOSE_FILE=${COMPOSE_FILE:-"$ROOT_DIR/compose.yaml"}
ENV_FILE=${ENV_FILE:-"$ROOT_DIR/.env"}
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-agentmail}
SERVICE=${SERVICE:-agentmail}
LOCK_FILE=${MIGRATE_LOCK_FILE:-"$ROOT_DIR/.migrate.lock"}

die() { printf 'migrate: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || die 'docker is required'
command -v flock >/dev/null 2>&1 || die 'flock (util-linux) is required'
[[ -f "$COMPOSE_FILE" ]] || die "compose file not found: $COMPOSE_FILE"
[[ -f "$ENV_FILE" ]] || die "environment file not found: $ENV_FILE"
exec 9>"$LOCK_FILE"
flock -n 9 || die 'another migration is already running'
compose=(docker compose --env-file "$ENV_FILE" --project-name "$PROJECT_NAME" --file "$COMPOSE_FILE")
"${compose[@]}" config --quiet || die 'compose preflight failed'
"${compose[@]}" config --services | grep -Fxq -- "$SERVICE" || die "service is not defined: $SERVICE"
for secret in login_client_secret gmail_client_secret credential_encryption_keyring session_csrf_secret; do
  [[ -s "$ROOT_DIR/secrets/$secret" ]] || die "secret file is missing or empty: $ROOT_DIR/secrets/$secret"
done
before=$("${compose[@]}" run --rm --no-deps "$SERVICE" migrate status)
printf 'migrate: before %s\n' "$before"
backup_output=$("$ROOT_DIR/scripts/backup.sh")
printf '%s\n' "$backup_output"
"${compose[@]}" stop --timeout 30 "$SERVICE" || die 'could not stop service; migration was not attempted'
if ! "${compose[@]}" run --rm --no-deps "$SERVICE" migrate; then
  printf 'migrate: failed; service remains stopped. Restore with: copy the reported backup over agentmail.db while the service is stopped.\n' >&2
  exit 1
fi
"${compose[@]}" up -d --no-deps "$SERVICE"
ready=false
for _attempt in $(seq 1 30); do
  if "${compose[@]}" exec -T "$SERVICE" wget --quiet --tries=1 --spider http://127.0.0.1:18080/health/ready; then
    ready=true
    break
  fi
  sleep 2
done
[[ "$ready" == true ]] || die 'migration succeeded but readiness did not recover'
after=$("${compose[@]}" run --rm --no-deps "$SERVICE" migrate status)
printf 'migrate: after %s\n' "$after"
printf 'migrate: succeeded; service is ready\n'