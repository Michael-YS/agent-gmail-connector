#!/usr/bin/env bash
set -Eeuo pipefail

image=${1:-agentmail:ci}
expected_arch=${2:-amd64}
name="agentmail-smoke-${RANDOM}-$$"
volume="$name-data"
cleanup() {
  docker rm --force "$name" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

test "$(docker image inspect "$image" --format '{{.Architecture}}')" = "$expected_arch"
test "$(docker run --rm --entrypoint /usr/bin/id "$image" -u)" = 10001
test "$(docker run --rm --entrypoint /usr/bin/id "$image" -g)" = 10001

# Disposable test credentials only; never load deployment secrets.
for variable in SESSION_SECRET CSRF_SECRET LOGIN_CLIENT_SECRET GMAIL_CLIENT_SECRET; do
  printf -v "$variable" '%s' "$(openssl rand -hex 32)"
  export "$variable"
done
export CREDENTIAL_ENCRYPTION_KEYRING="v1=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
options=(--read-only --cap-drop ALL --security-opt no-new-privileges:true
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m
  --mount "type=volume,source=$volume,target=/var/lib/agentmail"
  -e APP_ENV=test -e PUBLIC_BASE_URL=http://localhost:18080 -e OWNER_EMAIL=smoke@example.invalid
  -e GOOGLE_LOGIN_CLIENT_ID=smoke.invalid -e GOOGLE_GMAIL_CLIENT_ID=smoke.invalid
  -e SESSION_SECRET -e CSRF_SECRET -e LOGIN_CLIENT_SECRET -e GMAIL_CLIENT_SECRET
  -e CREDENTIAL_ENCRYPTION_KEYRING -e DATABASE_URL=sqlite:///var/lib/agentmail/agentmail.db)
docker run --rm "${options[@]}" "$image" migrate
docker run --rm "${options[@]}" "$image" migrate status | grep -q '"pending":\[\]'
docker run --detach --name "$name" --health-interval 1s --health-start-period 1s \
  "${options[@]}" "$image" serve >/dev/null
healthy=false
for _attempt in $(seq 1 30); do
  if [[ "$(docker inspect "$name" --format '{{.State.Health.Status}}')" == healthy ]]; then
    healthy=true
    break
  fi
  sleep 1
done
[[ "$healthy" == true ]] || { printf 'container smoke: health check failed\n' >&2; exit 1; }
docker exec "$name" wget --quiet --tries=1 --spider http://127.0.0.1:18080/health/ready
docker run --rm "${options[@]}" "$image" database backup /var/lib/agentmail/smoke-backup.db
printf 'container smoke: nonroot, migration, readonly startup, live/ready and backup passed\n'
